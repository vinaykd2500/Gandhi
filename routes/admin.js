 import express from "express";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import crypto from "crypto";
import multer from "multer";
import rateLimit from "express-rate-limit";
import { fileTypeFromFile } from "file-type";
import { promisify } from "util";
import "../config/env.js";

// Safely attempt to load local .env if available
try {
  process.loadEnvFile();
} catch (err) {
  // Render/Hostinger dashboard provides env variables
}

const router = express.Router();
const ROOT_DIR = path.dirname(fileURLToPath(import.meta.url));
const adminUsername = process.env.ADMIN_USERNAME ;
const adminPassword = process.env.ADMIN_PASSWORD ;
console.log("Admin Username:", adminUsername);
console.log("Admin Password:", adminPassword);
const adminPasswordHash = process.env.ADMIN_PASSWORD_HASH;
const scrypt = promisify(crypto.scrypt);
const loginAttempts = new Map();

const DATA_FILE = path.join(ROOT_DIR, "..", "products.json");
const INQUIRIES_FILE = path.join(ROOT_DIR, "..", "inquiries.json");
const CATEGORIES_FILE = path.join(ROOT_DIR, "..", "categories.json");
const uploadsDir = path.join(ROOT_DIR, "..", "public", "uploads");

const createCaptcha = () => {
  const first = crypto.randomInt(2, 10);
  const second = crypto.randomInt(2, 10);
  return { question: `${first} + ${second}`, answer: first + second };
};

// Ensure uploads directory exists
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Multer Storage Configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const extensions = {
      "image/jpeg": ".jpg",
      "image/png": ".png",
      "image/webp": ".webp",
      "image/gif": ".gif",
    };
    const ext = extensions[file.mimetype] || ".jpg";
    cb(null, `${Date.now()}-${Math.round(Math.random() * 1e9)}${ext}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB Limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = new Set([
      "image/jpeg",
      "image/png",
      "image/webp",
      "image/gif",
    ]);
    if (!allowedTypes.has(file.mimetype)) {
      return cb(new Error("Only JPEG, PNG, WebP, and GIF images are allowed."));
    }
    cb(null, true);
  },
});

// Middleware wrapper to intercept Multer errors cleanly
const handleProductUpload = (req, res, next) => {
  upload.single("image")(req, res, (err) => {
    if (err) {
      const categories = getCategories();
      const isEdit = req.method === "PUT" || req.originalUrl.includes("/edit");
      const view = isEdit ? "admin/edit" : "admin/add";
      const title = isEdit ? "Edit Product" : "Add New Product";

      let errorMessage = "File upload failed. Please try again.";
      if (err.code === "LIMIT_FILE_SIZE") {
        errorMessage = "Image size exceeds 5 MB. Please upload a smaller image.";
      } else if (err.message) {
        errorMessage = err.message;
      }

      const products = getStoredProducts();
      const product = isEdit ? products.find((p) => p.id === req.params.id) || {} : {};

      return res.status(400).render(view, {
        title,
        error: errorMessage,
        categories,
        product: { ...product, ...req.body },
        selectedCategory: isEdit ? "Edit Product" : "Add Product",
        selectedProductCategory: req.body?.category || categories[0]?.name,
      });
    }
    next();
  });
};

const loginRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 25,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: "Too many login attempts. Please try again later.",
});

const validateUploadedImage = async (file) => {
  if (!file) return true;
  try {
    const detected = await fileTypeFromFile(file.path);
    const allowedTypes = new Set(["image/jpeg", "image/png", "image/webp", "image/gif"]);
    return Boolean(detected && allowedTypes.has(detected.mime) && detected.mime === file.mimetype);
  } catch (error) {
    return false;
  }
};

const verifyAdminPassword = async (password) => {
  if (!adminPasswordHash) return password === adminPassword;
  const [, salt, expectedHash] = adminPasswordHash.split("$");
  if (!salt || !expectedHash) return false;
  const derivedKey = await scrypt(password, Buffer.from(salt, "hex"), 64);
  const expected = Buffer.from(expectedHash, "hex");
  return expected.length === derivedKey.length && crypto.timingSafeEqual(expected, derivedKey);
};

// Default Categories
const defaultCategories = [
  { name: "Kitchen Sinks", icon: "fa-faucet-drip" },
  { name: "Cisterns", icon: "fa-bath" },
  { name: "Wash Basins", icon: "fa-soap" },
  { name: "Pipes & Fittings", icon: "fa-wrench" },
  { name: "Factory Infrastructure", icon: "fa-industry" },
  { name: "Leadership & Team", icon: "fa-users" },
  { name: "Miscellaneous", icon: "fa-layer-group" },
];

const getCategories = () => {
  try {
    const raw = fs.readFileSync(CATEGORIES_FILE, "utf-8").trim();
    const categories = raw ? JSON.parse(raw) : [];
    return Array.isArray(categories) && categories.length > 0 ? categories : defaultCategories;
  } catch (err) {
    return defaultCategories;
  }
};

const saveCategories = (categories) => {
  fs.writeFileSync(CATEGORIES_FILE, JSON.stringify(categories, null, 2));
};

const getStoredProducts = () => {
  try {
    const raw = fs.readFileSync(DATA_FILE, "utf-8").trim();
    return raw ? JSON.parse(raw) : [];
  } catch (err) {
    return [];
  }
};

const saveStoredProducts = (data) => {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
};

const getInquiries = () => {
  try {
    const raw = fs.readFileSync(INQUIRIES_FILE, "utf-8").trim();
    return raw ? JSON.parse(raw) : [];
  } catch (err) {
    return [];
  }
};

const saveInquiries = (data) => {
  fs.writeFileSync(INQUIRIES_FILE, JSON.stringify(data, null, 2));
};

const validateProduct = (body, categories) => {
  const title = String(body.title || "").trim();
  const category = String(body.category || "").trim();
  if (!title || title.length > 120) {
    return { error: "Product title is required and must be 120 characters or fewer." };
  }
  if (!categories.some((item) => item.name === category)) {
    return { error: "Select a valid catalogue." };
  }
  return { title, category };
};

// CSRF & Security Middlewares
const requireSameOrigin = (req, res, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
  const source = req.get("origin") || req.get("referer");
  if (source) {
    try {
      const sourceUrl = new URL(source);
      const requestHost = req.get("host");
      if (sourceUrl.host !== requestHost) {
        return next();
      }
    } catch (err) {
      return next();
    }
  }
  next();
};

const requireCsrfToken = (req, res, next) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  }
  res.locals.csrfToken = req.session.csrfToken;

  if (!["GET", "HEAD", "OPTIONS"].includes(req.method)) {
    const receivedToken = req.body?._csrf || req.query?._csrf || req.get("x-csrf-token");
    if (!receivedToken || receivedToken !== req.session.csrfToken) {
      return res.status(403).send("Invalid CSRF token");
    }
  }
  next();
};

const getClientAddress = (req) => req.ip || req.socket.remoteAddress || "unknown";

router.use(requireSameOrigin);
router.use(requireCsrfToken);

// Auth Guard Middleware
const requireLogin = (req, res, next) => {
  if (req.session && req.session.isAdmin) return next();
  res.redirect("/admin/login");
};

// 1. Admin Login Page
router.get("/login", (req, res) => {
  if (req.session?.isAdmin) return res.redirect("/admin");
  const captcha = createCaptcha();
  req.session.loginCaptchaAnswer = captcha.answer;
  res.render("admin/login", {
    title: "Admin Login",
    error: req.query.error || null,
    captcha,
  });
});

// 2. Admin Login Action
router.post("/login", loginRateLimiter, async (req, res) => {
  const { username, password } = req.body;
  const captchaAnswer = Number(req.body.captchaAnswer);
  const expectedCaptcha = req.session.loginCaptchaAnswer;
  delete req.session.loginCaptchaAnswer;
  const address = getClientAddress(req);
  const now = Date.now();
  const attempt = loginAttempts.get(address) || { count: 0, blockedUntil: 0 };

  if (attempt.blockedUntil > now) {
    return res.redirect("/admin/login?error=Too%20Many%20Attempts");
  }

  if (!Number.isInteger(captchaAnswer) || captchaAnswer !== expectedCaptcha) {
    return res.redirect("/admin/login?error=Invalid%20verification%20answer");
  }

  if (username === adminUsername && (await verifyAdminPassword(password))) {
    loginAttempts.delete(address);
    return req.session.regenerate((err) => {
      if (err) return res.status(500).send("Unable to start session");
      req.session.isAdmin = true;
      req.session.csrfToken = crypto.randomBytes(32).toString("hex");
      req.session.save((saveError) => {
        if (saveError) return res.status(500).send("Unable to save session");
        res.redirect("/admin");
      });
    });
  }

  attempt.count += 1;
  if (attempt.count >= 25) {
    attempt.count = 0;
    attempt.blockedUntil = now + 60 * 1000;
  }
  loginAttempts.set(address, attempt);
  res.redirect("/admin/login?error=Invalid%20Credentials");
});

// 3. Logout
router.post("/logout", requireLogin, (req, res) => {
  req.session.destroy(() => res.redirect("/admin/login"));
});

// 4. Catalogue Management
router.get("/categories", requireLogin, (req, res) => {
  const products = getStoredProducts();
  const categories = getCategories().map((category) => ({
    ...category,
    productCount: products.filter((product) => product.category === category.name).length,
  }));

  res.render("admin/categories", {
    title: "Manage Catalogues",
    categories,
    selectedCategory: "Manage Catalogues",
    query: req.query,
  });
});

router.post("/categories", requireLogin, (req, res) => {
  const name = String(req.body.name || "").trim().replace(/\s+/g, " ");
  if (!name) return res.redirect("/admin/categories?error=missing");

  const categories = getCategories();
  const exists = categories.some(
    (category) => category.name.toLowerCase() === name.toLowerCase(),
  );
  if (exists) return res.redirect("/admin/categories?error=exists");

  categories.push({ name, icon: "fa-folder" });
  saveCategories(categories);
  res.redirect("/admin/categories?success=added");
});

router.delete("/categories/:name", requireLogin, (req, res) => {
  const categoryName = req.params.name;
  const categories = getCategories();
  const products = getStoredProducts();

  if (!categories.some((category) => category.name === categoryName)) {
    return res.redirect("/admin/categories?error=not-found");
  }
  if (categories.length === 1) {
    return res.redirect("/admin/categories?error=last");
  }
  if (products.some((product) => product.category === categoryName)) {
    return res.redirect(
      `/admin/categories?error=has-products&name=${encodeURIComponent(categoryName)}`,
    );
  }

  saveCategories(categories.filter((category) => category.name !== categoryName));
  res.redirect("/admin/categories?success=deleted");
});

// 5. Admin Dashboard
router.get("/", requireLogin, (req, res) => {
  const categories = getCategories();
  const selectedCategory = req.query.category || categories[0].name;
  const allProducts = getStoredProducts();

  const filteredProducts =
    selectedCategory === "All"
      ? allProducts
      : allProducts.filter((p) => p.category === selectedCategory);

  res.render("admin/index", {
    title: "Admin Dashboard",
    products: filteredProducts,
    categories,
    selectedCategory,
    totalCount: allProducts.length,
    catCount: filteredProducts.length,
  });
});

// 6. Add Product Form
router.get("/products/new", requireLogin, (req, res) => {
  const categories = getCategories();
  const requestedCategory = String(req.query.category || "");
  const selectedProductCategory = categories.some((c) => c.name === requestedCategory)
    ? requestedCategory
    : categories[0].name;

  res.render("admin/add", {
    title: "Add New Product",
    categories,
    selectedCategory: "Add Product",
    selectedProductCategory,
    error: null,
  });
});

// 7. Save New Product
router.post("/products", requireLogin, handleProductUpload, async (req, res) => {
  const categories = getCategories();
  const productFields = validateProduct(req.body, categories);

  if (productFields.error) {
    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    return res.status(400).render("admin/add", {
      title: "Add New Product",
      categories,
      selectedCategory: "Add Product",
      selectedProductCategory: req.body?.category || categories[0].name,
      error: productFields.error,
    });
  }

  if (!(await validateUploadedImage(req.file))) {
    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    return res.status(400).render("admin/add", {
      title: "Add New Product",
      categories,
      selectedCategory: "Add Product",
      selectedProductCategory: req.body?.category || categories[0].name,
      error: "The uploaded file is corrupted or not a supported image format.",
    });
  }

  const products = getStoredProducts();
  const newProduct = {
    id: Date.now().toString(),
    title: productFields.title,
    category: productFields.category,
    image: req.file ? `/uploads/${req.file.filename}` : "/images/sink1.png",
  };
  products.unshift(newProduct);
  saveStoredProducts(products);
  res.redirect(`/admin?category=${encodeURIComponent(newProduct.category)}`);
});

// 8. Edit Product Form
router.get("/products/:id/edit", requireLogin, (req, res) => {
  const categories = getCategories();
  const products = getStoredProducts();
  const product = products.find((p) => p.id === req.params.id);
  if (!product) return res.status(404).send("Product not found");

  res.render("admin/edit", {
    title: "Edit Product",
    product,
    categories,
    selectedCategory: "Edit Product",
    error: null,
  });
});

// 9. Update Product Handler (PUT)
router.put("/products/:id", requireLogin, handleProductUpload, async (req, res) => {
  const categories = getCategories();
  const products = getStoredProducts();
  const index = products.findIndex((p) => p.id === req.params.id);

  if (index === -1) {
    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    return res.status(404).send("Product not found");
  }

  const productFields = validateProduct(req.body, categories);
  if (productFields.error) {
    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    return res.status(400).render("admin/edit", {
      title: "Edit Product",
      product: { ...products[index], ...req.body },
      categories,
      selectedCategory: "Edit Product",
      error: productFields.error,
    });
  }

  if (!(await validateUploadedImage(req.file))) {
    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    return res.status(400).render("admin/edit", {
      title: "Edit Product",
      product: { ...products[index], ...req.body },
      categories,
      selectedCategory: "Edit Product",
      error: "The uploaded file is corrupted or not a supported image format.",
    });
  }

  let imagePath = products[index].image;
  if (req.file) {
    if (imagePath && imagePath.startsWith("/uploads/")) {
      const oldImg = path.join(ROOT_DIR, "..", "public", imagePath);
      if (fs.existsSync(oldImg)) fs.unlinkSync(oldImg);
    }
    imagePath = `/uploads/${req.file.filename}`;
  }

  products[index] = {
    ...products[index],
    title: productFields.title,
    category: productFields.category,
    image: imagePath,
  };

  saveStoredProducts(products);
  res.redirect(`/admin?category=${encodeURIComponent(products[index].category)}`);
});

// 10. Delete Product (Deletes image from disk)
router.delete("/products/:id", requireLogin, (req, res) => {
  let products = getStoredProducts();
  const product = products.find((p) => p.id === req.params.id);

  if (product && product.image && product.image.startsWith("/uploads/")) {
    const fullPath = path.join(ROOT_DIR, "..", "public", product.image);
    if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
  }

  const categoryRedirect = product ? product.category : getCategories()[0].name;
  products = products.filter((p) => p.id !== req.params.id);
  saveStoredProducts(products);
  res.redirect(`/admin?category=${encodeURIComponent(categoryRedirect)}`);
});

// 11. Inquiries List Page
router.get("/inquiries", requireLogin, (req, res) => {
  const selectedStatus = req.query.status || "All";
  const allInquiries = getInquiries();

  const filteredInquiries =
    selectedStatus === "All"
      ? allInquiries
      : allInquiries.filter((inq) => {
          const current = inq.status || "Pending";
          return current.toLowerCase() === selectedStatus.toLowerCase();
        });

  const pendingCount = allInquiries.filter(
    (i) => (i.status || "Pending") === "Pending",
  ).length;
  const completedCount = allInquiries.filter(
    (i) => i.status === "Completed",
  ).length;

  res.render("admin/inquiries", {
    title: "Customer Inquiries",
    inquiries: filteredInquiries,
    selectedStatus,
    pendingCount,
    completedCount,
    totalCount: allInquiries.length,
    categories: getCategories(),
    selectedCategory: "Customer Inquiries",
  });
});

// 12. Mark Inquiry as Completed
router.post("/inquiries/:id/complete", requireLogin, (req, res) => {
  let inquiries = getInquiries();
  inquiries = inquiries.map((inq) => {
    if (inq.id === req.params.id) {
      return { ...inq, status: "Completed" };
    }
    return inq;
  });

  saveInquiries(inquiries);
  res.redirect("/admin/inquiries");
});

// 13. Delete Inquiry
router.delete("/inquiries/:id", requireLogin, (req, res) => {
  let inquiries = getInquiries();
  inquiries = inquiries.filter((inq) => inq.id !== req.params.id);
  saveInquiries(inquiries);
  res.redirect("/admin/inquiries");
});

export default router;