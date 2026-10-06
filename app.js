import express from "express";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import session from "express-session";
import sessionFileStore from "session-file-store";
import adminRoutes from "./routes/admin.js";
import methodOverride from "method-override";
import crypto from "crypto";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import "./config/env.js";



const PORT = process.env.PORT ;
const ROOT_DIR = path.dirname(fileURLToPath(import.meta.url));
const sessionSecret = process.env.SESSION_SECRET || "secret_session_KEY";
const CATEGORIES_FILE = path.join(ROOT_DIR, "categories.json");
const GALLERY_CATEGORIES = new Set([
  "Factory Infrastructure",
  "Leadership & Team",
  "Miscellaneous",
]);


if (!sessionSecret) {
  throw new Error("SESSION_SECRET must be set in the environment.");
}

const app = express();

app.set("trust proxy", process.env.TRUST_PROXY === "true" ? 1 : false);
app.use(helmet({ contentSecurityPolicy: false }));

app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: true, limit: "100kb" }));
app.use(express.json({ limit: "100kb" }));
app.use(express.static(path.join(ROOT_DIR, "public")));
// Yeh line add karo (action query me ?_method=DELETE ya PUT detect karega)
app.use(methodOverride("_method"));

const FileStore = sessionFileStore(session);
//for admin session
 app.use(
  session({
    store: new FileStore({
      path: path.join(ROOT_DIR, "sessions"),
      retries: 5,               // Give Windows 5 retry attempts before failing
      factor: 1,                // Linear backoff
      minTimeout: 50,           // Wait 50ms before retrying
      maxTimeout: 200,          // Max wait between retries
      reapInterval: -1,         // Prevent background auto-purging from causing file collisions
      logFn: () => {},
    }),
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production" || process.env.SESSION_SECURE === "true",
      httpOnly: true,
      sameSite: "lax",
      maxAge: 24 * 60 * 60 * 1000,
    },
  })
);

// 2. Company Details Constant
const company = {
  name: "Jeson International",
  tagline: "Premium Kitchen Sinks & Building Materials",
  phone: "+91 8924914868",
  whatsapp: "8924914868",
  address:
    "Usha Complex Society Rd, Bhandup West, Mumbai, Maharashtra 400078, India",
  website: "https://www.jesoninternational.com/",
  email: "info@jesoninternational.in",
};

const createCaptcha = () => {
  const first = crypto.randomInt(2, 10);
  const second = crypto.randomInt(2, 10);
  return { question: `${first} + ${second}`, answer: first + second };
};

// 3. Global Data Middleware (Har EJS view me direct access ke liye)
app.use((req, res, next) => {
  res.locals.company = company;
  res.locals.currentPath = req.path;
  res.locals.productCategories = getPublicCategories();
  next();
});

// '/admin' se shuru hone wale saare routes adminRoutes handle karega
app.use("/admin", adminRoutes);

const DATA_FILE = path.join(ROOT_DIR, "products.json");

const getStoredProducts = () => {
  try {
    const raw = fs.readFileSync(DATA_FILE, "utf-8").trim();
    return raw ? JSON.parse(raw) : [];
  } catch (err) {
    return [];
  }
};

const getCategories = () => {
  try {
    const raw = fs.readFileSync(CATEGORIES_FILE, "utf-8").trim();
    const categories = raw ? JSON.parse(raw) : [];
    return Array.isArray(categories) ? categories : [];
  } catch (err) {
    return [];
  }
};

const getPublicCategories = () =>
  getCategories()
    .map((category) => category.name)
    .filter((name) => !GALLERY_CATEGORIES.has(name));

app.get("/", (req, res) => {
  res.render("index", {
    title: `${company.name} | Home`,
    products: getStoredProducts(),
    categories: getPublicCategories(),
  });
});

const INQUIRIES_FILE = path.join(ROOT_DIR, "inquiries.json");

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

const contactRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 25,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: "Too many inquiries. Please try again later.",
});

//product page

app.get("/products", (req, res) => {
  const selectedCategory = req.query.category || "All";
  const allItems = getStoredProducts();

  const productOnly = allItems.filter((p) => !GALLERY_CATEGORIES.has(p.category));

  const filteredProducts =
    selectedCategory === "All"
      ? productOnly
      : productOnly.filter((p) => p.category === selectedCategory);

  const categories = ["All", ...getPublicCategories()];

  res.render("products", {
    title: `Product Catalogue | ${res.locals.company.name}`,
    products: filteredProducts,
    categories,
    selectedCategory,
  });
});

//about us page
app.get("/about-us", (req, res) => {
  res.render("about", { title: `About Us | ${company.name}` });
});

// Contact Page Render
app.get("/contact-us", (req, res) => {
  const captcha = createCaptcha();
  req.session.contactCaptchaAnswer = captcha.answer;
  res.render("contact", {
    title: `Contact Us | ${company.name}`,
    success: req.query.success === "true",
    error: req.query.error || null,
    captcha,
  });
});

// Inquiry Form Submit Handler
app.post("/contact-us", contactRateLimiter, (req, res) => {
  const captchaAnswer = Number(req.body.captchaAnswer);
  const expectedCaptcha = req.session.contactCaptchaAnswer;
  delete req.session.contactCaptchaAnswer;

  if (!Number.isInteger(captchaAnswer) || captchaAnswer !== expectedCaptcha) {
    return res.redirect("/contact-us?error=Invalid%20verification%20answer");
  }

  const name = String(req.body.name || "").trim().slice(0, 100);
  const phone = String(req.body.phone || "").trim().slice(0, 30);
  const sinkModel = String(req.body.sinkModel || "").trim().slice(0, 120);
  const message = String(req.body.message || "").trim().slice(0, 2000);

  if (!name || !phone || !message) {
    return res.redirect("/contact-us?error=Name%2C%20phone%2C%20and%20message%20are%20required");
  }

  const inquiries = getInquiries();

  inquiries.unshift({
    id: Date.now().toString(),
    date: new Date().toLocaleString("en-IN", { timeZone: "Asia/Kolkata" }),
    name,
    phone,
    sinkModel: sinkModel || "General Inquiry",
    message,
    status: "Pending",
  });

  saveInquiries(inquiries);
  res.redirect("/contact-us?success=true");
});

app.get("/gallery", (req, res) => {
  const products = getStoredProducts();
  res.render("gallery", {
    title: `Infrastructure Gallery | ${company.name}`,
    products,
  });
});

app.get("/health" , (req , res)=>{
  res.send("Server Working Good");
});

app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return next(err);
  const status = err.code === "LIMIT_FILE_SIZE" || err.message?.startsWith("Only ") ? 400 : 500;
  res.status(status).send(status === 400 ? err.message : "Something went wrong. Please try again.");
});

app.use((req, res) => {
  res.status(404).render("404", {
    title: "Page Not Found",
  });
});

app.listen(PORT, () => {
  console.log(`app is listening on port ${PORT}`);
});
