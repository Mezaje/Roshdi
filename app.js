// /app.js — Secure Admin + ImageKit Uploads (Server-side)
"use strict";
require("dotenv").config();

const express = require("express");
const path = require("path");
const fs = require("fs");
const mongoose = require("mongoose");
const helmet = require("helmet");
const compression = require("compression");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const rateLimit = require("express-rate-limit");
const mongoSanitize = require("express-mongo-sanitize");
const csrf = require("csurf");
const ImageKit = require("imagekit");

const app = express();

/* ---------- Config ---------- */
const PORT = process.env.PORT || 4000;
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/roshdi_poetry";
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "password";
const ADMIN_PASS_HASH = process.env.ADMIN_PASS_HASH || ""; // bcrypt hash (اختياري)
const SESSION_SECRET = process.env.SESSION_SECRET || "change-me-secret";
const COOKIE_SECURE = /^(1|true)$/i.test(String(process.env.COOKIE_SECURE || ""));
const TRUST_PROXY = /^(1|true)$/i.test(String(process.env.TRUST_PROXY || "1"));

// ImageKit env (required for uploads)
const IK_PUBLIC_KEY = process.env.IMAGEKIT_PUBLIC_KEY || "";
const IK_PRIVATE_KEY = process.env.IMAGEKIT_PRIVATE_KEY || "";
const IK_URL_ENDPOINT = process.env.IMAGEKIT_URL_ENDPOINT || "";
const IK_FOLDER = process.env.IMAGEKIT_FOLDER || "/roshdi-uploads";

// Fail fast if ImageKit config missing (why: avoid silent local writes)
if (!IK_PUBLIC_KEY || !IK_PRIVATE_KEY || !IK_URL_ENDPOINT) {
  console.error("❌ Missing ImageKit env. Set IMAGEKIT_PUBLIC_KEY, IMAGEKIT_PRIVATE_KEY, IMAGEKIT_URL_ENDPOINT");
  process.exit(1);
}
const imagekit = new ImageKit({
  publicKey: IK_PUBLIC_KEY,
  privateKey: IK_PRIVATE_KEY,
  urlEndpoint: IK_URL_ENDPOINT,
});

/* ---------- Express base ---------- */
app.set("trust proxy", TRUST_PROXY);
app.disable("x-powered-by");
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public"), { maxAge: "7d", immutable: true }));
// keep /uploads static in case of legacy files; new uploads go to ImageKit
app.use("/uploads", express.static(path.join(__dirname, "uploads"), { maxAge: "7d", immutable: true }));
app.use(express.urlencoded({ extended: true, limit: "200kb" }));
app.use(express.json({ limit: "200kb" }));

// ✅ Sanitization in-place (لا إعادة تعيين للكائنات)
const sanitizeInPlace = (obj, opts = {}) => {
  if (!obj || typeof obj !== "object") return;
  mongoSanitize.sanitize(obj, opts);
};
app.use((req, _res, next) => {
  const opts = { replaceWith: "_" };
  try { sanitizeInPlace(req.body, opts); } catch {}
  try { sanitizeInPlace(req.params, opts); } catch {}
  try { sanitizeInPlace(req.query, opts); } catch {}
  next();
});

app.use(helmet({
  crossOriginOpenerPolicy: { policy: "same-origin" },
  crossOriginResourcePolicy: { policy: "same-site" },
  contentSecurityPolicy: false, // لدينا CSS/JS ضمن القوالب
  referrerPolicy: { policy: "strict-origin-when-cross-origin" }
}));
app.use(compression());

/* ---------- Sessions (Mongo store) ---------- */
app.use(session({
  name: "roshdi.sid",
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: COOKIE_SECURE,
    maxAge: 1000 * 60 * 60 * 8 // 8h
  },
  store: MongoStore.create({
    mongoUrl: MONGODB_URI,
    ttl: 60 * 60 * 24 * 7,
    crypto: { secret: SESSION_SECRET }
  })
}));
app.use((_req, res, next) => { res.setHeader("Cache-Control", "no-cache"); next(); });

/* ---------- CSRF (نطبقها على الإدارة فقط لتفادي كسر الواجهات العامة) ---------- */
const csrfProtection = csrf();
app.use((req, res, next) => { res.locals.admin = req.session?.admin || null; next(); });

/* ---------- Uploads (multer + file signature verify + ImageKit) ---------- */
const UPLOAD_DIR = path.join(__dirname, "uploads");
fs.mkdirSync(UPLOAD_DIR, { recursive: true }); // legacy dir

// Use memory storage (why: upload buffer directly to ImageKit, no disk I/O)
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  fileFilter: (_req, file, cb) => {
    if (/^image\/(png|jpe?g|webp|gif)$/i.test(file.mimetype)) return cb(null, true);
    cb(new Error("الملف يجب أن يكون صورة (PNG/JPG/WebP/GIF)."));
  },
  limits: { fileSize: 5 * 1024 * 1024 },
});

// Magic-bytes validation in memory (why: block spoofed extensions)
function isValidImageSignatureBuffer(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 12) return false;
  // PNG
  if (buf.slice(0, 8).equals(Buffer.from([0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A]))) return true;
  // JPEG
  if (buf[0] === 0xFF && buf[1] === 0xD8) return true;
  // GIF
  if (buf.slice(0, 6).toString() === "GIF87a" || buf.slice(0, 6).toString() === "GIF89a") return true;
  // WEBP
  if (buf.slice(0, 4).toString() === "RIFF" && buf.slice(8, 12).toString() === "WEBP") return true;
  return false;
}

async function uploadToImageKit({ buffer, originalname }) {
  const ext = path.extname(originalname || "").toLowerCase();
  const safeExt = [".png", ".jpg", ".jpeg", ".webp", ".gif"].includes(ext) ? ext : ".png";
  const fileName = `img-${Date.now()}-${Math.round(Math.random() * 1e9)}${safeExt}`;
  const result = await imagekit.upload({
    file: buffer,
    fileName,
    folder: IK_FOLDER,
    useUniqueFileName: true,
  });
  return { url: result.url, fileId: result.fileId };
}

async function deleteFromImageKit(fileId) {
  if (!fileId) return;
  try { await imagekit.deleteFile(fileId); } catch { /* ignore delete failures */ }
}

/* ---------- Rate Limits & Lockout ---------- */
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false, message: "محاولات كثيرة. حاول لاحقًا." });
const adminApiLimiter = rateLimit({ windowMs: 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false });
const attempts = new Map(); // key: ip|ua|user -> {count, until}
const bindKey = (req) => `${(req.ip || "").toString()}|${(req.get("user-agent") || "").slice(0,120)}`;
function isLocked(key){ const r=attempts.get(key); if(!r) return false; if(r.until && Date.now()<r.until) return true; if(r.until && Date.now()>=r.until) attempts.delete(key); return false; }
function failAttempt(key){ const r=attempts.get(key)||{count:0,until:0}; r.count++; const b=Math.min(r.count,6); r.until=Date.now()+b*60*1000; attempts.set(key,r); }
function resetAttempt(key){ attempts.delete(key); }

/* ---------- Mongo & Models ---------- */
mongoose.set("strictQuery", true);

const poemSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true },
  meter: { type: String, trim: true, default: "" },
  tags: { type: [String], default: [] },
  excerpt: { type: String, trim: true, default: "" },
  body: { type: String, trim: true, default: "" },
  imageUrl: { type: String, default: "" },
  imageKitId: { type: String, default: "" }, // needed to delete/replace on ImageKit
  createdAt: { type: Date, default: Date.now, index: true },
}, { versionKey: false });
poemSchema.index({ title: "text", excerpt: "text", body: "text" });
const Poem = mongoose.model("Poem", poemSchema);

const articleSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true },
  slug: { type: String, required: true, trim: true, unique: true },
  tags: { type: [String], default: [] },
  excerpt: { type: String, trim: true, default: "" },
  content: { type: String, trim: true, default: "" },
  imageUrl: { type: String, default: "" },
  imageKitId: { type: String, default: "" }, // needed to delete/replace on ImageKit
  createdAt: { type: Date, default: Date.now, index: true },
}, { versionKey: false });
articleSchema.index({ title: "text", excerpt: "text", content: "text" });
const Article = mongoose.model("Article", articleSchema);

const subscriberSchema = new mongoose.Schema({
  email: { type: String, required: true, lowercase: true, trim: true, unique: true },
  ip: String, ua: String, createdAt: { type: Date, default: Date.now },
}, { versionKey: false });
const Subscriber = mongoose.model("Subscriber", subscriberSchema);

/* ---------- Seed (dev only) ---------- */
async function seedIfEmpty() {
  const pc = await Poem.estimatedDocumentCount();
  if (pc === 0) {
    await Poem.insertMany([
      { title: "على الرمل", meter: "بحر الكامل", tags: ["غزل"], excerpt: "على الرملِ تمشي...", body: "متن القصيدة…", createdAt: new Date("2025-10-05") },
      { title: "ملح الطريق", meter: "بحر البسيط", tags: ["حكمة"], excerpt: "وما السنينُ سوى...", body: "متن القصيدة…", createdAt: new Date("2025-09-22") },
    ]);
  }
  const ac = await Article.estimatedDocumentCount();
  if (ac === 0) {
    await Article.insertMany([
      { title: "كيف أكتب القصيدة الأولى؟", slug: "first-poem", tags: ["كتابة"], excerpt: "مفاتيح عملية...", content: "نص المقال…", createdAt: new Date("2025-10-10") },
    ]);
  }
}

/* ---------- Auth (sessions) ---------- */
function softIp(ip){ const m=String(ip||"").match(/^(\d+\.\d+)\./); return m?m[1]:ip; }
function requireAdminSession(req, res, next) {
  const s = req.session;
  if (!s || !s.admin) return res.redirect("/admin/login?e=auth");
  const ua = req.get("user-agent") || "";
  const ipFrag = softIp(req.ip || "");
  if (s.admin.ua !== ua || s.admin.ipFrag !== ipFrag) {
    return req.session.destroy(() => res.redirect("/admin/login?e=bind"));
  }
  res.setHeader("Cache-Control", "no-store");
  next();
}

app.get("/admin/login", csrfProtection, (req, res) => {
  res.render("admin/login", { title: "تسجيل الدخول", e: req.query.e || "", csrfToken: req.csrfToken() });
});
app.post("/admin/login", loginLimiter, csrfProtection, async (req, res) => {
  const { username = "", password = "" } = req.body;
  const key = `${bindKey(req)}|${username}`;
  if (isLocked(key)) return res.redirect("/admin/login?e=locked");

  const userOk = username === ADMIN_USER;
  let passOk = false;
  if (ADMIN_PASS_HASH) {
    try { passOk = await bcrypt.compare(password, ADMIN_PASS_HASH); } catch { passOk = false; }
  } else {
    const a = Buffer.from(String(password)), b = Buffer.from(String(ADMIN_PASS));
    const len = Math.max(a.length, b.length); let eq = 0; for (let i=0;i<len;i++) eq |= (a[i]||0) ^ (b[i]||0);
    passOk = (eq === 0);
  }
  if (!userOk || !passOk) { failAttempt(key); return res.redirect("/admin/login?e=bad"); }

  resetAttempt(key);
  req.session.regenerate(err => {
    if (err) return res.redirect("/admin/login?e=err");
    req.session.admin = { username, at: Date.now(), ua: req.get("user-agent") || "", ipFrag: softIp(req.ip || "") };
    req.session.save(() => res.redirect("/admin"));
  });
});
app.post("/admin/logout", csrfProtection, (req, res) => req.session.destroy(() => res.redirect("/admin/login?e=out")));

/* ---------- Public ---------- */
app.get("/", async (req, res, next) => {
  try {
    const [poems, articles] = await Promise.all([
      Poem.find({}).sort({ createdAt: -1 }).limit(12).lean(),
      Article.find({}).sort({ createdAt: -1 }).limit(6).lean(),
    ]);
    res.render("home", { title: "رشدي | منصة الشعر العربي", poems, articles, sub: req.query.sub || "" });
  } catch (e) { next(e); }
});
app.post("/subscribe", loginLimiter, async (req, res) => {
  const email = (req.body.email || "").toLowerCase().trim();
  const valid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  if (!valid) return res.redirect("/?sub=bad");
  try {
    await Subscriber.updateOne({ email }, { $setOnInsert: { email, ip: req.ip, ua: req.get("user-agent") } }, { upsert: true });
    return res.redirect("/?sub=ok");
  } catch (e) {
    if (e && e.code === 11000) return res.redirect("/?sub=dup");
    return res.redirect("/?sub=err");
  }
});

/* ---------- Details & Lists ---------- */
app.get("/poem/:id", async (req, res, next) => {
  try {
    const p = await Poem.findById(req.params.id).lean();
    if (!p) return res.status(404).render("404", { title: "غير موجود" });

    const tag = (p.tags && p.tags[0]) || null;
    const q = tag ? { _id: { $ne: p._id }, tags: tag } : { _id: { $ne: p._id } };
    const relatedPoems = await Poem.find(q).sort({ createdAt: -1 }).limit(6).lean();

    const prevPoem = await Poem.findOne({ createdAt: { $lt: p.createdAt } }).sort({ createdAt: -1 }).select("_id title imageUrl createdAt").lean();
    const nextPoem = await Poem.findOne({ createdAt: { $gt: p.createdAt } }).sort({ createdAt: 1 }).select("_id title imageUrl createdAt").lean();

    res.render("poem", { title: p.title, p, relatedPoems, prevPoem, nextPoem });
  } catch (e) { next(e); }
});

app.get("/poems", async (req, res, next) => {
  try {
    const page = Math.max(parseInt(req.query.page || "1", 10), 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit || "12", 10), 6), 36);
    const count = await Poem.estimatedDocumentCount();
    const totalPages = Math.max(Math.ceil(count / limit), 1);
    const current = Math.min(page, totalPages);
    const skip = (current - 1) * limit;

    const poems = await Poem.find({}).sort({ createdAt: -1 }).skip(skip).limit(limit).lean();

    function buildPages(cur, total) {
      const s = new Set([1, total, cur, cur - 1, cur + 1, cur - 2, cur + 2].filter(n => n >= 1 && n <= total));
      return Array.from(s).sort((a, b) => a - b);
    }
    res.render("poems_index", { title: "كل القصائد", poems, count, page: current, limit, totalPages, pages: buildPages(current, totalPages) });
  } catch (e) { next(e); }
});

app.get("/article/:slug", async (req, res, next) => {
  try {
    const a = await Article.findOne({ slug: req.params.slug }).lean();
    if (!a) return res.status(404).render("404", { title: "غير موجود" });
    res.render("article", { title: a.title, a });
  } catch (e) { next(e); }
});

app.get("/articles", async (req, res, next) => {
  try {
    const page = Math.max(parseInt(req.query.page || "1", 10), 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit || "12", 10), 6), 36);
    const count = await Article.estimatedDocumentCount();
    const totalPages = Math.max(Math.ceil(count / limit), 1);
    const current = Math.min(page, totalPages);
    const skip = (current - 1) * limit;

    const articles = await Article.find({}).sort({ createdAt: -1 }).skip(skip).limit(limit).lean();

    function buildPages(cur, total) {
      const s = new Set([1, total, cur, cur - 1, cur + 1, cur - 2, cur + 2].filter(n => n >= 1 && n <= total));
      return Array.from(s).sort((a, b) => a - b);
    }
    res.render("articles_index", { title: "كل المقالات", articles, count, page: current, limit, totalPages, pages: buildPages(current, totalPages) });
  } catch (e) { next(e); }
});

// PATCH: /app.js — add /about route (place near other Public routes)
app.get("/about", async (req, res, next) => {
    try {
      // Optional stats
      const [pc, ac] = await Promise.all([
        Poem.estimatedDocumentCount(),
        Article.estimatedDocumentCount(),
      ]);
  
      // Profile data (compiled from public sources)
      const profile = {
        name: "رشدي بن إبراهيم الغدير الدوسري",
        shortName: "رشدي الغدير",
        birth: { h: "14 رمضان 1392هـ", g: "1972", place: "جزيرة دارين، شرق السعودية" },
        avatar: "https://ik.imagekit.io/o7rmqqhep/roshdi-uploads/img-1761678421802-821081079_14_Ml0T-Y.jpg?updatedAt=1761678423898", // ضع رابط صورة (ImageKit) إن وُجد
        tagline: "شاعر سعودي يكتب على الحافة، بنبرةٍ سرديةٍ حادّة ومجازٍ كثيف.",
        bio: [
          "وُلد الشاعر في جزيرة دارين عام 1972، وبرز بأسلوبٍ شخصي يجمع بين السرد الحر والقصيدة الحديثة، مع حضورٍ لغويّ مكثّف وتيمات وجدانية ووجودية.",
          "له ديوان مطبوع بعنوان «دارين»، وتناولت الصحافة تجربته وحضوره الجدلي في المشهد الثقافي العربي.",
        ],
        works: [
          { title: "دارين", type: "ديوان شعر", year: "", note: "مطبوع ومترجم إلى أكثر من لغة." },
        ],
        milestones: [
          { year: "2008", title: "جائزة صحفية", desc: "إشارة صحفية إلى فوزه بقصيدة «شهادة سِرّي» وإلى صدور ديوانه «دارين».", ref: "EmaratAlYoum" },
        ],
        quotes: [
          {
            text: "استرسل في شعره منذ صغره... وأثار ضجة كبيرة حين كتب شعوذته الشعرية...",
            by: "رؤى (حوار صحفي)",
          },
        ],
        links: [
          { label: "مدونة (WordPress)", href: "https://roshdi.wordpress.com/", rel: "me" },
          { label: "مدونة أخرى", href: "https://saudiroshdi.wordpress.com/" },
          { label: "صفحة فيسبوك", href: "https://www.facebook.com/p/Roshdi-al-ghadeer-100064469693239/" },
          { label: "تقرير صحفي – الإمارات اليوم (2008)", href: "https://www.emaratalyoum.com/local-section/2008-02-15-1.190091" },
        ],
        stats: { poems: pc, articles: ac },
      };
  
      res.render("About", {
        title: `عن ${profile.shortName}`,
        profile,
        meta: {
          description: "سيرة الشاعر رشدي الغدير، أعماله، محطّاته، واقتباسات صحفية.",
          url: `${req.protocol}://${req.get("host")}/about`,
        },
      });
    } catch (e) { next(e); }
  });
  

/* ---------- Admin (protected) ---------- */
app.use("/admin", adminApiLimiter);

app.get("/admin", requireAdminSession, async (_req, res, next) => {
  try {
    const [pc, ac, sc] = await Promise.all([
      Poem.estimatedDocumentCount(),
      Article.estimatedDocumentCount(),
      Subscriber.estimatedDocumentCount(),
    ]);
    res.render("admin/index", { title: "لوحة التحكم", stats: { pc, ac, sc } });
  } catch (e) { next(e); }
});

/* Poems (Admin) */
app.get("/admin/poems", requireAdminSession, async (_req, res, next) => {
  try {
    const poems = await Poem.find({}).sort({ createdAt: -1 }).lean();
    res.render("admin/poems_list", { title: "القصائد", poems, flash: res.req.query.ok || "" });
  } catch (e) { next(e); }
});
app.get("/admin/poems/new", requireAdminSession, csrfProtection, (req, res) => {
  res.render("admin/poems_new", { title: "قصيدة جديدة", csrfToken: req.csrfToken() });
});
app.post("/admin/poems", requireAdminSession, upload.single("image"), csrfProtection, async (req, res, next) => {
  try {
    const { title, meter, tags, excerpt, body, createdAt } = req.body;

    let imageUrl = "";
    let imageKitId = "";
    if (req.file) {
      const { buffer, originalname } = req.file;
      if (!isValidImageSignatureBuffer(buffer)) {
        const err = new Error("ملف الصورة غير صالح.");
        err.status = 400; throw err;
      }
      const uploaded = await uploadToImageKit({ buffer, originalname });
      imageUrl = uploaded.url;
      imageKitId = uploaded.fileId;
    }

    const doc = new Poem({
      title: String(title).trim(),
      meter: String(meter || "").trim(),
      tags: String(tags || "").split(",").map((t) => t.trim()).filter(Boolean),
      excerpt: String(excerpt || "").trim(),
      body: String(body || "").trim(),
      imageUrl,
      imageKitId,
      createdAt: createdAt ? new Date(createdAt) : new Date(),
    });
    await doc.save();
    res.redirect("/admin/poems?ok=created");
  } catch (e) { next(e); }
});
app.get("/admin/poems/:id/edit", requireAdminSession, csrfProtection, async (req, res, next) => {
  try {
    const poem = await Poem.findById(req.params.id).lean();
    if (!poem) return res.status(404).send("القصيدة غير موجودة.");
    res.render("admin/poems_edit", { title: `تعديل: ${poem.title}`, poem, csrfToken: req.csrfToken() });
  } catch (e) { next(e); }
});
app.post("/admin/poems/:id", requireAdminSession, upload.single("image"), csrfProtection, async (req, res, next) => {
  try {
    const poem = await Poem.findById(req.params.id);
    if (!poem) return res.status(404).send("القصيدة غير موجودة.");

    poem.title   = String(req.body.title || poem.title).trim();
    poem.meter   = String(req.body.meter || "").trim();
    poem.tags    = String(req.body.tags || "").split(",").map(t=>t.trim()).filter(Boolean);
    poem.excerpt = String(req.body.excerpt || "").trim();
    poem.body    = String(req.body.body || "").trim();
    if (req.body.createdAt) poem.createdAt = new Date(req.body.createdAt);

    const removeImage = String(req.body.removeImage || "") === "on";
    if (removeImage && poem.imageKitId) {
      await deleteFromImageKit(poem.imageKitId);
      poem.imageUrl = ""; poem.imageKitId = "";
    } else if (removeImage && poem.imageUrl && !poem.imageKitId) {
      // legacy local file cleanup if any
      try {
        const filePath = path.join(__dirname, poem.imageUrl.replace(/^\/+/, ""));
        if (filePath.startsWith(path.join(__dirname, "uploads")) && fs.existsSync(filePath)) fs.unlinkSync(filePath);
      } catch {}
      poem.imageUrl = "";
    }

    if (req.file) {
      const { buffer, originalname } = req.file;
      if (!isValidImageSignatureBuffer(buffer)) {
        const err=new Error("ملف الصورة غير صالح."); err.status=400; throw err;
      }
      if (poem.imageKitId) await deleteFromImageKit(poem.imageKitId);
      const uploaded = await uploadToImageKit({ buffer, originalname });
      poem.imageUrl = uploaded.url;
      poem.imageKitId = uploaded.fileId;
    }

    await poem.save();
    res.redirect("/admin/poems?ok=updated");
  } catch (e) { next(e); }
});
app.post("/admin/poems/:id/delete", requireAdminSession, csrfProtection, async (req, res, next) => {
  try {
    const doc = await Poem.findByIdAndDelete(req.params.id);
    if (doc?.imageKitId) await deleteFromImageKit(doc.imageKitId);
    // legacy local cleanup
    if (doc?.imageUrl && !doc?.imageKitId) {
      try {
        const filePath = path.join(__dirname, doc.imageUrl.replace(/^\/+/, ""));
        if (filePath.startsWith(path.join(__dirname, "uploads")) && fs.existsSync(filePath)) fs.unlinkSync(filePath);
      } catch {}
    }
    res.redirect("/admin/poems?ok=deleted");
  } catch (e) { next(e); }
});

/* Articles (Admin) */
app.get("/admin/articles", requireAdminSession, async (_req, res, next) => {
  try {
    const articles = await Article.find({}).sort({ createdAt: -1 }).lean();
    res.render("admin/articles_list", { title: "المقالات", articles, flash: res.req.query.ok || "" });
  } catch (e) { next(e); }
});
app.get("/admin/articles/new", requireAdminSession, csrfProtection, (req, res) => {
  res.render("admin/article_new", { title: "مقال جديد", csrfToken: req.csrfToken() });
});
app.post("/admin/articles", requireAdminSession, upload.single("image"), csrfProtection, async (req, res, next) => {
  try {
    const { title, slug, tags, excerpt, content, createdAt } = req.body;

    let imageUrl = "";
    let imageKitId = "";
    if (req.file) {
      const { buffer, originalname } = req.file;
      if (!isValidImageSignatureBuffer(buffer)) {
        const err = new Error("ملف الصورة غير صالح.");
        err.status = 400; throw err;
      }
      const uploaded = await uploadToImageKit({ buffer, originalname });
      imageUrl = uploaded.url;
      imageKitId = uploaded.fileId;
    }

    const doc = new Article({
      title: String(title).trim(),
      slug: String(slug).trim(),
      tags: String(tags || "").split(",").map((t) => t.trim()).filter(Boolean),
      excerpt: String(excerpt || "").trim(),
      content: String(content || "").trim(),
      imageUrl,
      imageKitId,
      createdAt: createdAt ? new Date(createdAt) : new Date(),
    });
    await doc.save();
    res.redirect("/admin/articles?ok=created");
  } catch (e) {
    if (e && e.code === 11000) return res.status(400).send("Slug مستخدم مسبقًا.");
    next(e);
  }
});
app.get("/admin/articles/:id/edit", requireAdminSession, csrfProtection, async (req, res, next) => {
  try {
    const article = await Article.findById(req.params.id).lean();
    if (!article) return res.status(404).send("المقال غير موجود.");
    res.render("admin/articles_edit", { title: `تعديل: ${article.title}`, article, csrfToken: req.csrfToken() });
  } catch (e) { next(e); }
});
app.post("/admin/articles/:id", requireAdminSession, upload.single("image"), csrfProtection, async (req, res, next) => {
  try {
    const article = await Article.findById(req.params.id);
    if (!article) return res.status(404).send("المقال غير موجود.");

    const newSlug = String(req.body.slug || article.slug).trim();
    article.title   = String(req.body.title || article.title).trim();
    article.slug    = newSlug;
    article.tags    = String(req.body.tags || "").split(",").map(t=>t.trim()).filter(Boolean);
    article.excerpt = String(req.body.excerpt || "").trim();
    article.content = String(req.body.content || "").trim();
    if (req.body.createdAt) article.createdAt = new Date(req.body.createdAt);

    const removeImage = String(req.body.removeImage || "") === "on";
    if (removeImage && article.imageKitId) {
      await deleteFromImageKit(article.imageKitId);
      article.imageUrl = ""; article.imageKitId = "";
    } else if (removeImage && article.imageUrl && !article.imageKitId) {
      // legacy local cleanup
      try {
        const filePath = path.join(__dirname, article.imageUrl.replace(/^\/+/, ""));
        if (filePath.startsWith(path.join(__dirname, "uploads")) && fs.existsSync(filePath)) fs.unlinkSync(filePath);
      } catch {}
      article.imageUrl = "";
    }

    if (req.file) {
      const { buffer, originalname } = req.file;
      if (!isValidImageSignatureBuffer(buffer)) {
        const err=new Error("ملف الصورة غير صالح."); err.status=400; throw err;
      }
      if (article.imageKitId) await deleteFromImageKit(article.imageKitId);
      const uploaded = await uploadToImageKit({ buffer, originalname });
      article.imageUrl = uploaded.url;
      article.imageKitId = uploaded.fileId;
    }

    await article.save();
    res.redirect("/admin/articles?ok=updated");
  } catch (e) {
    if (e && e.code === 11000) return res.status(400).send("Slug مستخدم مسبقًا.");
    next(e);
  }
});
app.post("/admin/articles/:id/delete", requireAdminSession, csrfProtection, async (req, res, next) => {
  try {
    const doc = await Article.findByIdAndDelete(req.params.id);
    if (doc?.imageKitId) await deleteFromImageKit(doc.imageKitId);
    // legacy local cleanup
    if (doc?.imageUrl && !doc?.imageKitId) {
      try {
        const filePath = path.join(__dirname, doc.imageUrl.replace(/^\/+/, ""));
        if (filePath.startsWith(path.join(__dirname, "uploads")) && fs.existsSync(filePath)) fs.unlinkSync(filePath);
      } catch {}
    }
    res.redirect("/admin/articles?ok=deleted");
  } catch (e) { next(e); }
});

/* ---------- Errors ---------- */
app.use((req, res) => res.status(404).render("404", { title: "غير موجود" }));
app.use((err, _req, res, _next) => {
  console.error(err);
  const status = err.status || 500;
  res.status(status);
  try {
    return res.render("error", { title: "خطأ", status, message: err.message || "حدث خطأ غير متوقع." });
  } catch {
    return res.type("text").send(`Error ${status}: ${err.message || "Unexpected error"}`);
  }
});

/* ---------- Start ---------- */
async function start() {
  await mongoose.connect(MONGODB_URI, { autoIndex: true });
  await seedIfEmpty();
  app.listen(PORT, "0.0.0.0", () => console.log(`HTTP on :${PORT}`));
}
if (require.main === module) start();
module.exports = app;
