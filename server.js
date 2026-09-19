import crypto from "crypto";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import mongoose from "mongoose";
import mongoSanitize from "express-mongo-sanitize";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import Project from "./models/Project.js";

dotenv.config();

/* ---------- Config ---------- */

const {
  MONGO_URI,
  ADMIN_ID,
  PORT = 5000,
  CLIENT_URL = "https://sitebase-platform.netlify.app",
  ALLOW_PUBLIC_ADD,
} = process.env;

for (const [name, value] of Object.entries({ MONGO_URI, ADMIN_ID })) {
  if (!value) {
    console.error(`Missing ${name} in environment variables`);
    process.exit(1);
  }
}

/* ---------- App setup ---------- */

const app = express();
app.set("trust proxy", 1); // Render sits behind a proxy

app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));

app.use(
  cors({
    origin: CLIENT_URL.split(",").map((o) => o.trim()),
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "x-admin-id"],
  }),
);

app.use(express.json({ limit: "50kb" }));
app.use(mongoSanitize());

const createLimiter = (options) =>
  rateLimit({
    windowMs: 15 * 60 * 1000,
    standardHeaders: true,
    legacyHeaders: false,
    ...options,
  });

app.use(
  "/api",
  createLimiter({
    max: 200,
    message: { message: "Too many requests, please try again later." },
  }),
);

// Counts only failed admin attempts (401)
const adminLimiter = createLimiter({
  max: 10,
  skipSuccessfulRequests: true,
  requestWasSuccessful: (req, res) => res.statusCode !== 401,
  message: { message: "Too many failed attempts, please try again later." },
});

/* ---------- Helpers ---------- */

const wrap = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

const safeEqual = (a, b) => {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  return bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB);
};

const isAdminRequest = (req) => {
  const provided = req.headers["x-admin-id"];
  return Boolean(provided) && safeEqual(String(provided).trim(), ADMIN_ID);
};

const requireAdmin = (req, res, next) =>
  isAdminRequest(req)
    ? next()
    : res.status(401).json({ message: "Invalid admin ID" });

const adminOnly = [adminLimiter, requireAdmin];
const addGuard = ALLOW_PUBLIC_ADD === "true" ? [] : adminOnly;

const isValidHttpUrl = (value) => {
  try {
    const { protocol } = new URL(value);
    return protocol === "http:" || protocol === "https:";
  } catch {
    return false;
  }
};

const pickProjectFields = (body = {}) => {
  const text = (v) => (typeof v === "string" ? v.trim() : "");
  return {
    title: text(body.title),
    description: text(body.description),
    liveUrl: text(body.liveUrl),
    image: text(body.image),
  };
};

const validateProject = ({ title, description, liveUrl, image }) => {
  if (!title) return "Title is required";
  if (title.length > 120) return "Title must be under 120 characters";
  if (!description) return "Description is required";
  if (description.length > 2000)
    return "Description must be under 2000 characters";
  if (!liveUrl) return "Live URL is required";
  if (!isValidHttpUrl(liveUrl)) return "Live URL must be a valid http(s) link";
  if (image && !isValidHttpUrl(image))
    return "Preview image must be a valid http(s) link";
  return null;
};

/* ---------- Screenshot proxy ---------- */

const BROWSER_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
const CACHE_MAX = 200;
const screenshotCache = new Map();
const inFlight = new Map();

const isPublicHostname = ({ hostname }) => {
  const host = hostname.toLowerCase();
  if (host === "localhost" || host.endsWith(".local")) return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    const [a, b] = host.split(".").map(Number);
    const isPrivate =
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168);
    if (isPrivate) return false;
  }
  return true;
};

const fetchWithTimeout = async (url, timeoutMs = 20000) => {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, {
      headers: { "User-Agent": BROWSER_UA },
      signal: ctrl.signal,
    });
  } finally {
    clearTimeout(timer);
  }
};

const toShot = async (res, fallbackType) => ({
  type: res.headers.get("content-type")?.split(";")[0] || fallbackType,
  data: Buffer.from(await res.arrayBuffer()),
});

const fromMicrolink = async (url) => {
  const api = `https://api.microlink.io/?url=${encodeURIComponent(url)}&screenshot=true&meta=false&palette=false&video=false`;
  const json = await (await fetchWithTimeout(api)).json();
  const shotUrl = json?.data?.screenshot?.url;
  if (!shotUrl) throw new Error("microlink returned no screenshot");
  const img = await fetchWithTimeout(shotUrl);
  if (!img.ok) throw new Error("microlink image download failed");
  return toShot(img, "image/png");
};

const fromMshots = async (url) => {
  const res = await fetchWithTimeout(
    `https://s0.wp.com/mshots/v1/${encodeURIComponent(url)}?w=640&h=420`,
  );
  if (!res.ok) throw new Error("mshots request failed");
  if (!res.headers.get("content-type")?.startsWith("image/"))
    throw new Error("mshots did not return an image");
  return toShot(res, "image/jpeg");
};

const fetchScreenshot = async (url) => {
  let lastError = "no screenshot service available";
  for (const source of [fromMicrolink, fromMshots]) {
    try {
      return await source(url);
    } catch (err) {
      lastError = err.message;
    }
  }
  throw new Error(lastError);
};

const getScreenshot = (key) => {
  if (screenshotCache.has(key)) return screenshotCache.get(key);
  if (inFlight.has(key)) return inFlight.get(key);

  const promise = fetchScreenshot(key)
    .then((shot) => {
      screenshotCache.set(key, shot);
      if (screenshotCache.size > CACHE_MAX) {
        screenshotCache.delete(screenshotCache.keys().next().value);
      }
      return shot;
    })
    .finally(() => inFlight.delete(key));

  inFlight.set(key, promise);
  return promise;
};

app.get("/api/screenshot", async (req, res) => {
  const raw = req.query.url;
  if (!raw || typeof raw !== "string") {
    return res.status(400).json({ message: "url query parameter is required" });
  }

  let target;
  try {
    target = new URL(raw);
  } catch {
    return res.status(400).json({ message: "Invalid screenshot URL" });
  }
  if (!["http:", "https:"].includes(target.protocol)) {
    return res.status(400).json({ message: "Invalid screenshot URL" });
  }
  if (!isPublicHostname(target)) {
    return res
      .status(400)
      .json({ message: "URL must point to a public address" });
  }

  try {
    const shot = await getScreenshot(target.toString());
    res.set("Content-Type", shot.type);
    res.set("Cache-Control", "public, max-age=86400");
    res.send(shot.data);
  } catch {
    if (!res.headersSent) {
      res.status(502).json({ message: "Could not generate screenshot" });
    }
  }
});

app.post("/api/admin/verify", ...adminOnly, (req, res) =>
  res.status(200).json({ message: "Admin verified" }),
);

app.get(
  "/api/projects",
  wrap(async (req, res) => {
    const projects = await Project.find().sort({ createdAt: -1 }).lean();
    res.status(200).json(projects);
  }),
);

app.post(
  "/api/projects",
  ...addGuard,
  wrap(async (req, res) => {
    const project = pickProjectFields(req.body);
    const error = validateProject(project);
    if (error) return res.status(400).json({ message: error });

    res.status(201).json(await Project.create(project));
  }),
);

app.put(
  "/api/projects/:id",
  ...adminOnly,
  wrap(async (req, res) => {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: "Invalid project ID" });
    }
    const project = pickProjectFields(req.body);
    const error = validateProject(project);
    if (error) return res.status(400).json({ message: error });

    const updated = await Project.findByIdAndUpdate(req.params.id, project, {
      new: true,
      runValidators: true,
    });
    if (!updated) return res.status(404).json({ message: "Project not found" });
    res.status(200).json(updated);
  }),
);

app.delete(
  "/api/projects/:id",
  ...adminOnly,
  wrap(async (req, res) => {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: "Invalid project ID" });
    }
    const deleted = await Project.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ message: "Project not found" });
    res.status(200).json({ message: "Project deleted successfully" });
  }),
);

/* ---------- Fallbacks ---------- */

app.use((req, res) => res.status(404).json({ message: "Route not found" }));

app.use((err, req, res, next) => {
  console.error("Error:", err);
  if (res.headersSent) return next(err);

  if (err.type === "entity.parse.failed") {
    return res.status(400).json({ message: "Invalid JSON in request body" });
  }
  if (err.type === "entity.too.large") {
    return res.status(413).json({ message: "Request body too large" });
  }

  res
    .status(err.status || 500)
    .json({ message: "Something went wrong on the server" });
});

/* ---------- Startup & shutdown ---------- */

mongoose.connection.on("error", (err) =>
  console.error("MongoDB error:", err.message),
);
mongoose.connection.on("disconnected", () =>
  console.warn("MongoDB disconnected"),
);

mongoose
  .connect(MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => {
    console.error("MongoDB connection error:", err.message);
    process.exit(1);
  });

const server = app.listen(PORT, () =>
  console.log(`Server running on port ${PORT}`),
);

process.on("unhandledRejection", (reason) =>
  console.error(
    "Unhandled rejection:",
    reason instanceof Error ? reason.stack : reason,
  ),
);
process.on("uncaughtException", (err) =>
  console.error("Uncaught exception:", err.stack || err),
);

const shutdown = () => {
  const forceExit = setTimeout(() => process.exit(1), 5000);
  forceExit.unref();
  server.close(() => {
    clearTimeout(forceExit);
    mongoose.connection.close(false, () => process.exit(0));
  });
};
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
