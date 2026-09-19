import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import mongoSanitize from "express-mongo-sanitize";
import dotenv from "dotenv";
import Project from "./models/Project.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

const CLIENT_URL =
  process.env.CLIENT_URL || "https://sitebase-platform.netlify.app";

// Security headers
app.use(helmet());

// CORS: allow only the frontend origin
app.use(
  cors({
    origin: CLIENT_URL.split(",").map((o) => o.trim()),
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "x-admin-id"],
  }),
);

// Trust proxy when running behind reverse proxy (Render / Nginx)
app.set("trust proxy", 1);

// Body parser with size limit
app.use(express.json({ limit: "50kb" }));

// Prevent NoSQL injection
app.use(mongoSanitize());

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: "Too many requests, please try again later." },
});
app.use("/api", apiLimiter);

const { MONGO_URI } = process.env;
if (!MONGO_URI) {
  console.error("❌ MONGO_URI is missing in .env");
  process.exit(1);
}

const ADMIN_ID = process.env.ADMIN_ID || "150231";

const isAdminRequest = (req) => {
  const provided =
    req.headers["x-admin-id"] || req.body?.adminId || req.query?.adminId;
  return Boolean(provided && String(provided).trim() === ADMIN_ID);
};

mongoose
  .connect(MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err.message);
    process.exit(1);
  });

// ---------- HELPERS ----------

const isValidHttpUrl = (value) => {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
};

const validateProject = ({ title, description, liveUrl, image }) => {
  if (!title || !title.trim()) return "Title is required";
  if (title.trim().length > 120) return "Title must be under 120 characters";
  if (!description || !description.trim()) return "Description is required";
  if (description.trim().length > 2000)
    return "Description must be under 2000 characters";
  if (!liveUrl || !liveUrl.trim()) return "Live URL is required";
  if (!isValidHttpUrl(liveUrl.trim()))
    return "Live URL must be a valid http(s) link";
  if (image && image.trim() && !isValidHttpUrl(image.trim())) {
    return "Preview image must be a valid http(s) link";
  }
  return null;
};

// ---------- LIVE SCREENSHOT PROXY ----------

const BROWSER_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

const screenshotCache = new Map();
const CACHE_MAX = 200;
const inFlight = new Map();

const isPublicHostname = (url) => {
  const host = url.hostname.toLowerCase();
  if (host === "localhost" || host.endsWith(".local")) return false;
  const ipv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
  if (ipv4) {
    const [a, b] = host.split(".").map(Number);
    if (
      a === 127 ||
      a === 10 ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254) ||
      a === 0
    ) {
      return false;
    }
  }
  return true;
};

const fetchWithTimeout = async (url, options) => {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 20000);
  try {
    return await fetch(url, { ...options, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
};

const fetchFromMicrolink = async (url) => {
  const api = `https://api.microlink.io/?url=${encodeURIComponent(url)}&screenshot=true&meta=false&palette=false&video=false`;
  const res = await fetchWithTimeout(api, {
    headers: { "User-Agent": BROWSER_UA },
  });
  const json = await res.json();
  const shotUrl = json?.data?.screenshot?.url;
  if (!shotUrl) throw new Error("microlink returned no screenshot");
  const img = await fetchWithTimeout(shotUrl, {
    headers: { "User-Agent": BROWSER_UA },
  });
  if (!img.ok) throw new Error("microlink image download failed");
  return {
    type: img.headers.get("content-type")?.split(";")[0] || "image/png",
    data: Buffer.from(await img.arrayBuffer()),
  };
};

const fetchFromMshots = async (url) => {
  const api = `https://s0.wp.com/mshots/v1/${encodeURIComponent(url)}?w=640&h=420`;
  const res = await fetchWithTimeout(api, {
    headers: { "User-Agent": BROWSER_UA },
  });
  if (!res.ok) throw new Error("mshots request failed");
  const type = res.headers.get("content-type")?.split(";")[0] || "image/jpeg";
  if (!type.startsWith("image/"))
    throw new Error("mshots did not return an image");
  return {
    type,
    data: Buffer.from(await res.arrayBuffer()),
  };
};

const fetchScreenshot = async (url) => {
  const sources = [fetchFromMicrolink, fetchFromMshots];
  let lastError = "no screenshot service available";
  for (const source of sources) {
    try {
      return await source(url);
    } catch (err) {
      lastError = err.message;
    }
  }
  throw new Error(lastError);
};

const getScreenshot = async (key) => {
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
    if (!["http:", "https:"].includes(target.protocol))
      throw new Error("bad protocol");
    if (!isPublicHostname(target)) {
      return res
        .status(400)
        .json({ message: "URL must point to a public address" });
    }
  } catch {
    return res.status(400).json({ message: "Invalid screenshot URL" });
  }

  const key = target.toString();

  try {
    const shot = await getScreenshot(key);
    if (res.headersSent) return;
    res.set("Content-Type", shot.type);
    res.set("Cache-Control", "public, max-age=86400");
    res.send(shot.data);
  } catch (err) {
    if (res.headersSent) return;
    res.status(502).json({ message: "Could not generate screenshot" });
  }
});

// ---------- ROUTES ----------

// Verify admin ID before allowing edits / deletes
app.post("/api/admin/verify", (req, res) => {
  if (isAdminRequest(req)) {
    return res.status(200).json({ message: "Admin verified" });
  }
  return res.status(401).json({ message: "Invalid admin ID" });
});

// GET all projects
app.get("/api/projects", async (req, res, next) => {
  try {
    const projects = await Project.find().sort({ createdAt: -1 }).lean();
    res.status(200).json(projects);
  } catch (err) {
    next(err);
  }
});

// POST new project
app.post("/api/projects", async (req, res, next) => {
  try {
    const project = {
      title: req.body.title || "",
      description: req.body.description || "",
      liveUrl: req.body.liveUrl || "",
      image: req.body.image || "",
    };
    const validationError = validateProject(project);
    if (validationError) {
      return res.status(400).json({ message: validationError });
    }
    const newProject = await Project.create(project);
    res.status(201).json(newProject);
  } catch (err) {
    next(err);
  }
});

// PUT update project
app.put("/api/projects/:id", async (req, res, next) => {
  if (!isAdminRequest(req)) {
    return res.status(401).json({ message: "Invalid admin ID" });
  }
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: "Invalid project ID" });
    }
    const project = {
      title: req.body.title || "",
      description: req.body.description || "",
      liveUrl: req.body.liveUrl || "",
      image: req.body.image || "",
    };
    const validationError = validateProject(project);
    if (validationError) {
      return res.status(400).json({ message: validationError });
    }
    const updated = await Project.findByIdAndUpdate(req.params.id, project, {
      new: true,
      runValidators: true,
    });
    if (!updated) return res.status(404).json({ message: "Project not found" });
    res.status(200).json(updated);
  } catch (err) {
    next(err);
  }
});

// DELETE project
app.delete("/api/projects/:id", async (req, res, next) => {
  if (!isAdminRequest(req)) {
    return res.status(401).json({ message: "Invalid admin ID" });
  }
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: "Invalid project ID" });
    }
    const deleted = await Project.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ message: "Project not found" });
    res.status(200).json({ message: "Project deleted successfully" });
  } catch (err) {
    next(err);
  }
});

// ---------- FALLBACKS ----------

// 404 handler
app.use((req, res) => {
  res.status(404).json({ message: "Route not found" });
});

// Central error handler
app.use((err, req, res, next) => {
  console.error("❌", err.message);
  if (res.headersSent) {
    return next(err);
  }
  res
    .status(err.status || 500)
    .json({ message: "Something went wrong on the server" });
});

// MongoDB connection listeners (prevent silent crashes on reconnect issues)
mongoose.connection.on("error", (err) =>
  console.error("❌ MongoDB error:", err.message),
);
mongoose.connection.on("disconnected", () =>
  console.warn("⚠️ MongoDB disconnected"),
);

const server = app.listen(PORT, () =>
  console.log(`🚀 Server running on port ${PORT}`),
);

// Global crash guards — log instead of letting the process die
process.on("unhandledRejection", (reason) => {
  console.error(
    "⚠️ Unhandled rejection:",
    reason instanceof Error ? reason.stack : reason,
  );
});
process.on("uncaughtException", (err) => {
  console.error("⚠️ Uncaught exception:", err.stack || err);
});

// Graceful shutdown
const shutdown = () => {
  console.log("Shutting down gracefully...");
  const forceExit = setTimeout(() => process.exit(1), 5000);
  forceExit.unref();
  server.close(() => {
    clearTimeout(forceExit);
    mongoose.connection.close(false, () => process.exit(0));
  });
};
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
