require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");
const fs = require("fs");
const path = require("path");

const app = express();

// 👇 Admin settings (yahi password aur secret hai)
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123";
const JWT_SECRET = process.env.JWT_SECRET || "supersecret123";

// ---- File-based "database" ----
const DATA_FILE = path.join(__dirname, "data.json");
let complaints = [];

// Load on start
function loadComplaints() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const raw = fs.readFileSync(DATA_FILE, "utf8");
      complaints = JSON.parse(raw || "[]");
    } else {
      complaints = [];
    }
  } catch (err) {
    console.error("Error loading complaints:", err);
    complaints = [];
  }
}

function saveComplaints() {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(complaints, null, 2), "utf8");
  } catch (err) {
    console.error("Error saving complaints:", err);
  }
}

loadComplaints();

// ---- Security middlewares ----
app.use(helmet());
app.use(
  cors({
    origin: true,
  })
);

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// Rate limiters
const createLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { message: "Too many complaints created from this IP, please try again later." },
});

const upvoteLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { message: "Too many upvotes from this IP, please slow down." },
});

// ---- Admin auth middleware ----
function authAdmin(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;

  if (!token) {
    return res.status(401).json({ message: "Missing token" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (!decoded || decoded.role !== "admin") {
      return res.status(403).json({ message: "Invalid token" });
    }

    req.admin = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
}

// ---- Routes ----

// API health check
app.get("/", (req, res) => {
  res.json({ status: "ok", message: "Smart Complaint Portal API running ✅" });
});

// ✅ Admin Login
app.post("/api/admin/login", (req, res) => {
  const { password } = req.body;

  if (!password || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ message: "Invalid admin password" });
  }

  const token = jwt.sign({ role: "admin" }, JWT_SECRET, {
    expiresIn: "8h",
  });

  res.json({ token });
});

// ✅ Get all complaints
app.get("/api/complaints", (req, res) => {
  const sorted = complaints.slice().sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json(sorted);
});

// ✅ Create complaint
app.post(
  "/api/complaints",
  createLimiter,
  [
    body("issueType").isIn(["Road", "Street Light", "Water", "Garbage", "Other"]),
    body("title").isLength({ min: 5, max: 120 }),
    body("description").isLength({ min: 10, max: 1000 }),
    body("location").isLength({ min: 3, max: 200 }),
    body("name").optional().isLength({ max: 80 }),
    body("photoData").optional().isLength({ max: 5000000 }),
  ],
  (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({ message: "Validation failed", errors: errors.array() });
    }

    try {
      const { name, issueType, title, description, location, photoData } = req.body;

      const complaint = {
        _id: "c_" + Date.now().toString(36) + Math.random().toString(36).slice(2, 8),
        name: name || "",
        issueType,
        title,
        description,
        location,
        status: "Pending",
        upvotes: 0,
        photoData: photoData || null,
        upvoters: [],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };

      complaints.push(complaint);
      saveComplaints();

      res.status(201).json(complaint);
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "Failed to create complaint" });
    }
  }
);

// ✅ Upvote complaint
app.post("/api/complaints/:id/upvote", upvoteLimiter, (req, res) => {
  try {
    const id = req.params.id;
    const ip = req.ip;

    const complaint = complaints.find((c) => c._id === id);
    if (!complaint) return res.status(404).json({ message: "Complaint not found" });

    if (!complaint.upvoters.includes(ip)) {
      complaint.upvoters.push(ip);
      complaint.upvotes++;
      complaint.updatedAt = new Date().toISOString();
      saveComplaints();
    }

    res.json(complaint);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to upvote complaint" });
  }
});

// ✅ Update status (Admin only)
app.patch(
  "/api/complaints/:id/status",
  authAdmin,
  [body("status").isIn(["Pending", "In Progress", "Resolved"])],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: "Validation failed", errors: errors.array() });
    }

    const id = req.params.id;
    const { status } = req.body;

    const complaint = complaints.find((c) => c._id === id);
    if (!complaint) return res.status(404).json({ message: "Complaint not found" });

    complaint.status = status;
    complaint.updatedAt = new Date().toISOString();
    saveComplaints();

    res.json(complaint);
  }
);

// Global error handler
app.use((err, req, res, next) => {
  console.error("Unexpected error:", err);
  res.status(500).json({ message: "Internal server error" });
});

// ✅ Server start
const port = process.env.PORT || 5000;
app.listen(port, () => {
  console.log(`✅ API listening on port ${port}`);
  console.log(`🔐 Admin password: ${ADMIN_PASSWORD}`);
});
