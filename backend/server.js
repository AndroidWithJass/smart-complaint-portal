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
    origin: true, // local dev ke liye sab allow; chaho to specific origin set kar sakte ho
  })
);
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" })); // limit payload (photoData badi na ho)

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

// ---- Admin auth helper ----
function authAdmin(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ message: "Missing token" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
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

// Health check
app.get("/", (req, res) => {
  res.json({ status: "ok", message: "Smart Complaint Portal API (file-based)" });
});

// Admin login -> returns JWT
app.post("/api/admin/login", (req, res) => {
  const { password } = req.body;
  if (!password || password !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ message: "Invalid admin password" });
  }
  const token = jwt.sign({ role: "admin" }, process.env.JWT_SECRET, {
    expiresIn: "8h",
  });
  res.json({ token });
});

// Get complaints
app.get("/api/complaints", (req, res) => {
  const sorted = complaints.slice().sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json(sorted);
});

// Create complaint
app.post(
  "/api/complaints",
  createLimiter,
  [
    body("issueType")
      .isIn(["Road", "Street Light", "Water", "Garbage", "Other"])
      .withMessage("Invalid issue type"),
    body("title").isLength({ min: 5, max: 120 }).withMessage("Title length invalid"),
    body("description").isLength({ min: 10, max: 1000 }).withMessage("Description length invalid"),
    body("location").isLength({ min: 3, max: 200 }).withMessage("Location length invalid"),
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

// Upvote complaint
app.post("/api/complaints/:id/upvote", upvoteLimiter, (req, res) => {
  try {
    const id = req.params.id;
    const ip = req.ip;

    const idx = complaints.findIndex((c) => c._id === id);
    if (idx === -1) return res.status(404).json({ message: "Complaint not found" });

    const complaint = complaints[idx];

    if (!complaint.upvoters.includes(ip)) {
      complaint.upvoters.push(ip);
      complaint.upvotes = (complaint.upvotes || 0) + 1;
      complaint.updatedAt = new Date().toISOString();
      saveComplaints();
    }

    res.json(complaint);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to upvote complaint" });
  }
});

// Change status (Admin only)
app.patch(
  "/api/complaints/:id/status",
  authAdmin,
  [body("status").isIn(["Pending", "In Progress", "Resolved"]).withMessage("Invalid status")],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: "Validation failed", errors: errors.array() });
    }

    try {
      const id = req.params.id;
      const { status } = req.body;

      const idx = complaints.findIndex((c) => c._id === id);
      if (idx === -1) return res.status(404).json({ message: "Complaint not found" });

      complaints[idx].status = status;
      complaints[idx].updatedAt = new Date().toISOString();
      saveComplaints();

      res.json(complaints[idx]);
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "Failed to update status" });
    }
  }
);

// Global error handler
app.use((err, req, res, next) => {
  console.error("Unexpected error:", err);
  res.status(500).json({ message: "Internal server error" });
});

const port = process.env.PORT || 5000;
app.listen(port, () => {
  console.log(`API listening on port ${port}`);
});
