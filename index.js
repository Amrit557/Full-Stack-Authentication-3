// index.js

const express = require("express");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const cors = require("cors");

const app = express();
app.use(bodyParser.json());
app.use(cors());

const PORT = 3000;
const SECRET_KEY = "mysecretkey";

// Hardcoded users for demo (username, password, role, email, fullName)
const users = [
  { username: "admin", password: "admin123", role: "Admin", email: "admin@example.com", fullName: "Alice Admin" },
  { username: "moderator", password: "mod123", role: "Moderator", email: "moderator@example.com", fullName: "Mark Moderator" },
  { username: "user", password: "user123", role: "User", email: "user@example.com", fullName: "Uma User" }
];

// ----------------- LOGIN ROUTE -----------------
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  const user = users.find(
    (u) => u.username === username && u.password === password
  );

  if (!user) return res.status(401).json({ message: "Invalid credentials" });

  // Generate JWT including role
  const token = jwt.sign(
    { username: user.username, role: user.role },
    SECRET_KEY,
    { expiresIn: "1h" }
  );

  // Return token + user details
  res.json({
    token,
    user: {
      username: user.username,
      role: user.role,
      email: user.email,
      fullName: user.fullName
    }
  });
});

// ----------------- JWT VERIFICATION MIDDLEWARE -----------------
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Bearer <token>

  if (!token) return res.status(401).json({ message: "Token missing" });

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = decoded; // store decoded payload
    next();
  });
}

// ----------------- ROLE-BASED AUTHORIZATION MIDDLEWARE -----------------
function authorizeRoles(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ message: "Unauthorized" });
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ message: "Access denied: Insufficient role" });
    }
    next();
  };
}

// ----------------- PROTECTED ROUTES -----------------

// Admin dashboard
app.get("/admin-dashboard", verifyToken, authorizeRoles("Admin"), (req, res) => {
  const userDetails = users.find(u => u.username === req.user.username);
  res.json({
    message: `Welcome Admin ${req.user.username}!`,
    user: {
      username: userDetails.username,
      role: userDetails.role,
      email: userDetails.email,
      fullName: userDetails.fullName
    }
  });
});

// Moderator panel
app.get("/moderator-panel", verifyToken, authorizeRoles("Moderator"), (req, res) => {
  const userDetails = users.find(u => u.username === req.user.username);
  res.json({
    message: `Welcome Moderator ${req.user.username}!`,
    user: {
      username: userDetails.username,
      role: userDetails.role,
      email: userDetails.email,
      fullName: userDetails.fullName
    }
  });
});

// User profile (all roles)
app.get("/user-profile", verifyToken, authorizeRoles("User", "Admin", "Moderator"), (req, res) => {
  const userDetails = users.find(u => u.username === req.user.username);
  res.json({
    message: `Welcome ${req.user.username}! Your role is ${req.user.role}`,
    user: {
      username: userDetails.username,
      role: userDetails.role,
      email: userDetails.email,
      fullName: userDetails.fullName
    }
  });
});

// Public route
app.get("/", (req, res) => {
  res.send("Public route, no token required");
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
