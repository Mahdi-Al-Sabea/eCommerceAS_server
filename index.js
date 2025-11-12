import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

dotenv.config();


const ROLES = ["weather", "products"];

const app = express();
app.use(helmet());
app.use(cors({ origin: "*"}));
app.use(express.json());
app.use(morgan("dev"));

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "change_me";
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "1d";


const users = new Map();

// Seed a couple of users
await seedUsers();

// ---------- Helpers ----------

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ message: "Missing token" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { id, email, roles }
    return next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

function requireRoles(...needOneOf) {
  return (req, res, next) => {
    const userRoles = req.user?.roles || [];
    const ok = needOneOf.some((r) => userRoles.includes(r));
    if (!ok) return res.status(403).json({ message: "Forbidden: insufficient role" });
    next();
  };
}

function sanitizeRoles(inputRoles = []) {
  if (!Array.isArray(inputRoles)) return [];
  const uniq = Array.from(new Set(inputRoles));
  return uniq.filter((r) => ROLES.includes(r));
}

// ---------- Auth Routes ----------

/**
 * POST /auth/signup
 * body: { email, password, roles?: ["weather","products"] }
 * Returns: { user, token }
 */
app.post("/auth/signup", async (req, res) => {
  try {
    const { email, password, roles = [] } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ message: "email and password are required" });
    }
    if (users.has(email)) {
      return res.status(409).json({ message: "Email already registered" });
    }

    const rolesClean = sanitizeRoles(roles);
    const id = `u_${Math.random().toString(36).slice(2, 10)}`;
    const passwordHash = await bcrypt.hash(password, 10);

    const user = { id, email, passwordHash, roles: rolesClean };
    users.set(email, user);

    const token = signToken({ id, email, roles: user.roles });
    return res.status(201).json({
      user: { id, email, roles: user.roles },
      token
    });
  } catch (e) {
    return res.status(500).json({ message: "Server error", error: e.message });
  }
});

/**
 * POST /auth/login
 * body: { email, password }
 * Returns: { user, token }
 */
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const user = users.get(email);
    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    const token = signToken({ id: user.id, email: user.email, roles: user.roles });
    return res.json({ user: { id: user.id, email: user.email, roles: user.roles }, token });
  } catch (e) {
    return res.status(500).json({ message: "Server error", error: e.message });
  }
});



//----- Start ----------

app.listen(PORT, () => {
  console.log(`API listening on http://localhost:${PORT}`);
});

// ---------- Seed users for quick testing ----------
async function seedUsers() {
  const seed = [
    { email: "weather@demo.io", password: "password123", roles: ["weather"] },
    { email: "products@demo.io", password: "password123", roles: ["products"] },
    { email: "both@demo.io",    password: "password123", roles: ["weather","products"] }
  ];
  for (const u of seed) {
    const hash = await bcrypt.hash(u.password, 10);
    users.set(u.email, { id: `seed_${u.email}`, email: u.email, passwordHash: hash, roles: u.roles });
  }
}