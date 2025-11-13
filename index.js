import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

dotenv.config();


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

// ---------- Auth Routes ----------

/**
 * POST /auth/signup
 * body: {fullname, email, password }
 * Returns: { user, token }
 */
app.post("/auth/signup", async (req, res) => {
  try {
    const { fullname, email, password } = req.body || {};
    if (!fullname || !email || !password) {
      return res.status(400).json({ message: "fullname, email and password are required" });
    }
    if (users.has(email)) {
      return res.status(409).json({ message: "Email already registered" });
    }

    
    const id = `u_${Math.random().toString(36).slice(2, 10)}`;
    const passwordHash = await bcrypt.hash(password, 10);

    const user = { id, fullname, email, passwordHash };
    users.set(email, user);

    const token = signToken({ id, email });
    return res.status(201).json({
      user: { id, fullname, email },
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

    const token = signToken({ id: user.id, email: user.email});
    return res.json({ user: { id: user.id,fullname: user.fullname, email: user.email}, token });
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
    { fullname: "user1", email: "user@1", password: "password123" },
    { fullname: "user2", email: "user@2", password: "password123" },
  ];
  for (const u of seed) {
    const hash = await bcrypt.hash(u.password, 10);
    users.set(u.email, { id: `seed_${u.email}`, email: u.email, passwordHash: hash });
  }
}