// server.js
import express from "express";
import fetch from "node-fetch";
import cors from "cors";
import dotenv from "dotenv";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import passport from "passport";
import session from "express-session";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";

dotenv.config();
const app = express();

// Middleware
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });

// User schema
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  googleId: String,
  remainingCredits: { type: Number, default: 5 } // free generations
});
const User = mongoose.model("User", userSchema);

// JWT helper
const generateToken = (user) => jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });

// Passport Google OAuth
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const user = await User.findOne({ googleId: profile.id });
    if (user) return done(null, user);
    const newUser = await User.create({ googleId: profile.id, email: profile.emails[0].value });
    return done(null, newUser);
  } catch (err) {
    return done(err, null);
  }
}));

passport.serializeUser((user, done) => done(null, user._id));
passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id);
  done(null, user);
});

// JWT middleware
const authMiddleware = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token provided" });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.id);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
};

// Gemini API config
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_MODEL = "gemini-1.5-flash-8b-latest";
const GEMINI_API_URL = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${GEMINI_API_KEY}`;

// Routes

// Signup
app.post("/signup", async (req, res) => {
  try {
    const { email, password } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ email, password: hashed });
    const token = generateToken(user);
    res.json({ token, email: user.email, remainingCredits: user.remainingCredits });
  } catch (err) {
    res.status(400).json({ error: "Signup failed", message: err.message });
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "Invalid credentials" });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });
    const token = generateToken(user);
    res.json({ token, email: user.email, remainingCredits: user.remainingCredits });
  } catch (err) {
    res.status(400).json({ error: "Login failed", message: err.message });
  }
});

// Google OAuth
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get("/auth/google/callback", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    const token = generateToken(req.user);
    res.redirect(`${process.env.FRONTEND_URL}/?token=${token}`); // send JWT to frontend
  }
);

// Summarize (protected)
app.post("/summarize", authMiddleware, async (req, res) => {
  try {
    const user = req.user;
    if (user.remainingCredits <= 0) return res.status(403).json({ error: "No remaining free generations" });

    const { text } = req.body;
    if (!text || text.trim().length < 20) return res.status(400).json({ error: "Insufficient content" });

    const payload = {
      contents: [{ parts: [{ text: `Create a social media post based on: ${text.substring(0, 3000)}` }] }],
      generationConfig: { temperature: 0.9, maxOutputTokens: 280, topP: 0.95 }
    };

    const response = await fetch(GEMINI_API_URL, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    if (!response.ok) return res.status(response.status).json({ error: "Gemini API failed" });

    const result = await response.json();
    const generatedText = result?.candidates?.[0]?.content?.parts?.[0]?.text?.trim();
    if (!generatedText) return res.status(500).json({ error: "Empty Gemini response" });

    user.remainingCredits -= 1;
    await user.save();

    res.json({ generated_text: generatedText, remainingCredits: user.remainingCredits });

  } catch (err) {
    res.status(500).json({ error: "Summarize failed", message: err.message });
  }
});

// Health check
app.get("/health", (req, res) => {
  res.json({ status: "Server running", geminiConfigured: !!GEMINI_API_KEY, model: GEMINI_MODEL });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log("Endpoints: POST /signup, POST /login, GET /auth/google, POST /summarize, GET /health");
});
