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

// MongoDB connection with improved error handling and SSL options
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  ssl: true,
  tlsAllowInvalidCertificates: true, // This helps with Render's network issues
  serverSelectionTimeoutMS: 5000, // Timeout after 5 seconds
  socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
})
.then(() => {
  console.log("MongoDB connected successfully");
})
.catch(err => {
  console.error("MongoDB connection error:", err);
  // Don't exit the process, let the server run with fallback
});

// Handle connection events
mongoose.connection.on('error', err => {
  console.error('MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
  console.log('MongoDB disconnected');
});

mongoose.connection.on('reconnected', () => {
  console.log('MongoDB reconnected');
});

// Fallback in-memory storage if MongoDB fails
let fallbackUsers = [];
let nextUserId = 1;

// User schema
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  googleId: String,
  remainingCredits: { type: Number, default: 5 } // free generations
});
const User = mongoose.model("User", userSchema);

// Helper functions with fallback
const findUser = async (query) => {
  try {
    if (mongoose.connection.readyState === 1) {
      return await User.findOne(query);
    }
  } catch (err) {
    console.error("Database error, using fallback:", err);
  }
  // Fallback to in-memory storage
  return fallbackUsers.find(u => 
    u.email === query.email || u.googleId === query.googleId
  );
};

const createUser = async (userData) => {
  try {
    if (mongoose.connection.readyState === 1) {
      return await User.create(userData);
    }
  } catch (err) {
    console.error("Database error, using fallback:", err);
  }
  // Fallback to in-memory storage
  const user = { 
    _id: nextUserId++, 
    ...userData, 
    remainingCredits: 5 
  };
  fallbackUsers.push(user);
  return user;
};

const updateUser = async (id, updates) => {
  try {
    if (mongoose.connection.readyState === 1) {
      return await User.findByIdAndUpdate(id, updates, { new: true });
    }
  } catch (err) {
    console.error("Database error, using fallback:", err);
  }
  // Fallback to in-memory storage
  const user = fallbackUsers.find(u => u._id === id);
  if (user) {
    Object.assign(user, updates);
  }
  return user;
};

// JWT helper
const generateToken = (user) => jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });

// Passport Google OAuth
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const user = await findUser({ googleId: profile.id });
    if (user) return done(null, user);
    
    const newUser = await createUser({ 
      googleId: profile.id, 
      email: profile.emails[0].value 
    });
    return done(null, newUser);
  } catch (err) {
    return done(err, null);
  }
}));

passport.serializeUser((user, done) => done(null, user._id));
passport.deserializeUser(async (id, done) => {
  try {
    if (mongoose.connection.readyState === 1) {
      const user = await User.findById(id);
      return done(null, user);
    }
  } catch (err) {
    console.error("Database error:", err);
  }
  // Fallback
  const user = fallbackUsers.find(u => u._id === id);
  done(null, user);
});

// JWT middleware
const authMiddleware = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token provided" });
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    try {
      if (mongoose.connection.readyState === 1) {
        req.user = await User.findById(decoded.id);
      } else {
        // Fallback
        req.user = fallbackUsers.find(u => u._id === decoded.id);
      }
      
      if (!req.user) {
        return res.status(401).json({ error: "User not found" });
      }
      
      next();
    } catch (dbErr) {
      console.error("Database error in auth:", dbErr);
      return res.status(500).json({ error: "Server error" });
    }
  } catch (jwtErr) {
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
    
    // Check if user exists
    const existingUser = await findUser({ email });
    if (existingUser) {
      return res.status(400).json({ error: "User already exists" });
    }
    
    const hashed = await bcrypt.hash(password, 10);
    const user = await createUser({ email, password: hashed });
    const token = generateToken(user);
    
    res.json({ 
      token, 
      email: user.email, 
      remainingCredits: user.remainingCredits 
    });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(400).json({ error: "Signup failed", message: err.message });
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await findUser({ email });
    
    if (!user) return res.status(400).json({ error: "Invalid credentials" });
    
    // Check if user has password (Google users might not have one)
    if (!user.password) {
      return res.status(400).json({ error: "Please use Google login" });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });
    
    const token = generateToken(user);
    res.json({ 
      token, 
      email: user.email, 
      remainingCredits: user.remainingCredits 
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(400).json({ error: "Login failed", message: err.message });
  }
});

// Google OAuth
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get("/auth/google/callback", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    const token = generateToken(req.user);
    // For Chrome extension, we need to handle this differently
    res.send(`
      <html>
        <script>
          // Send token to extension
          window.opener.postMessage({ type: 'OAUTH_SUCCESS', token: '${token}' }, '*');
          window.close();
        </script>
        <body>Authentication successful. You can close this window.</body>
      </html>
    `);
  }
);

// Get user data (protected)
app.get("/user", authMiddleware, async (req, res) => {
  try {
    res.json({ 
      email: req.user.email, 
      remainingCredits: req.user.remainingCredits 
    });
  } catch (err) {
    console.error("User data error:", err);
    res.status(500).json({ error: "Failed to fetch user data" });
  }
});

// Summarize (protected)
app.post("/summarize", authMiddleware, async (req, res) => {
  try {
    const user = req.user;
    
    if (user.remainingCredits <= 0) {
      return res.status(403).json({ error: "No remaining free generations" });
    }

    const { text } = req.body;
    if (!text || text.trim().length < 20) {
      return res.status(400).json({ error: "Insufficient content" });
    }

    const payload = {
      contents: [{ 
        parts: [{ 
          text: `Create a engaging social media post based on this content: ${text.substring(0, 3000)}` 
        }] 
      }],
      generationConfig: { 
        temperature: 0.9, 
        maxOutputTokens: 280, 
        topP: 0.95 
      }
    };

    const response = await fetch(GEMINI_API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    
    if (!response.ok) {
      console.error("Gemini API failed:", response.status);
      return res.status(response.status).json({ error: "Gemini API failed" });
    }

    const result = await response.json();
    const generatedText = result?.candidates?.[0]?.content?.parts?.[0]?.text?.trim();
    
    if (!generatedText) {
      return res.status(500).json({ error: "Empty Gemini response" });
    }

    // Update user credits
    user.remainingCredits -= 1;
    await updateUser(user._id, { remainingCredits: user.remainingCredits });

    res.json({ 
      generated_text: generatedText, 
      remainingCredits: user.remainingCredits 
    });

  } catch (err) {
    console.error("Summarize error:", err);
    res.status(500).json({ error: "Summarize failed", message: err.message });
  }
});

// Health check
app.get("/health", (req, res) => {
  const dbStatus = mongoose.connection.readyState === 1 ? "connected" : "disconnected";
  res.json({ 
    status: "Server running", 
    database: dbStatus,
    geminiConfigured: !!GEMINI_API_KEY, 
    model: GEMINI_MODEL 
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log("Endpoints: POST /signup, POST /login, GET /auth/google, POST /summarize, GET /health, GET /user");
});