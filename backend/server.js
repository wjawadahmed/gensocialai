// server.js - FIXED VERSION
import express from "express";
import fetch from "node-fetch";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();
const app = express();

// Get __dirname equivalent in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Middleware
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

// SQLite Database setup
let db;
async function initializeDatabase() {
  try {
    db = await open({
      filename: path.join(__dirname, 'database.sqlite'),
      driver: sqlite3.Database
    });

    // Create users table
    await db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password TEXT,
        googleId TEXT UNIQUE,
        remainingCredits INTEGER DEFAULT 5,
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log("SQLite database initialized successfully");
  } catch (error) {
    console.error("Database initialization error:", error);
  }
}

// Initialize database
initializeDatabase();

// Database helper functions
const findUser = async (query) => {
  try {
    if (query.email) {
      return await db.get('SELECT * FROM users WHERE email = ?', query.email);
    } else if (query.googleId) {
      return await db.get('SELECT * FROM users WHERE googleId = ?', query.googleId);
    } else if (query.id) {
      return await db.get('SELECT * FROM users WHERE id = ?', query.id);
    }
  } catch (error) {
    console.error("Database query error:", error);
    return null;
  }
};

const createUser = async (userData) => {
  try {
    const { email, password, googleId, remainingCredits = 5 } = userData;
    const result = await db.run(
      'INSERT INTO users (email, password, googleId, remainingCredits) VALUES (?, ?, ?, ?)',
      [email, password, googleId, remainingCredits]
    );
    
    // Return user data WITHOUT the password (FIXED)
    return { 
      id: result.lastID, 
      email, 
      googleId, 
      remainingCredits 
    };
  } catch (error) {
    console.error("Database insert error:", error);
    throw error;
  }
};

const updateUser = async (id, updates) => {
  try {
    const fields = [];
    const values = [];
    
    for (const [key, value] of Object.entries(updates)) {
      fields.push(`${key} = ?`);
      values.push(value);
    }
    
    values.push(id);
    
    await db.run(
      `UPDATE users SET ${fields.join(', ')} WHERE id = ?`,
      values
    );
    
    return await findUser({ id });
  } catch (error) {
    console.error("Database update error:", error);
    throw error;
  }
};

// JWT helper
const generateToken = (user) => jwt.sign({ id: user.id }, process.env.JWT_SECRET || 'fallback-secret', { expiresIn: "7d" });

// JWT middleware
const authMiddleware = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token provided" });
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret');
    const user = await findUser({ id: decoded.id });
    
    if (!user) {
      return res.status(401).json({ error: "User not found" });
    }
    
    req.user = user;
    next();
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
    
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }
    
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
    
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }
    
    const user = await findUser({ email });
    
    if (!user) return res.status(400).json({ error: "Invalid credentials" });
    
    // Check if user has password
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

// Simple Google auth endpoint (for extension compatibility)
app.post("/auth/google", async (req, res) => {
  try {
    const { email, googleId } = req.body;
    
    if (!email || !googleId) {
      return res.status(400).json({ error: "Email and Google ID are required" });
    }
    
    let user = await findUser({ email });
    
    if (!user) {
      // Create new user
      user = await createUser({ email, googleId });
    } else if (!user.googleId) {
      // Update existing user with Google ID
      await updateUser(user.id, { googleId });
      user.googleId = googleId;
    }
    
    const token = generateToken(user);
    res.json({ 
      token, 
      email: user.email, 
      remainingCredits: user.remainingCredits 
    });
  } catch (err) {
    console.error("Google auth error:", err);
    res.status(400).json({ error: "Google authentication failed" });
  }
});

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

    // Check if Gemini API key is configured
    if (!GEMINI_API_KEY) {
      // Mock response for testing
      const mockResponses = [
        "🚀 Check out this amazing content! So excited to share this with everyone. #inspiration #motivation",
        "✨ Just discovered something incredible! This is definitely worth your time. #discovery #learning",
        "🌟 Amazing insights from this article! Definitely worth reading and sharing. #knowledge #growth"
      ];
      
      const generatedText = mockResponses[Math.floor(Math.random() * mockResponses.length)];
      
      // Update user credits
      await updateUser(user.id, { remainingCredits: user.remainingCredits - 1 });
      
      return res.json({ 
        generated_text: generatedText, 
        remainingCredits: user.remainingCredits - 1 
      });
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
    await updateUser(user.id, { remainingCredits: user.remainingCredits - 1 });

    res.json({ 
      generated_text: generatedText, 
      remainingCredits: user.remainingCredits - 1 
    });

  } catch (err) {
    console.error("Summarize error:", err);
    res.status(500).json({ error: "Summarize failed", message: err.message });
  }
});

// Health check
app.get("/health", async (req, res) => {
  try {
    // Test database connection
    await db.get('SELECT 1 as test');
    res.json({ 
      status: "Server running", 
      database: "connected",
      geminiConfigured: !!GEMINI_API_KEY, 
      model: GEMINI_MODEL 
    });
  } catch (error) {
    res.json({ 
      status: "Server running", 
      database: "disconnected",
      geminiConfigured: !!GEMINI_API_KEY, 
      model: GEMINI_MODEL,
      warning: "Database not available, using fallback"
    });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log("Endpoints: POST /signup, POST /login, POST /auth/google, POST /summarize, GET /health, GET /user");
});