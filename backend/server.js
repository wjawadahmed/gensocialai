// server.js - FIREBASE VERSION
import express from "express";
import fetch from "node-fetch";
import cors from "cors";
import dotenv from "dotenv";
import admin from "firebase-admin";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();
const app = express();

// Get __dirname equivalent in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Initialize Firebase Admin
const serviceAccount = {
  type: "service_account",
  project_id: process.env.FIREBASE_PROJECT_ID,
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: "https://accounts.google.com/o/oauth2/auth",
  token_uri: "https://oauth2.googleapis.com/token",
  auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
  client_x509_cert_url: process.env.FIREBASE_CLIENT_CERT_URL
};

try {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
  console.log("Firebase Admin initialized successfully");
} catch (error) {
  console.error("Firebase initialization error:", error);
}

// Middleware
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

// SQLite Database setup (for storing user credits)
let db;
async function initializeDatabase() {
  try {
    db = await open({
      filename: path.join(__dirname, 'database.sqlite'),
      driver: sqlite3.Database
    });

    // Create users table for credits
    await db.exec(`
      CREATE TABLE IF NOT EXISTS user_credits (
        uid TEXT PRIMARY KEY,
        email TEXT UNIQUE,
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

// Database helper functions for credits
const getUserCredits = async (uid) => {
  try {
    return await db.get('SELECT * FROM user_credits WHERE uid = ?', uid);
  } catch (error) {
    console.error("Database query error:", error);
    return null;
  }
};

const createUserCredits = async (uid, email) => {
  try {
    const result = await db.run(
      'INSERT INTO user_credits (uid, email, remainingCredits) VALUES (?, ?, ?)',
      [uid, email, 5]
    );
    
    return { uid, email, remainingCredits: 5 };
  } catch (error) {
    console.error("Database insert error:", error);
    throw error;
  }
};

const updateUserCredits = async (uid, remainingCredits) => {
  try {
    await db.run(
      'UPDATE user_credits SET remainingCredits = ? WHERE uid = ?',
      [remainingCredits, uid]
    );
    
    return await getUserCredits(uid);
  } catch (error) {
    console.error("Database update error:", error);
    throw error;
  }
};

// Firebase Auth middleware
const firebaseAuthMiddleware = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: "No token provided" });
  }
  
  const idToken = authHeader.split('Bearer ')[1];
  
  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.user = decodedToken;
    
    // Get user credits from our database
    const userCredits = await getUserCredits(decodedToken.uid);
    req.user.remainingCredits = userCredits ? userCredits.remainingCredits : 5;
    
    next();
  } catch (error) {
    console.error("Firebase auth error:", error);
    return res.status(401).json({ error: "Invalid token" });
  }
};

// Gemini API config
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_MODEL = "gemini-1.5-flash-8b-latest";
const GEMINI_API_URL = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${GEMINI_API_KEY}`;

// Routes

// Create custom token endpoint (for testing or special cases)
app.post("/create-custom-token", async (req, res) => {
  try {
    const { uid } = req.body;
    
    if (!uid) {
      return res.status(400).json({ error: "UID is required" });
    }
    
    const customToken = await admin.auth().createCustomToken(uid);
    res.json({ customToken });
  } catch (error) {
    console.error("Create custom token error:", error);
    res.status(500).json({ error: "Failed to create custom token" });
  }
});

// Get user data (protected)
app.get("/user", firebaseAuthMiddleware, async (req, res) => {
  try {
    res.json({ 
      email: req.user.email, 
      remainingCredits: req.user.remainingCredits,
      uid: req.user.uid
    });
  } catch (err) {
    console.error("User data error:", err);
    res.status(500).json({ error: "Failed to fetch user data" });
  }
});

// Initialize user credits (called after Firebase auth)
app.post("/init-user", firebaseAuthMiddleware, async (req, res) => {
  try {
    const { uid, email } = req.user;
    
    let userCredits = await getUserCredits(uid);
    
    if (!userCredits) {
      userCredits = await createUserCredits(uid, email);
    }
    
    res.json({ 
      email: userCredits.email, 
      remainingCredits: userCredits.remainingCredits 
    });
  } catch (err) {
    console.error("Init user error:", err);
    res.status(500).json({ error: "Failed to initialize user" });
  }
});

// Summarize (protected)
app.post("/summarize", firebaseAuthMiddleware, async (req, res) => {
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
      const newCredits = user.remainingCredits - 1;
      await updateUserCredits(user.uid, newCredits);
      
      return res.json({ 
        generated_text: generatedText, 
        remainingCredits: newCredits 
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
    const newCredits = user.remainingCredits - 1;
    await updateUserCredits(user.uid, newCredits);

    res.json({ 
      generated_text: generatedText, 
      remainingCredits: newCredits 
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
      firebase: "initialized",
      geminiConfigured: !!GEMINI_API_KEY, 
      model: GEMINI_MODEL 
    });
  } catch (error) {
    res.json({ 
      status: "Server running", 
      database: "disconnected",
      firebase: "initialized", 
      geminiConfigured: !!GEMINI_API_KEY, 
      model: GEMINI_MODEL,
      warning: "Database not available, using fallback"
    });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log("Endpoints: GET /user, POST /init-user, POST /summarize, GET /health");
});