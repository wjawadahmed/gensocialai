import express from "express";
import fetch from "node-fetch";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_MODEL = "gemini-1.5-flash-8b-latest"; // Free / lightweight model
const GEMINI_API_URL = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${GEMINI_API_KEY}`;


app.post("/summarize", async (req, res) => {
  try {
    const { text } = req.body;

    if (!text || text.trim().length < 20) {
      return res.status(400).json({ 
        error: "Insufficient content",
        message: "Please provide content with at least 20 characters" 
      });
    }
    if (!GEMINI_API_KEY) {
      return res.status(500).json({ 
        error: "Server configuration error",
        message: "Gemini API key not configured" 
      });
    }

    // Correct payload structure for Gemini API
    const payload = {
      contents: [
        {
          parts: [
            {
              text: `Create a compelling, engaging social media post based on the following content. 
              Include relevant hashtags and make it conversational and authentic:
              
              ${text.substring(0, 3000)}`
            }
          ]
        }
      ],
      generationConfig: {
        temperature: 0.9,
        maxOutputTokens: 280,
        topP: 0.95
      }
    };

    const response = await fetch(GEMINI_API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      const errorData = await response.json();
      console.error("Gemini API error:", errorData);
      return res.status(response.status).json({
        error: "Gemini API failed",
        details: errorData
      });
    }

    const result = await response.json();
    
    // Extract the generated text from the response
    let generatedText = "";
    if (result.candidates && result.candidates[0] && result.candidates[0].content) {
      generatedText = result.candidates[0].content.parts[0].text.trim();
    }

    if (generatedText && generatedText.length > 10) {
      console.log("✅ Gemini success:", generatedText);
      return res.json({ 
        generated_text: generatedText, 
        source: "gemini",
        length: generatedText.length
      });
    } else {
      throw new Error("Empty or invalid response from Gemini API");
    }

  } catch (error) {
    console.error("❌ Error in /summarize:", error.message);
    res.status(500).json({ 
      error: "Internal server error",
      message: error.message
    });
  }
});

app.get("/health", (req, res) => {
  res.json({ 
    status: "✅ Server is running", 
    timestamp: new Date().toISOString(),
    gemini_configured: !!GEMINI_API_KEY,
    model: GEMINI_MODEL
  });
});

// Test endpoint to verify the API works
app.post("/test", async (req, res) => {
  try {
    const testContent = "Mars is the fourth planet from the Sun. The surface of Mars is orange-red because it is covered in iron oxide dust, giving it the nickname 'the Red Planet'.";
    
    const payload = {
      contents: [
        {
          parts: [
            {
              text: `Create a social media post about: ${testContent}`
            }
          ]
        }
      ],
      generationConfig: {
        temperature: 0.8,
        maxOutputTokens: 150
      }
    };

    const response = await fetch(GEMINI_API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      const errorData = await response.json();
      return res.status(500).json({
        error: "Test failed",
        details: errorData
      });
    }

    const result = await response.json();
    const generatedText = result.candidates[0].content.parts[0].text.trim();
    
    res.json({
      test: "success",
      generated_text: generatedText,
      model: GEMINI_MODEL
    });

  } catch (error) {
    res.status(500).json({
      error: "Test failed",
      message: error.message
    });
  }
});

// List available models (for debugging)
app.get("/models", async (req, res) => {
  if (!GEMINI_API_KEY) {
    return res.status(500).json({ 
      error: "API key not configured"
    });
  }
  
  try {
    const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models?key=${GEMINI_API_KEY}`);
    
    if (response.ok) {
      const models = await response.json();
      res.json({ 
        models: models.models || []
      });
    } else {
      res.status(500).json({ 
        error: "Failed to fetch models",
        status: response.status
      });
    }
  } catch (error) {
    res.status(500).json({ 
      error: "Failed to fetch models",
      message: error.message
    });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
  console.log("🎯 Endpoints: POST /summarize, POST /test, GET /models");
  console.log(`🔑 Gemini API: ${GEMINI_API_KEY ? "Configured" : "Not configured"}`);
  console.log(`🤖 Model: ${GEMINI_MODEL}`);
});