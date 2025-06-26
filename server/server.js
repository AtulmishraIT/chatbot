const express = require("express")
const mongoose = require("mongoose")
const cors = require("cors")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const helmet = require("helmet")
const rateLimit = require("express-rate-limit")
const validator = require("validator")
const { generateText } = require("ai")
const { google } = require("@ai-sdk/google")
require("dotenv").config()

const app = express()

// Initialize Gemini AI
let geminiModel = null
if (process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== "your-gemini-api-key") {
  const { createGoogleGenerativeAI } = require("@ai-sdk/google")

  const googleAI = createGoogleGenerativeAI({
    apiKey: process.env.GEMINI_API_KEY,
  })

  geminiModel = googleAI("gemini-1.5-flash")
}


// Security middleware
app.use(helmet())
app.use(
  cors({
    origin: process.env.CLIENT_URL || "http://localhost:5173",
    credentials: true,
  }),
)
app.use(express.json({ limit: "10mb" }))

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: "Too many requests from this IP, please try again later.",
})
app.use(limiter)

// Chat rate limiting (more restrictive)
const chatLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 10, // limit each IP to 10 chat requests per minute
  message: "Too many chat requests, please slow down.",
})

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || "mongodb://localhost:27017/chatbot", {
  
})

const db = mongoose.connection
db.on("error", console.error.bind(console, "MongoDB connection error:"))
db.once("open", () => {
  console.log("Connected to MongoDB")
})

// User Schema
const userSchema = new mongoose.Schema(
  {
    fullName: {
      type: String,
      required: [true, "Full name is required"],
      trim: true,
      minlength: [2, "Full name must be at least 2 characters"],
      maxlength: [50, "Full name cannot exceed 50 characters"],
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
      lowercase: true,
      validate: [validator.isEmail, "Please provide a valid email"],
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      minlength: [6, "Password must be at least 6 characters"],
    },
    avatar: {
      type: String,
      default: null,
    },
    isActive: {
      type: Boolean,
      default: true,
    },
    lastLogin: {
      type: Date,
      default: Date.now,
    },
  },
  {
    timestamps: true,
  },
)

// Chat Session Schema
const chatSessionSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    title: {
      type: String,
      required: true,
      trim: true,
      maxlength: [100, "Title cannot exceed 100 characters"],
    },
    isActive: {
      type: Boolean,
      default: true,
    },
  },
  {
    timestamps: true,
  },
)

// Message Schema
const messageSchema = new mongoose.Schema(
  {
    sessionId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "ChatSession",
      required: true,
    },
    role: {
      type: String,
      enum: ["user", "assistant"],
      required: true,
    },
    content: {
      type: String,
      required: true,
      maxlength: [5000, "Message content cannot exceed 5000 characters"],
    },
    tokens: {
      type: Number,
      default: 0,
    },
  },
  {
    timestamps: true,
  },
)

const User = mongoose.model("User", userSchema)
const ChatSession = mongoose.model("ChatSession", chatSessionSchema)
const Message = mongoose.model("Message", messageSchema)

// Mock AI responses for development
const getMockAIResponse = (prompt) => {
  const responses = [
    "That's a great question! Let me help you with that. Based on what you've asked, here are some key points to consider...",
    "I understand what you're looking for. Here's my take on this topic and some suggestions that might be helpful...",
    "Thanks for asking! This is an interesting topic. Let me break it down for you in a way that's easy to understand...",
    "I'd be happy to help you with that! Here's what I think about your question and some practical advice...",
    "That's a thoughtful question. Based on current knowledge and best practices, here's what I would recommend...",
    "Great question! Let me provide you with a comprehensive answer that covers the main aspects of what you're asking about...",
    "I can definitely help you with that. Here's a detailed explanation along with some practical examples and tips...",
    "Thanks for reaching out! This is something many people wonder about. Let me give you a clear and helpful response...",
  ]

  // Simple keyword-based responses
  const lowerPrompt = prompt.toLowerCase()

  if (lowerPrompt.includes("hello") || lowerPrompt.includes("hi")) {
    return "Hello! I'm your AI assistant powered by Google Gemini. How can I help you today? Feel free to ask me anything!"
  }

  if (lowerPrompt.includes("how are you")) {
    return "I'm doing great, thank you for asking! I'm here and ready to help you with any questions or tasks you have."
  }

  if (lowerPrompt.includes("programming") || lowerPrompt.includes("code")) {
    return "I'd be happy to help with programming! Whether you need help with debugging, learning new concepts, or choosing the right approach for a project, I'm here to assist. What specific programming topic are you interested in?"
  }

  if (lowerPrompt.includes("explain") || lowerPrompt.includes("what is")) {
    return "I'll do my best to explain that clearly! " + responses[Math.floor(Math.random() * responses.length)]
  }


  // Default response with the user's prompt context
  return `I understand you're asking about "${prompt.slice(0, 50)}${prompt.length > 50 ? "..." : ""}". ${responses[Math.floor(Math.random() * responses.length)]} 

Is there anything specific you'd like me to elaborate on or any follow-up questions you have?`
}

// Auth Middleware
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers["authorization"]
    const token = authHeader && authHeader.split(" ")[1]

    if (!token) {
      return res.status(401).json({ error: "Access token required" })
    }


    const decoded = jwt.verify(token, process.env.JWT_SECRET || "your-secret-key")
    const user = await User.findById(decoded.userId).select("-password")

    if (!user || !user.isActive) {
      return res.status(403).json({ error: "User not found or inactive" })
    }

    req.user = user
    next()
  } catch (error) {
    return res.status(403).json({ error: "Invalid or expired token" })
  }
}

// Validation middleware
const validateRegistration = (req, res, next) => {
  const { fullName, email, password } = req.body

  if (!fullName || !email || !password) {
    return res.status(400).json({ error: "All fields are required" })
  }

  if (!validator.isEmail(email)) {
    return res.status(400).json({ error: "Please provide a valid email" })
  }

  if (password.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters" })
  }

  next()
}

// Routes

// Health check
app.get("/api/health", (req, res) => {
  res.json({
    status: "OK",
    timestamp: new Date().toISOString(),
    geminiConfigured: !!geminiModel,
    mode: geminiModel ? "Google Gemini" : "Mock AI",
  })
})

// Register
app.post("/api/register", validateRegistration, async (req, res) => {
  try {
    const { fullName, email, password } = req.body

    // Check if user exists
    const existingUser = await User.findOne({ email })
    if (existingUser) {
      return res.status(400).json({ error: "User already exists with this email" })
    }

    // Hash password
    const saltRounds = 12
    const hashedPassword = await bcrypt.hash(password, saltRounds)

    // Create user
    const user = new User({
      fullName: fullName.trim(),
      email: email.toLowerCase().trim(),
      password: hashedPassword,
    })

    await user.save()

    // Generate token
    const token = jwt.sign({ userId: user._id, email: user.email }, process.env.JWT_SECRET || "your-secret-key", {
      expiresIn: "7d",
    })

    res.status(201).json({
      message: "User created successfully",
      token,
      user: {
        id: user._id,
        fullName: user.fullName,
        email: user.email,
        avatar: user.avatar,
      },
    })
  } catch (error) {
    console.error("Registration error:", error)
    if (error.code === 11000) {
      return res.status(400).json({ error: "Email already exists" })
    }
    res.status(500).json({ error: "Internal server error" })
  }
})

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" })
    }

    // Find user
    const user = await User.findOne({ email: email.toLowerCase().trim() })
    if (!user || !user.isActive) {
      return res.status(400).json({ error: "Invalid credentials" })
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password)
    if (!isValidPassword) {
      return res.status(400).json({ error: "Invalid credentials" })
    }

    // Update last login
    user.lastLogin = new Date()
    await user.save()

    // Generate token
    const token = jwt.sign({ userId: user._id, email: user.email }, process.env.JWT_SECRET || "your-secret-key", {
      expiresIn: "7d",
    })

    res.json({
      message: "Login successful",
      token,
      user: {
        id: user._id,
        fullName: user.fullName,
        email: user.email,
        avatar: user.avatar,
        lastLogin: user.lastLogin,
      },
    })
  } catch (error) {
    console.error("Login error:", error)
    res.status(500).json({ error: "Internal server error" })
  }
})

// Get user profile
app.get("/api/profile", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select("-password")
    res.json(user)
  } catch (error) {
    console.error("Profile error:", error)
    res.status(500).json({ error: "Internal server error" })
  }
})

// Update user profile
app.put("/api/profile", authenticateToken, async (req, res) => {
  try {
    const { fullName } = req.body

    if (!fullName || fullName.trim().length < 2) {
      return res.status(400).json({ error: "Full name must be at least 2 characters" })
    }

    const user = await User.findByIdAndUpdate(
      req.user._id,
      { fullName: fullName.trim() },
      { new: true, runValidators: true },
    ).select("-password")

    res.json(user)
  } catch (error) {
    console.error("Profile update error:", error)
    res.status(500).json({ error: "Internal server error" })
  }
})

// Create chat session
app.post("/api/chat/sessions", authenticateToken, async (req, res) => {
  try {
    const { title } = req.body

    const session = new ChatSession({
      userId: req.user._id,
      title: title?.trim() || `Chat ${new Date().toLocaleDateString()}`,
    })

    await session.save()
    res.status(201).json(session)
  } catch (error) {
    console.error("Session creation error:", error)
    res.status(500).json({ error: "Internal server error" })
  }
})

// Get user's chat sessions
app.get("/api/chat/sessions", authenticateToken, async (req, res) => {
   
  try {
    const sessions = await ChatSession.find({
      userId: req.user._id,
      isActive: true,
    })
      .sort({ updatedAt: -1 })
      .limit(50)

    res.json(sessions)
  } catch (error) {
    console.error("Sessions fetch error:", error)
    res.status(500).json({ error: "Internal server error" })
  }
})

// Get messages for a session
app.get("/api/chat/sessions/:sessionId/messages", authenticateToken, async (req, res) => {
  try {
    const { sessionId } = req.params

    if (!mongoose.Types.ObjectId.isValid(sessionId)) {
      return res.status(400).json({ error: "Invalid session ID" })
    }

    // Verify session belongs to user
    const session = await ChatSession.findOne({
      _id: sessionId,
      userId: req.user._id,
      isActive: true,
    })

    if (!session) {
      return res.status(404).json({ error: "Session not found" })
    }

    const messages = await Message.find({ sessionId }).sort({ createdAt: 1 }).limit(100)

    res.json(messages)
  } catch (error) {
    console.error("Messages fetch error:", error)
    res.status(500).json({ error: "Internal server error" })
  }
})

// Chat endpoint with Gemini AI and Mock AI fallback
app.post("/api/chat", [authenticateToken, chatLimiter], async (req, res) => {
  try {
    const { prompt, sessionId } = req.body

    console.log("Received chat request:", { prompt, sessionId, userId: req.user._id })

    if (!prompt || !prompt.trim()) {
      return res.status(400).json({ error: "Prompt is required" })
    }

    let session
    if (sessionId) {
      if (!mongoose.Types.ObjectId.isValid(sessionId)) {
        return res.status(400).json({ error: "Invalid session ID" })
      }

      session = await ChatSession.findOne({
        _id: sessionId,
        userId: req.user._id,
        isActive: true,
      })

      if (!session) {
        return res.status(404).json({ error: "Session not found" })
      }
    } else {
      // Create new session
      session = new ChatSession({
        userId: req.user._id,
        title: prompt.slice(0, 50) + (prompt.length > 50 ? "..." : ""),
      })
      await session.save()
      console.log("Created new session:", session._id)
    }

    // Save user message
    const userMessage = new Message({
      sessionId: session._id,
      role: "user",
      content: prompt.trim(),
    })
    await userMessage.save()
    console.log("Saved user message")

    let aiResponse = ""
    let tokensUsed = 0

    // Try Gemini AI first, fallback to mock AI
    if (geminiModel) {
      try {
        console.log("Attempting Gemini AI API call...")

        // Get recent messages for context
        const recentMessages = await Message.find({ sessionId: session._id })
          .sort({ createdAt: -1 })
          .limit(10)
          .sort({ createdAt: 1 })

        // Build conversation context
        let conversationContext =
          "You are a helpful AI assistant. Be concise, friendly, and informative in your responses. If you're unsure about something, say so rather than guessing.\n\nConversation history:\n"

        recentMessages.forEach((msg) => {
          conversationContext += `${msg.role === "user" ? "User" : "Assistant"}: ${msg.content}\n`
        })

        const result = await generateText({
          model: geminiModel,
          prompt: conversationContext,
          maxTokens: 1000,
          temperature: 0.7,
        })

        aiResponse = result.text || ""
        tokensUsed = result.usage?.totalTokens || 0
        console.log("Gemini AI response received successfully")
      } catch (geminiError) {
        console.log("Gemini AI API failed, using mock AI:", geminiError.message)
        aiResponse = getMockAIResponse(prompt.trim())
        tokensUsed = 0
      }
    } else {
      console.log("Using mock AI (Gemini not configured)")
      // Simulate thinking time
      await new Promise((resolve) => setTimeout(resolve, 1000 + Math.random() * 2000))
      aiResponse = getMockAIResponse(prompt.trim())
      tokensUsed = 0
    }

    if (!aiResponse || !aiResponse.trim()) {
      console.error("No response generated")
      return res.status(500).json({ error: "Failed to generate response" })
    }

    console.log("AI response:", aiResponse.substring(0, 100) + "...")

    // Save assistant message
    const assistantMessage = new Message({
      sessionId: session._id,
      role: "assistant",
      content: aiResponse,
      tokens: tokensUsed,
    })
    await assistantMessage.save()
    console.log("Saved assistant message")

    // Update session timestamp
    session.updatedAt = new Date()
    await session.save()

    res.json({
      reply: aiResponse,
      sessionId: session._id,
      tokens: tokensUsed,
      mode: geminiModel ? "Google Gemini" : "Mock AI",
    })

    console.log("Response sent successfully")
  } catch (error) {
    console.error("Chat error:", error)
    res.status(500).json({ error: "Failed to process chat request: " + error.message })
  }
})

// Delete chat session
app.delete("/api/chat/sessions/:sessionId", authenticateToken, async (req, res) => {
  try {
    const { sessionId } = req.params

    if (!mongoose.Types.ObjectId.isValid(sessionId)) {
      return res.status(400).json({ error: "Invalid session ID" })
    }

    const session = await ChatSession.findOneAndUpdate(
      { _id: sessionId, userId: req.user._id },
      { isActive: false },
      { new: true },
    )

    if (!session) {
      return res.status(404).json({ error: "Session not found" })
    }

    res.json({ message: "Session deleted successfully" })
  } catch (error) {
    console.error("Session deletion error:", error)
    res.status(500).json({ error: "Internal server error" })
  }
})

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack)
  res.status(500).json({ error: "Something went wrong!" })
})

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: "Route not found" })
})

const PORT = process.env.PORT || 5000
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
  console.log(`Mode: ${geminiModel ? "Google Gemini AI" : "Mock AI (Development)"}`)
  if (geminiModel) {
    console.log("Gemini API Key configured: Yes")
  } else {
    console.log("Gemini API Key: Not configured or invalid - using Mock AI for development")
  }
})
