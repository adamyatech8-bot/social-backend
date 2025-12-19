// ====== Imports & Setup ======
const express = require("express");
const http = require("http");
const path = require("path");
const { Server } = require("socket.io");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const cors = require("cors");
require("dotenv").config();

const JWT_SECRET = process.env.JWT_SECRET || "shhhh";

const userModel = require("./models/user");
const postModel = require("./models/post");
const upload = require("./config/multer.config");
const uploadvideo = require("./config/multervideo");
const Reel = require("./models/reelModel");
const Story = require("./models/storymodel");
const uploadStory = require("./config/multerstory");

// ====== App Configuration ======
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.FRONTEND_URL || "http://localhost:5173",
    credentials: true
  }
});

// ====== Middleware ======
app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:5173",
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

// ====== Auth Middleware (API response: JSON) ======
function isLoggedIn(req, res, next) {
  try {
    const token = req.cookies.token || req.headers.authorization
      ? (req.headers.authorization || '').replace(/^Bearer\s/, '') 
      : null;
    if (!token) {
      return res.status(401).json({ success: false, message: "Not authenticated" });
    }
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    res.status(401).json({ success: false, message: "Invalid authentication" });
  }
}

// ====== API Routes ======

// Auth endpoints
app.post("/api/register", async (req, res) => {
  const { username, name, password, age, email } = req.body;
  try {
    const existingUser = await userModel.findOne({ email });
    if (existingUser) return res.status(409).json({ success: false, message: "User already registered" });

    const hash = await bcrypt.hash(password, 10);
    const user = await userModel.create({ username, name, email, password: hash, age });
    const token = jwt.sign({ email: user.email, userid: user._id }, JWT_SECRET);
    res.cookie("token", token, { httpOnly: true, sameSite: 'lax' });
    res.json({ success: true, token, user: { username: user.username, email: user.email, _id: user._id } });
  } catch (err) {
    res.status(500).json({ success: false, message: "Registration failed" });
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await userModel.findOne({ email });
    if (!user) return res.status(400).json({ success: false, message: "Invalid credentials" });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ success: false, message: "Invalid credentials" });
    const token = jwt.sign({ email: user.email, userid: user._id }, JWT_SECRET);
    res.cookie("token", token, { httpOnly: true, sameSite: 'lax' });
    res.json({ success: true, token, user: { username: user.username, email: user.email, _id: user._id } });
  } catch (err) {
    res.status(500).json({ success: false, message: "Login failed" });
  }
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ success: true, message: "Logged out" });
});

// Profile endpoints
app.get("/api/profile", isLoggedIn, async (req, res) => {
  try {
    const user = await userModel.findOne({ email: req.user.email })
      .populate({
        path: "posts",
        populate: { path: "user comments.user", select: "username" }
      });
    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, message: "Error fetching profile" });
  }
});

app.get("/api/home", isLoggedIn, async (req, res) => {
  try {
    const user = await userModel.findById(req.user.userid)
      .populate({
        path: "posts",
        populate: { path: "user comments.user", select: "username" }
      });
    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, message: "Error fetching home info" });
  }
});

// Upload profile picture
app.post("/api/upload", isLoggedIn, upload.single("image"), async (req, res) => {
  try {
    const user = await userModel.findById(req.user.userid);
    user.profilepic = req.file.filename;
    await user.save();
    res.json({ success: true, profilepic: user.profilepic });
  } catch (err) {
    res.status(500).json({ success: false, message: "Error uploading profile pic" });
  }
});

// STORY SECTION
app.post("/api/upload/story", isLoggedIn, uploadStory.single("story"), async (req, res) => {
  if (!req.file) return res.status(400).json({ success: false, message: "No story uploaded" });

  const storyPath = `/stories/uploads/${req.file.filename}`;
  await Story.create({
    user: req.user.userid,
    file: req.file.filename,
    filepath: storyPath,
  });

  res.json({ success: true, filepath: storyPath });
});

app.get("/api/story", isLoggedIn, async (req, res) => {
  const stories = await Story.find().populate("user");
  const user = await userModel.findById(req.user.userid);
  res.json({ success: true, stories, user });
});

app.delete("/api/story/:id", isLoggedIn, async (req, res) => {
  try {
    const story = await Story.findById(req.params.id);
    if (!story) return res.status(404).json({ success: false, message: "Story not found" });

    if (story.user && story.user.toString() !== req.user.userid.toString()) {
      return res.status(403).json({ success: false, message: "Not allowed" });
    }

    await Story.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: "Story deleted successfully" });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// REELS SECTION
app.post("/api/upload/video", isLoggedIn, uploadvideo.single("video"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, message: "No video uploaded" });

    const videoPath = `/videos/uploads/${req.file.filename}`;
    await Reel.create({
      user: req.user.userid,
      filename: req.file.filename,
      filepath: videoPath,
      caption: req.body.caption || "",
    });

    res.json({ success: true, filepath: videoPath });
  } catch (err) {
    res.status(500).json({ success: false, message: "Error uploading video" });
  }
});

app.get("/api/reels", isLoggedIn, async (req, res) => {
  try {
    const reels = await Reel.find()
      .populate("user", "username")
      .sort({ createdAt: -1 });
    const user = await userModel.findById(req.user.userid);
    res.json({ success: true, reels, user });
  } catch (err) {
    res.status(500).json({ success: false, message: "Error fetching reels" });
  }
});

app.post("/api/like/:id", isLoggedIn, async (req, res) => {
  try {
    const { id } = req.params;
    const { type } = req.query; // type=reel or post
    const userId = String(req.user.userid);

    let item;
    if (type === "reel") item = await Reel.findById(id);
    else item = await postModel.findById(id);

    if (!item) return res.status(404).json({ success: false, message: "Item not found" });

    const idx = item.likes.findIndex(l => String(l) === userId);
    if (idx === -1) item.likes.push(req.user.userid);
    else item.likes.splice(idx, 1);

    await item.save();
    res.json({ success: true, likesCount: item.likes.length });
  } catch (err) {
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

app.post("/api/reel/comment/:id", isLoggedIn, async (req, res) => {
  try {
    const reel = await Reel.findById(req.params.id);
    if (!reel) return res.status(404).json({ success: false, message: "Reel not found" });

    reel.comments.push({
      user: req.user.userid,
      text: req.body.text,
    });

    await reel.save();
    res.json({ success: true, comments: reel.comments });
  } catch (err) {
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

app.get("/api/reel/:id", isLoggedIn, async (req, res) => {
  try {
    const reel = await Reel.findById(req.params.id)
      .populate("user", "username")
      .populate("comments.user", "username");

    if (!reel) return res.status(404).json({ success: false, message: "Reel not found" });

    const user = await userModel.findById(req.user.userid);
    res.json({ success: true, reel, user });
  } catch (err) {
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Post endpoints
app.post("/api/uploadpost", isLoggedIn, upload.single("postpic"), async (req, res) => {
  try {
    const user = await userModel.findById(req.user.userid);
    const newPost = await postModel.create({
      content: req.body.content,
      postpic: req.file ? req.file.filename : "default.png",
      user: user._id
    });
    user.posts.push(newPost._id);
    await user.save();
    res.json({ success: true, post: newPost });
  } catch (err) {
    res.status(500).json({ success: false, message: "Error uploading post" });
  }
});

app.post("/api/likepost/:id", isLoggedIn, async (req, res) => {
  try {
    const post = await postModel.findById(req.params.id);
    if (!post) return res.status(404).json({ success: false, message: "Post not found" });
    const userId = String(req.user.userid);

    const idx = post.likes.findIndex(l => String(l) === userId);
    if (idx === -1) post.likes.push(req.user.userid);
    else post.likes.splice(idx, 1);
    await post.save();
    res.json({ success: true, likesCount: post.likes.length });
  } catch (err) {
    res.status(500).json({ success: false, message: "Error liking post" });
  }
});

app.post("/api/comment/:id", isLoggedIn, async (req, res) => {
  try {
    const post = await postModel.findById(req.params.id);
    if (!post) return res.status(404).json({ success: false, message: "Post not found" });
    post.comments.push({ user: req.user.userid, content: req.body.content });
    await post.save();
    res.json({ success: true, comments: post.comments });
  } catch (err) {
    res.status(500).json({ success: false, message: "Error commenting post" });
  }
});

// Edit & Update post
app.put("/api/edit/:id", isLoggedIn, async (req, res) => {
  try {
    const post = await postModel.findByIdAndUpdate(req.params.id, { content: req.body.content }, { new: true });
    res.json({ success: true, post });
  } catch(err) {
    res.status(500).json({ success: false, message: "Error updating post" });
  }
});

// Get all your posts & likes (client page)
app.get("/api/client", isLoggedIn, async (req, res) => {
  try {
    const user = await userModel.findById(req.user.userid)
      .populate({
        path: "posts",
        populate: { path: "likes", select: "_id" }
      });
    res.json({ success: true, user });
  } catch(err) {
    res.status(500).json({ success: false, message: "Error loading client data" });
  }
});

// Chat users listing
app.get("/api/users", isLoggedIn, async (req, res) => {
  try {
    const allUsers = await userModel.find({}, "username _id");
    res.json({ success: true, users: allUsers });
  } catch(err) {
    res.status(500).json({ success: false, message: "Error fetching users" });
  }
});

// ====== PASSWORD RESET ======
const User = require("./models/user");

app.post("/api/forgot", async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ success: false, message: "No user found with that email" });

    const token = crypto.randomBytes(20).toString("hex");
    user.resetToken = token;
    user.resetTokenExpiry = Date.now() + 15 * 60 * 1000;
    await user.save();

    const resetLink = `${process.env.RESET_BASE_URL || "http://localhost:5173"}/reset/${token}`;
    // TODO: send reset email. For now, return the link for frontend.
    res.json({ success: true, resetLink });
  } catch (err) {
    res.status(500).json({ success: false, message: "Error processing reset" });
  }
});

app.get("/api/reset/:token", async (req, res) => {
  try {
    const user = await User.findOne({
      resetToken: req.params.token,
      resetTokenExpiry: { $gt: Date.now() },
    });
    if (!user) return res.status(400).json({ success: false, message: "Invalid or expired token" });
    res.json({ success: true, token: req.params.token });
  } catch (err) {
    res.status(500).json({ success: false, message: "Reset check failed" });
  }
});

app.post("/api/reset/:token", async (req, res) => {
  try {
    const user = await User.findOne({
      resetToken: req.params.token,
      resetTokenExpiry: { $gt: Date.now() },
    });
    if (!user) return res.status(400).json({ success: false, message: "Invalid or expired token" });

    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;
    await user.save();

    res.json({ success: true, message: "Password updated" });
  } catch (err) {
    res.status(500).json({ success: false, message: "Reset failed" });
  }
});

// ====== SOCKET.IO PRIVATE CHAT ENDPOINT ======
const userSocketMap = {};

io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token || (socket.handshake.headers.authorization ? socket.handshake.headers.authorization.replace(/^Bearer\s/, '') : null);
    if (!token) return next(new Error("No token"));
    const user = jwt.verify(token, JWT_SECRET);
    socket.user = user;
    next();
  } catch {
    next(new Error("Invalid token"));
  }
});

io.on("connection", (socket) => {
  const userId = socket.user.userid;
  userSocketMap[userId] = socket.id;
  console.log(`🟢 User connected: ${userId}`);

  socket.on("private-message", ({ to, message }) => {
    const targetSocketId = userSocketMap[to];
    if (targetSocketId) {
      io.to(targetSocketId).emit("receive-message", {
        from: userId,
        message,
      });
    }
  });

  socket.on("disconnect", () => {
    delete userSocketMap[userId];
    console.log(`🔴 User disconnected: ${userId}`);
  });
});

// ====== Start Server ======
const PORT = process.env.PORT || 3000;
server.listen(PORT, () =>
  console.log(`🚀 API server running with CORS and Socket.IO at http://localhost:${PORT}`)
);

