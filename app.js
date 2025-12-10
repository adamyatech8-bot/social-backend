// ====== Imports ======
const express = require("express");
const http = require("http");
const path = require("path");
const { Server } = require("socket.io");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
require("dotenv").config();

const JWT_SECRET = process.env.JWT_SECRET || "shhhh";

const userModel = require("./models/user");
const postModel = require("./models/post");
const upload = require("./config/multer.config");
const uploadvideo = require("./config/multervideo");
const Reel = require("./models/reelModel");
const Story = require("./models/storymodel");
const uploadStory = require("./config/multerstory");

// ====== Setup ======
const app = express();
const server = http.createServer(app);
const io = new Server(server);

// ====== App setup ======
app.set("view engine", "ejs");
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

// ====== Middleware ======
function isLoggedIn(req, res, next) {
  try {
    if (!req.cookies.token) return res.redirect("/login");
    req.user = jwt.verify(req.cookies.token, JWT_SECRET);
    next();
  } catch (err) {
    res.redirect("/login");
  }
}

// ====== Routes ======
app.get("/", (_req, res) => res.render("index"));
app.get("/login", (_req, res) => res.render("login"));

// ===== Register & Login =====
app.post("/register", async (req, res) => {
  const { username, name, password, age, email } = req.body;
  const existingUser = await userModel.findOne({ email });
  if (existingUser) return res.status(500).send("User already registered");

  const hash = await bcrypt.hash(password, 10);
  const user = await userModel.create({ username, name, email, password: hash, age });
  const token = jwt.sign({ email: user.email, userid: user._id }, JWT_SECRET);
  res.cookie("token", token);
  res.redirect("/login");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await userModel.findOne({ email });
  if (!user) return res.status(400).send("Invalid credentials");

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.redirect("/login");

  const token = jwt.sign({ email: user.email, userid: user._id }, JWT_SECRET);
  res.cookie("token", token);
  res.redirect("/home");
});

app.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/login");
});

// ====== Profile & Home ======
app.get("/profile", isLoggedIn, async (req, res) => {
  const user = await userModel.findOne({ email: req.user.email })
    .populate({
      path: "posts",
      populate: { path: "user comments.user", select: "username" }
    });
  res.render("profile", { user });
});

app.get("/home", isLoggedIn, async (req, res) => {
  const user = await userModel.findById(req.user.userid)
    .populate({
      path: "posts",
      populate: { path: "user comments.user", select: "username" }
    });
  res.render("home", { user });
});

// ===== Upload Profile Pic =====
app.post("/upload", isLoggedIn, upload.single("image"), async (req, res) => {
  const user = await userModel.findById(req.user.userid);
  user.profilepic = req.file.filename;
  await user.save();
  res.redirect("/home");
});

// ====== STORY SECTION ======
app.get("/upload/story", isLoggedIn, (req, res) => {
  res.render("uploadstory");
});

app.post("/upload/story", isLoggedIn, uploadStory.single("story"), async (req, res) => {
  if (!req.file) return res.status(400).send("No story uploaded");

  const storyPath = `/stories/uploads/${req.file.filename}`;
  await Story.create({
    user: req.user.userid,
    file: req.file.filename,
    filepath: storyPath,
  });

  res.redirect("/story");
});

app.get("/story", isLoggedIn, async (req, res) => {
  const stories = await Story.find().populate("user");
  const user = await userModel.findById(req.user.userid);
  res.render("story", { stories, user });
});

// ===== Delete Story =====
app.delete("/story/:id", isLoggedIn, async (req, res) => {
  try {
    const story = await Story.findById(req.params.id);
    if (!story) return res.status(404).json({ success: false, message: "Story not found" });

    if (story.user && story.user.toString() !== req.user.userid.toString()) {
      return res.status(403).json({ success: false, message: "Not allowed" });
    }

    await Story.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: "Story deleted successfully" });
  } catch (err) {
    console.error("Delete story error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ====================== 🎥 REELS SECTION ======================

// Show video upload form
app.get("/upload/video", isLoggedIn, (_req, res) => {
  res.render("uploadvideo");
});

// Upload a reel
app.post("/upload/video", isLoggedIn, uploadvideo.single("video"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).send("No video uploaded");

    const videoPath = `/videos/uploads/${req.file.filename}`;
    await Reel.create({
      user: req.user.userid, // IMPORTANT: link reel to uploader
      filename: req.file.filename,
      filepath: videoPath,
      caption: req.body.caption || "",
    });

    res.redirect("/reels");
  } catch (err) {
    console.error("❌ Error uploading video:", err);
    res.status(500).send("Error uploading video");
  }
});

// Display all reels (populating uploader username)
app.get("/reels", isLoggedIn, async (req, res) => {
  const reels = await Reel.find()
    .populate("user", "username")
    .sort({ createdAt: -1 });
  const user = await userModel.findById(req.user.userid);
  res.render("reels", { reels, user });
});

// Like/Unlike Reel or Post (robust handling)
app.get("/like/:id", isLoggedIn, async (req, res) => {
  try {
    const { id } = req.params;
    const { type } = req.query; // type=reel or post
    const userId = String(req.user.userid);

    let item;
    if (type === "reel") item = await Reel.findById(id);
    else item = await postModel.findById(id);

    if (!item) return res.status(404).send("Item not found");

    const idx = item.likes.findIndex(l => String(l) === userId);
    if (idx === -1) item.likes.push(req.user.userid);
    else item.likes.splice(idx, 1);

    await item.save();
    res.redirect("back");
  } catch (err) {
    console.error("Like error:", err);
    res.status(500).send("Internal server error");
  }
});

// Add comment to reel
app.post("/reel/comment/:id", isLoggedIn, async (req, res) => {
  try {
    const reel = await Reel.findById(req.params.id);
    if (!reel) return res.status(404).send("Reel not found");

    reel.comments.push({
      user: req.user.userid,
      text: req.body.text,
    });

    await reel.save();
    res.redirect("/reel/" + req.params.id);
  } catch (err) {
    console.error("Comment error:", err);
    res.status(500).send("Internal server error");
  }
});

// Single reel page (populate uploader and commenters)
app.get("/reel/:id", isLoggedIn, async (req, res) => {
  const reel = await Reel.findById(req.params.id)
    .populate("user", "username")
    .populate("comments.user", "username");

  if (!reel) return res.status(404).send("Reel not found");

  const user = await userModel.findById(req.user.userid);
  res.render("reelpage", { reel, user });
});

// ===============================================================

// ====== Post Upload ======
app.post("/uploadpost", isLoggedIn, upload.single("postpic"), async (req, res) => {
  const user = await userModel.findById(req.user.userid);
  const newPost = await postModel.create({
    content: req.body.content,
    postpic: req.file ? req.file.filename : "default.png",
    user: user._id
  });
  user.posts.push(newPost._id);
  await user.save();
  res.redirect("/home");
});

// ====== Like Post (backwards-compatible route if you used it) ======
app.get("/likepost/:id", isLoggedIn, async (req, res) => {
  const post = await postModel.findById(req.params.id);
  if (!post) return res.status(404).send("Post not found");
  const userId = String(req.user.userid);
  const idx = post.likes.findIndex(l => String(l) === userId);
  if (idx === -1) post.likes.push(req.user.userid);
  else post.likes.splice(idx, 1);
  await post.save();
  res.redirect(req.query.from === "home" ? "/home" : "/profile");
});

// ====== Comment Post ======
app.post("/comment/:id", isLoggedIn, async (req, res) => {
  const post = await postModel.findById(req.params.id);
  if (!post) return res.status(404).send("Post not found");
  post.comments.push({ user: req.user.userid, content: req.body.content });
  await post.save();
  res.redirect(req.headers.referer || "/home");
});

// ====== Edit & Update Post ======
app.get("/edit/:id", isLoggedIn, async (req, res) => {
  const post = await postModel.findById(req.params.id).populate("user");
  res.render("edit", { post });
});

app.post("/update/:id", isLoggedIn, async (req, res) => {
  await postModel.findByIdAndUpdate(req.params.id, { content: req.body.content });
  res.redirect("/profile");
});

// ====== Client Page ======
app.get("/client", isLoggedIn, async (req, res) => {
  const user = await userModel.findById(req.user.userid)
    .populate({
      path: "posts",
      populate: { path: "likes", select: "_id" }
    });
  res.render("client", { user });
});

// ====== CHAT PAGE ======
app.get("/chat", isLoggedIn, async (req, res) => {
  const allUsers = await userModel.find({}, "username _id");
  res.render("chat", {
    user: req.user,
    allUsers,
    token: req.cookies.token
  });
});

// ====== PASSWORD RESET ======
const User = require("./models/user");

app.get("/forgot", (req, res) => res.render("forgot"));

app.post("/forgot", async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.send("⚠️ No user found with that email.");

  const token = crypto.randomBytes(20).toString("hex");
  user.resetToken = token;
  user.resetTokenExpiry = Date.now() + 15 * 60 * 1000;
  await user.save();

  const resetLink = `http://localhost:3000/reset/${token}`;
  console.log("🔗 Reset link:", resetLink);

  res.send(`Password reset link generated! (check console): ${resetLink}`);
});

app.get("/reset/:token", async (req, res) => {
  const user = await User.findOne({
    resetToken: req.params.token,
    resetTokenExpiry: { $gt: Date.now() },
  });
  if (!user) return res.send("Invalid or expired reset link.");
  res.render("reset", { token: req.params.token });
});

app.post("/reset/:token", async (req, res) => {
  const user = await User.findOne({
    resetToken: req.params.token,
    resetTokenExpiry: { $gt: Date.now() },
  });
  if (!user) return res.send("Invalid or expired token.");

  const hashedPassword = await bcrypt.hash(req.body.password, 10);
  user.password = hashedPassword;
  user.resetToken = undefined;
  user.resetTokenExpiry = undefined;
  await user.save();

  res.send("✅ Password successfully updated! You can now login.");
});

// ====== SOCKET.IO PRIVATE CHAT ======
const userSocketMap = {};

io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token;
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
    console.log(`🔴 User disconnected: ${userId}`);
    delete userSocketMap[userId];
  });
});

// ====== Start Server ======
const PORT = process.env.PORT || 3000;
server.listen(PORT, () =>
  console.log(`🚀 Server running with Socket.IO on http://localhost:${PORT}`)
);
