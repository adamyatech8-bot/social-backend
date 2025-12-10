const mongoose = require("mongoose");

mongoose.connect(`mongodb://127.0.0.1:27017/postappproject`);

const userSchema = mongoose.Schema({
  username: String,
  name: String,
  email: String,
  password: { type: String, required: true },
  profilepic: { type: String, default: "default.png" },
  age: Number,
  posts: [
    { type: mongoose.Schema.Types.ObjectId, ref: "Post" }
  ],
  followers: [
    { type: mongoose.Schema.Types.ObjectId, ref: "User" }
  ],
  following: [
    { type: mongoose.Schema.Types.ObjectId, ref: "User" }
  ],
  resetToken: String,           // ✅ for forgot password
  resetTokenExpiry: Date        // ✅ token expiry time
});

module.exports = mongoose.model("User", userSchema);
