const mongoose = require("mongoose");

const storySchema = mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  file: String, // image or short video
  filepath: String,
  createdAt: { type: Date, default: Date.now, expires: "24h" } // auto delete after 24h
});

module.exports = mongoose.model("Story", storySchema);
 