const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const uploadPath = path.join(__dirname, "../public/stories/uploads");
if (!fs.existsSync(uploadPath)) {
  fs.mkdirSync(uploadPath, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (_req, file, cb) => cb(null, uploadPath),
  filename: (_req, file, cb) => {
    crypto.randomBytes(12, (err, bytes) => {
      if (err) return cb(err);
      cb(null, bytes.toString("hex") + path.extname(file.originalname));
    });
  },
});

function fileFilter(_req, file, cb) {
  const allowed = ["image/jpeg", "image/png", "video/mp4", "video/webm"];
  if (allowed.includes(file.mimetype)) cb(null, true);
  else cb(new Error("Only images or short videos allowed for stories!"));
}

const uploadStory = multer({ storage, fileFilter, limits: { fileSize: 20 * 1024 * 1024 } }); // 20MB max

module.exports = uploadStory;
