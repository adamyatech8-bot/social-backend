const multer = require("multer");
const path = require("path");
const crypto = require("crypto");
const fs = require("fs");

// ✅ Ensure upload folder exists
const uploadPath = path.join(__dirname, "../public/videos/uploads");
if (!fs.existsSync(uploadPath)) {
  fs.mkdirSync(uploadPath, { recursive: true });
}

// ✅ Configure Multer storage
const storage = multer.diskStorage({
  destination: function (_req, _file, cb) {
    cb(null, uploadPath);
  },
  filename: function (_req, file, cb) {
    crypto.randomBytes(12, (err, bytes) => {
      if (err) return cb(err);
      const filename = bytes.toString("hex") + path.extname(file.originalname);
      cb(null, filename);
    });
  },
});

// ✅ Filter video files only
function fileFilter(_req, file, cb) {
  const allowedTypes = ["video/mp4", "video/mkv", "video/webm", "video/avi"];
  if (allowedTypes.includes(file.mimetype)) cb(null, true);
  else cb(new Error("Only video files are allowed!"));
}

// ✅ Export multer instance
const uploadvideo = multer({
  storage,
  fileFilter,
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB limit
});

module.exports = uploadvideo;
