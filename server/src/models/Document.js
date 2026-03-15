
import mongoose from "mongoose";

const DocumentSchema = new mongoose.Schema({
  org_id: { type: mongoose.Schema.Types.ObjectId, ref: "Org" },
  filename: String,
  path: String,
  s3_key: { type: String, default: "" },
  s3_url: { type: String, default: "" },
  mime: String,
  size: Number,
  pages: Number,
  sha256: String,
  uploaded_by: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  created_at: { type: Date, default: Date.now },
});

export default mongoose.model("Document", DocumentSchema);