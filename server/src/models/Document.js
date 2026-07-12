import mongoose from "mongoose";

const DocumentSchema = new mongoose.Schema({
  org_id: {
  type: mongoose.Schema.Types.ObjectId,
  ref: "Organization",
  default: null,
  index: true,
},
  filename: String,
  path: String,
  s3_key: { type: String, default: "" },
  s3_url: { type: String, default: "" },
  mime: String,
  size: Number,
  pages: Number,
  sha256: String,
 uploaded_by: {
  type: mongoose.Schema.Types.ObjectId,
  ref: "User",
  required: true,
  index: true,
},
  created_at: { type: Date, default: Date.now },
});
DocumentSchema.index({
  org_id: 1,
  uploaded_by: 1,
  created_at: -1,
});

export default mongoose.model("Document", DocumentSchema);