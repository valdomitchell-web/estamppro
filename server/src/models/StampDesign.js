import mongoose from "mongoose";

const StampDesignSchema = new mongoose.Schema({
  org_id: { type: mongoose.Schema.Types.ObjectId, ref: "Org" },
  name: String,
  design_type: { type: String, enum: ["uploaded", "custom"], default: "uploaded" },
  image_path: String,
  s3_key: { type: String, default: "" },
  width: Number,
  height: Number,
  customization: {
    shape: { type: String, default: "" },
    topText: { type: String, default: "" },
    centerText: { type: String, default: "" },
    bottomText: { type: String, default: "" },
    borderColor: { type: String, default: "" },
    textColor: { type: String, default: "" },
    borderWidth: { type: Number, default: 0 },
    fontSize: { type: Number, default: 0 },
    padding: { type: Number, default: 0 },
    showQrBox: { type: Boolean, default: false },
  },
  secret: {
    salt_b64: String,
    iv_b64: String,
    tag_b64: String,
    enc_key_b64: String,
    kdf: { type: String, default: "scrypt" },
    N: { type: Number, default: 16384 },
    r: { type: Number, default: 8 },
    p: { type: Number, default: 1 },
  },
  created_by: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  created_at: { type: Date, default: Date.now },
});

export default mongoose.model("StampDesign", StampDesignSchema);