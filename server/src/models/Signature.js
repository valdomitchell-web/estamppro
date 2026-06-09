import mongoose from "mongoose";

const SignatureSchema = new mongoose.Schema(
  {
    org_id: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
    created_by: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    name: { type: String, default: "My Signature" },
    imageDataUrl: { type: String, required: true },
    visibility: {
      type: String,
      enum: ["organization", "private"],
      default: "organization",
    },
  },
  { timestamps: true }
);

export default mongoose.model("Signature", SignatureSchema);