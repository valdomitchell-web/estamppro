import mongoose from "mongoose";

const AuditSchema = new mongoose.Schema({
  org_id: { type: mongoose.Schema.Types.ObjectId, ref: "Org", default: null },

  stamp_id: { type: mongoose.Schema.Types.ObjectId, ref: "StampDesign", default: null },
  document_id: { type: mongoose.Schema.Types.ObjectId, ref: "Document", default: null },
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },

  action: { type: String, default: "" },
  ok: { type: Boolean, default: true },
  target: { type: String, default: "" },

  verification_code: { type: String, default: "" },
  document_hash: { type: String, default: "" },

  page: { type: Number, default: 0 },
  x: { type: Number, default: 0 },
  y: { type: Number, default: 0 },
  scale: { type: Number, default: 1 },
  opacity: { type: Number, default: 1 },

  device_fingerprint: { type: String, default: "" },

  meta: { type: mongoose.Schema.Types.Mixed, default: {} },

  verification: {
    scheme: { type: String, default: "" },
    sig: { type: String, default: "" },
    payload: { type: mongoose.Schema.Types.Mixed, default: {} },
  },

  created_at: { type: Date, default: Date.now },
}, {
  minimize: false,
});

export default mongoose.model("Audit", AuditSchema);