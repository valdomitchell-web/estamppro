import mongoose from "mongoose";

const EmailDeliverySchema = new mongoose.Schema(
  {
    org_id: { type: mongoose.Schema.Types.ObjectId, ref: "Organization", index: true, required: true },
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: "User", index: true, required: true },
    audit_id: { type: mongoose.Schema.Types.ObjectId, ref: "Audit", default: null, index: true },
    kind: { type: String, enum: ["test", "verification_share"], required: true },
    status: { type: String, enum: ["queued", "sent", "failed"], default: "queued", index: true },
    provider: { type: String, default: "resend" },
    provider_message_id: { type: String, default: "" },
    to: { type: [String], default: [] },
    cc: { type: [String], default: [] },
    bcc: { type: [String], default: [] },
    reply_to: { type: String, default: "" },
    subject: { type: String, default: "" },
    note: { type: String, default: "" },
    verification_code: { type: String, default: "" },
    verify_url: { type: String, default: "" },
    certificate_url: { type: String, default: "" },
    html: { type: String, default: "" },
    text: { type: String, default: "" },
    branding_snapshot: { type: Object, default: {} },
    tags: { type: [Object], default: [] },
    response_meta: { type: Object, default: {} },
    error_code: { type: String, default: "" },
    error_message: { type: String, default: "" },
    user_message: { type: String, default: "" },
    resent_from_delivery_id: { type: mongoose.Schema.Types.ObjectId, ref: "EmailDelivery", default: null },
    created_at: { type: Date, default: Date.now },
    updated_at: { type: Date, default: Date.now },
  },
  { minimize: false }
);

EmailDeliverySchema.pre("save", function preSave(next) {
  this.updated_at = new Date();
  next();
});

export default mongoose.model("EmailDelivery", EmailDeliverySchema);
