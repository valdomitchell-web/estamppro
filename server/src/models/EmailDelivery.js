import mongoose from "mongoose";

const DeliveryEventSchema = new mongoose.Schema(
  {
    type: {
      type: String,
      enum: ["queued", "sent", "delivered", "opened", "bounced", "complained", "failed"],
      required: true,
    },
    at: { type: Date, default: Date.now },
    raw: { type: mongoose.Schema.Types.Mixed, default: null },
  },
  { _id: false }
);

const EmailDeliverySchema = new mongoose.Schema(
  {
    org_id: { type: mongoose.Schema.Types.ObjectId, ref: "Organization", index: true, required: true },
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: "User", index: true, default: null },
    audit_id: { type: mongoose.Schema.Types.ObjectId, ref: "Audit", default: null, index: true },
    kind: { type: String, enum: ["test", "verification_share"], default: "verification_share", index: true },
    provider: { type: String, default: "resend" },
    provider_message_id: { type: String, default: "", index: true },
    status: {
      type: String,
      enum: ["queued", "sent", "delivered", "opened", "bounced", "complained", "failed"],
      default: "queued",
      index: true,
    },
    to: { type: [String], default: [] },
    cc: { type: [String], default: [] },
    bcc: { type: [String], default: [] },
    reply_to: { type: String, default: "" },
    subject: { type: String, default: "" },
    note: { type: String, default: "" },
    verification_code: { type: String, default: "", index: true },
    verify_url: { type: String, default: "" },
    certificate_url: { type: String, default: "" },
    html: { type: String, default: "" },
    text: { type: String, default: "" },
    branding_snapshot: { type: Object, default: {} },
    response_meta: { type: Object, default: {} },
    error_code: { type: String, default: "" },
    error_message: { type: String, default: "" },
    user_message: { type: String, default: "" },
    queued_at: { type: Date, default: Date.now },
    sent_at: { type: Date, default: null },
    delivered_at: { type: Date, default: null },
    opened_at: { type: Date, default: null },
    failed_at: { type: Date, default: null },
    resent_from_delivery_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "EmailDelivery",
      default: null,
      index: true,
    },
    events: { type: [DeliveryEventSchema], default: [{ type: "queued", at: new Date(), raw: null }] },
    created_at: { type: Date, default: Date.now, index: true },
    updated_at: { type: Date, default: Date.now },
  },
  { minimize: false, timestamps: true }
);

EmailDeliverySchema.pre("save", function preSave(next) {
  this.updated_at = new Date();
  if (!this.queued_at) this.queued_at = this.created_at || new Date();
  next();
});

export default mongoose.models.EmailDelivery || mongoose.model("EmailDelivery", EmailDeliverySchema);
