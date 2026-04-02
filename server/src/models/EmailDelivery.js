import mongoose from "mongoose";

const DeliveryEventSchema = new mongoose.Schema(
  {
    type: { type: String, required: true },
    at: { type: Date, default: Date.now },
    meta: { type: mongoose.Schema.Types.Mixed, default: {} },
  },
  { _id: false }
);

const EmailDeliverySchema = new mongoose.Schema(
  {
    kind: { type: String, enum: ["test", "verification_share"], default: "verification_share" },
    org_id: { type: mongoose.Schema.Types.ObjectId, ref: "Organization", index: true },
    audit_id: { type: mongoose.Schema.Types.ObjectId, ref: "Audit", index: true },
    to: [{ type: String }],
    cc: [{ type: String }],
    bcc: [{ type: String }],
    subject: { type: String, default: "" },
    provider: { type: String, default: "resend" },
    provider_message_id: { type: String, index: true, sparse: true },
    provider_payload_id: { type: String, index: true, sparse: true },
    verification_code: { type: String, index: true, sparse: true },
    verification_url: { type: String, default: "" },
    certificate_url: { type: String, default: "" },
    status: {
      type: String,
      enum: ["queued", "sent", "delivered", "opened", "clicked", "failed", "bounced", "complained"],
      default: "queued",
      index: true,
    },
    issue: { type: String, default: "" },
    sent_at: { type: Date },
    delivered_at: { type: Date },
    opened_at: { type: Date },
    first_clicked_at: { type: Date },
    last_clicked_at: { type: Date },
    open_count: { type: Number, default: 0 },
    click_count: { type: Number, default: 0 },
    recipient_opens: {
      type: Map,
      of: new mongoose.Schema(
        {
          count: { type: Number, default: 0 },
          first_at: { type: Date },
          last_at: { type: Date },
        },
        { _id: false }
      ),
      default: {},
    },
    recipient_clicks: {
      type: Map,
      of: new mongoose.Schema(
        {
          count: { type: Number, default: 0 },
          first_at: { type: Date },
          last_at: { type: Date },
          last_target: { type: String, default: "verify" },
        },
        { _id: false }
      ),
      default: {},
    },
    events: { type: [DeliveryEventSchema], default: [] },
  },
  { timestamps: true }
);

EmailDeliverySchema.index({ org_id: 1, createdAt: -1 });
EmailDeliverySchema.index({ verification_code: 1, createdAt: -1 });

export default mongoose.models.EmailDelivery || mongoose.model("EmailDelivery", EmailDeliverySchema);
