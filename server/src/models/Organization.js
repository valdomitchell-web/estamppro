import mongoose from "mongoose";

const OrganizationSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    slug: { type: String, unique: true, index: true, required: true },
    owner_user_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },

    plan: {
      type: String,
      enum: ["free", "pro", "business"],
      default: "free",
    },

    billing: {
      stripe_customer_id: { type: String, default: "" },
      stripe_subscription_id: { type: String, default: "" },
      status: { type: String, default: "inactive" },
      stripe_price_id: { type: String, default: "" },
      subscription_status: { type: String, default: "inactive" },
      current_period_end: { type: Date, default: null },
      cancel_at_period_end: { type: Boolean, default: false },
      last_checkout_session_id: { type: String, default: "" },
      last_event_id: { type: String, default: "" },
    },

    usage: {
      documentsThisMonth: { type: Number, default: 0 },
      stampsThisMonth: { type: Number, default: 0 },
      storageUsedMB: { type: Number, default: 0 },
      resetAt: {
        type: Date,
        default: () => new Date(new Date().getFullYear(), new Date().getMonth(), 1),
      },
    },

    branding: {
      logo_url: { type: String, default: "" },
      primary_color: { type: String, default: "#1d4ed8" },
      accent_color: { type: String, default: "#0f172a" },
      stamp_label: { type: String, default: "Official Organization Stamp" },
      email_footer: { type: String, default: "" },
      watermark_text: { type: String, default: "" },
    },

    created_at: { type: Date, default: Date.now },
  },
  { minimize: false }
);

export default mongoose.model("Organization", OrganizationSchema);
