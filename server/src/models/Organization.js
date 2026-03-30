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

    branding: {
      logo_url: { type: String, default: "" },
      primary_color: { type: String, default: "#1d4ed8" },
      accent_color: { type: String, default: "#0f172a" },
      stamp_label: { type: String, default: "Official eStamp" },
      email_header_text: { type: String, default: "Verified document update" },
      email_footer: { type: String, default: "Sent securely by eStamp Pro" },
      verification_tagline: { type: String, default: "Digital verification you can trust" },
      custom_watermark_text: { type: String, default: "" },
      support_email: { type: String, default: "" },
      website_url: { type: String, default: "" },
    },

    created_at: { type: Date, default: Date.now },
  },
  { minimize: false }
);

export default mongoose.model("Organization", OrganizationSchema);
