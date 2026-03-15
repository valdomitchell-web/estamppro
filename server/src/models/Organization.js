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
    },

    created_at: { type: Date, default: Date.now },
  },
  { minimize: false }
);

export default mongoose.model("Organization", OrganizationSchema);