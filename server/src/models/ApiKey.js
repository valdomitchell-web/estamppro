import mongoose from "mongoose";

const ApiKeySchema = new mongoose.Schema({
  org_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Organization",
    required: true,
    index: true,
  },

  name: { type: String, default: "Default Key" },

  // 🔒 Secure storage
  key_hash: { type: String, required: true },

  // ✅ NEW: display-safe fields
  prefix: { type: String, default: "" },     // first 8 chars
  masked: { type: String, default: "" },     // esk_xxxx****xxxx

  last_used_at: Date,

  created_by: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
  },

  created_at: { type: Date, default: Date.now },
  
revoked: {
    type: Boolean,
    default: false,
},

revoked_at: Date,

});

export default mongoose.model("ApiKey", ApiKeySchema);