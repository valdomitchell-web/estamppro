import mongoose from "mongoose";

const ApiKeySchema = new mongoose.Schema({
  org_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Organization",
    required: true,
    index: true,
    prefix: rawKey.slice(0, 8),
    masked: maskApiKey(rawKey),
  },

  name: { type: String, default: "Default Key" },

  key_hash: { type: String, required: true },

  last_used_at: Date,

  created_by: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
  },

  created_at: { type: Date, default: Date.now },
});

export default mongoose.model("ApiKey", ApiKeySchema);