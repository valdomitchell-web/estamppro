import mongoose from "mongoose";

const BackupCodeSchema = new mongoose.Schema(
  {
    code_hash: String,
    used_at: Date,
  },
  { _id: false }
);

const RefreshTokenSchema = new mongoose.Schema(
  {
    token_hash: String,
    lookup_hash: { type: String, index: true },
    created_at: { type: Date, default: Date.now },
    expires_at: Date,
    revoked_at: Date,
    device: String,
  },
  { _id: false }
);

const TrustedDeviceSchema = new mongoose.Schema(
  {
    token_hash: String,
    label: String,
    created_at: { type: Date, default: Date.now },
    last_ip: String,
    last_ua: String,
    expires_at: Date,
    revoked_at: Date,
  },
  { _id: false }
);

const UserSchema = new mongoose.Schema({
  email: { type: String, unique: true, index: true },
  password_hash: String,
  
  reset_password_token_hash: String,
  reset_password_expires_at: Date,

  org_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Organization",
    default: null,
    index: true,
  },

  role: {
    type: String,
    enum: ["owner", "admin", "user", "verifier"],
    default: "owner",
  },

  plan: {
    type: String,
    enum: ["free", "pro", "business"],
    default: "free",
  },

  password_reset_token_hash: {
  type: String,
  default: null,
},

password_reset_expires_at: {
  type: Date,
  default: null,
},

platform_role: {
  type: String,
  enum: ["owner", "staff", "user"],
  default: "user",
},


  invite_pending: { type: Boolean, default: false },

  mfa_enabled: { type: Boolean, default: false },
  mfa_secret: String,

  backup_codes: [BackupCodeSchema],
  refresh_tokens: [RefreshTokenSchema],
  trusted_devices: [TrustedDeviceSchema],

  created_at: { type: Date, default: Date.now },
});

export default mongoose.model("User", UserSchema);