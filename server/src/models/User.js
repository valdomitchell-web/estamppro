import mongoose from 'mongoose';

const BackupCodeSchema = new mongoose.Schema({
  code_hash: String,
  used_at: Date
}, { _id: false });

const RefreshTokenSchema = new mongoose.Schema({
  token_hash: String,       // argon2 hash of random token
  created_at: { type: Date, default: Date.now },
  expires_at: Date,
  revoked_at: Date,
  device: String
}, { _id: false });

const TrustedDeviceSchema = new mongoose.Schema({
  token_hash: String,          // argon2 hash of random device token
  label: String,               // e.g., "Chrome on Windows"
  created_at: { type: Date, default: Date.now },
  last_ip: String,
  last_ua: String,
  expires_at: Date,
  revoked_at: Date
}, { _id: false });

const UserSchema = new mongoose.Schema({
  email: { type: String, unique: true, index: true },
  password_hash: String,
  mfa_enabled: { type: Boolean, default: false },
  mfa_secret: String,
  backup_codes: [BackupCodeSchema],
  refresh_tokens: [RefreshTokenSchema],
  trusted_devices: [TrustedDeviceSchema],        // <--- NEW
  created_at: { type: Date, default: Date.now }
});


export default mongoose.model('User', UserSchema);
