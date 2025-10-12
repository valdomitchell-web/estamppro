
import mongoose from 'mongoose';

const StampDesignSchema = new mongoose.Schema({
  org_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Org' },
  name: String,
  image_path: String,
  width: Number,
  height: Number,
  secret: {
    salt_b64: String,
    iv_b64: String,
    tag_b64: String,
    enc_key_b64: String,
    kdf: { type: String, default: 'scrypt' },
    N: { type: Number, default: 16384 },
    r: { type: Number, default: 8 },
    p: { type: Number, default: 1 }
  },
  created_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  created_at: { type: Date, default: Date.now }
});

export default mongoose.model('StampDesign', StampDesignSchema);
