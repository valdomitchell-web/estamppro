
import mongoose from 'mongoose';

const OrgSchema = new mongoose.Schema({
  name: String,
  owner_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  tier: { type: String, enum: ['free','pro','enterprise'], default: 'free' },
  created_at: { type: Date, default: Date.now }
});

export default mongoose.model('Org', OrgSchema);
