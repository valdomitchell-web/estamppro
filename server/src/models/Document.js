
import mongoose from 'mongoose';

const DocumentSchema = new mongoose.Schema({
  org_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Org' },
  filename: String,
  path: String,
  mime: String,
  pages: Number,
  sha256: String,
  uploaded_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  created_at: { type: Date, default: Date.now }
});

export default mongoose.model('Document', DocumentSchema);
