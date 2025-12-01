
import mongoose from 'mongoose';

const DocumentSchema = new mongoose.Schema({
  org_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Org' },
  filename: String,
  path: String,                  // local disk path (disk mode)
  s3_key: String,                // S3 object key (S3 mode)
  s3_url: String,                // optional public URL (if bucket allows)
  mime: String,
  pages: Number,
  sha256: String,
  uploaded_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  created_at: { type: Date, default: Date.now }
});

export default mongoose.model('Document', DocumentSchema);
