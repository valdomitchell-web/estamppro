import mongoose from 'mongoose';

const AuditSchema = new mongoose.Schema({
  org_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Org' },
  stamp_id: { type: mongoose.Schema.Types.ObjectId, ref: 'StampDesign' },
  document_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Document' },

  // NEW (so the table has data)
  action:   { type: String,  default: '' },
  ok:       { type: Boolean, default: true },
  target:   { type: String,  default: '' },
  meta:     { type: Object,  default: {} },

  page: Number,
  x: Number, y: Number, scale: Number, opacity: Number,
  timestamp: { type: Date, default: Date.now },
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  device_fingerprint: String,
  verification: Object
}, { timestamps: true });

export default mongoose.model('Audit', AuditSchema);
