import mongoose from "mongoose";

const AnalyticsReportRunSchema = new mongoose.Schema(
  {
    kind: {
      type: String,
      enum: ["scheduled", "manual"],
      default: "scheduled",
    },

    org_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Organization",
      index: true,
      required: true,
    },

    org_name: {
      type: String,
      default: "",
    },

    status: {
      type: String,
      enum: ["started", "sent", "skipped", "failed"],
      default: "started",
      index: true,
    },

    reason: {
      type: String,
      default: "",
    },

    recipients: {
      type: [String],
      default: [],
    },

    subject: {
      type: String,
      default: "",
    },

    range_days: {
      type: Number,
      default: 7,
    },

    started_at: {
      type: Date,
      default: Date.now,
      index: true,
    },

    finished_at: {
      type: Date,
      default: null,
    },

    error_message: {
      type: String,
      default: "",
    },

    meta: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
  },
  {
    timestamps: true,
    minimize: false,
  }
);

export default mongoose.models.AnalyticsReportRun ||
  mongoose.model("AnalyticsReportRun", AnalyticsReportRunSchema);