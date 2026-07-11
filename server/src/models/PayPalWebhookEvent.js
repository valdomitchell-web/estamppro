import mongoose from "mongoose";

const PayPalWebhookEventSchema = new mongoose.Schema(
  {
    event_id: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    event_type: {
      type: String,
      required: true,
      index: true,
    },
    status: {
      type: String,
      enum: ["processing", "processed", "failed"],
      default: "processing",
      index: true,
    },
    result: {
      type: mongoose.Schema.Types.Mixed,
      default: null,
    },
    error: {
      type: mongoose.Schema.Types.Mixed,
      default: null,
    },
    received_at: {
      type: Date,
      default: Date.now,
    },
    processed_at: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
    collection: "paypal_webhook_events",
  }
);

export default mongoose.models.PayPalWebhookEvent ||
  mongoose.model("PayPalWebhookEvent", PayPalWebhookEventSchema);
