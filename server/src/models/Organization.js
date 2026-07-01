import mongoose from "mongoose";

const OrganizationSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    slug: { type: String, unique: true, index: true, required: true },
    owner_user_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },
    owner_email: {
      type: String,
      default: "",
      index: true,
    },
    plan: {
      type: String,
      enum: ["free", "pro", "business"],
      default: "free",
    },

    suspended: {
  type: Boolean,
  default: false,
},

suspended_at: {
  type: Date,
  default: null,
},

    billing: {
      provider: { type: String, default: "" },
customerId: { type: String, default: "" },
subscriptionId: { type: String, default: "" },
lemonSqueezyCustomerId: { type: String, default: "" },
lemonSqueezySubscriptionId: { type: String, default: "" },
lemonSqueezyVariantId: { type: String, default: "" },
fastSpringCustomerId: { type: String, default: "" },
fastSpringSubscriptionId: { type: String, default: "" },
fastSpringProductPath: { type: String, default: "" },
fastSpringAccountId: { type: String, default: "" },
fastSpringOrderId: { type: String, default: "" },
      stripe_customer_id: { type: String, default: "" },
      stripe_subscription_id: { type: String, default: "" },
      status: { type: String, default: "inactive" },
      stripe_price_id: { type: String, default: "" },
      subscription_status: { type: String, default: "inactive" },
      current_period_end: { type: Date, default: null },
      cancel_at_period_end: { type: Boolean, default: false },
      last_checkout_session_id: { type: String, default: "" },
      last_event_id: { type: String, default: "" },

    },


billingProvider: { type: String, default: "" },
billingStatus: { type: String, default: "" },
subscriptionStatus: { type: String, default: "" },
subscriptionId: { type: String, default: "" },
customerId: { type: String, default: "" },
lemonSqueezyCustomerId: { type: String, default: "" },
lemonSqueezySubscriptionId: { type: String, default: "" },
lemonSqueezyVariantId: { type: String, default: "" },
lemonSqueezyTestMode: { type: Boolean, default: false },
renewalDate: { type: Date, default: null },
cancelAtPeriodEnd: { type: Boolean, default: false },
upgradedAt: { type: Date, default: null },
fastSpringCustomerId: { type: String, default: "" },
fastSpringSubscriptionId: { type: String, default: "" },
fastSpringProductPath: { type: String, default: "" },
fastSpringAccountId: { type: String, default: "" },
fastSpringOrderId: { type: String, default: "" },

    usage: {
      documentsThisMonth: { type: Number, default: 0 },
      stampsThisMonth: { type: Number, default: 0 },
      storageUsedMB: { type: Number, default: 0 },
      resetAt: {
        type: Date,
        default: () => new Date(new Date().getFullYear(), new Date().getMonth(), 1),
      },
    },

    branding: {
      logo_url: { type: String, default: "" },
      primary_color: { type: String, default: "#1d4ed8" },
      accent_color: { type: String, default: "#0f172a" },
      stamp_label: { type: String, default: "Official Organization Stamp" },
      email_footer: { type: String, default: "" },
      watermark_text: { type: String, default: "" },
      verification_tagline: { type: String, default: "Trusted digital stamp verification" },
      email_header_text: { type: String, default: "A document has been shared with you for verification." },
      support_email: { type: String, default: "" },
      website_url: { type: String, default: "" },
      certificate_stamp_id: { type: String, default: "" },
certificate_signature_id: { type: String, default: "" },
certificate_signatory_name: { type: String, default: "" },
certificate_signatory_title: { type: String, default: "" },
    },

    reports: {
      analytics_reports_enabled: { type: Boolean, default: false },
      analytics_report_frequency: { type: String, default: "weekly" },
      analytics_report_day: { type: String, default: "monday" },
      analytics_recipients: { type: [String], default: [] },
      last_analytics_report_sent_at: { type: Date, default: null },
    },
   report_settings: {
     analytics_reports_enabled: { type: Boolean, default: false },
     analytics_report_frequency: { type: String, default: "weekly" },
     analytics_report_day: { type: String, default: "monday" },
     analytics_recipients: { type: [String], default: [] },
     last_analytics_report_sent_at: { type: Date, default: null },
    },
    email_settings: {
      provider: { type: String, default: "resend" },
      from_name: { type: String, default: "" },
      reply_to: { type: String, default: "" },
      sender_domain: { type: String, default: "" },
      domain_verified: { type: Boolean, default: null },
      last_delivery_status: { type: String, default: "idle" },
      last_error_code: { type: String, default: "" },
      last_error_message: { type: String, default: "" },
      last_test_sent_at: { type: Date, default: null },
      last_sent_at: { type: Date, default: null },
    },

    created_at: { type: Date, default: Date.now },
  },
  { minimize: false }
);

export default mongoose.model("Organization", OrganizationSchema);
