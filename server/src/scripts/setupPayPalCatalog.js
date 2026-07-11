import "dotenv/config";
import crypto from "crypto";

const env = String(process.env.PAYPAL_ENV || "sandbox").trim().toLowerCase();
const clientId = String(process.env.PAYPAL_CLIENT_ID || "").trim();
const clientSecret = String(process.env.PAYPAL_CLIENT_SECRET || "").trim();

const apiBase =
  env === "live"
    ? "https://api-m.paypal.com"
    : "https://api-m.sandbox.paypal.com";

const proPrice = String(process.env.PAYPAL_PRO_PRICE || "19.00");
const businessPrice = String(process.env.PAYPAL_BUSINESS_PRICE || "49.00");
const currency = String(process.env.PAYPAL_CURRENCY || "USD").toUpperCase();

if (!clientId || !clientSecret) {
  throw new Error("PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET are required.");
}

async function readResponse(response) {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return { raw: text };
  }
}

async function accessToken() {
  const basic = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");

  const response = await fetch(`${apiBase}/v1/oauth2/token`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${basic}`,
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "grant_type=client_credentials",
  });

  const data = await readResponse(response);
  if (!response.ok) throw new Error(JSON.stringify(data));
  return data.access_token;
}

async function paypal(path, options = {}) {
  const token = await accessToken();

  const response = await fetch(`${apiBase}${path}`, {
    ...options,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });

  const data = await readResponse(response);

  if (!response.ok) {
    throw new Error(
      `${options.method || "GET"} ${path} failed: ${JSON.stringify(data)}`
    );
  }

  return data;
}

async function createProduct() {
  return paypal("/v1/catalogs/products", {
    method: "POST",
    headers: {
      "PayPal-Request-Id": crypto.randomUUID(),
      Prefer: "return=representation",
    },
    body: JSON.stringify({
      name: "eStamp Pro",
      description:
        "Secure digital document stamping, verification, analytics, and organization tools.",
      type: "SERVICE",
      category: "SOFTWARE",
    }),
  });
}

async function createPlan(productId, name, price) {
  return paypal("/v1/billing/plans", {
    method: "POST",
    headers: {
      "PayPal-Request-Id": crypto.randomUUID(),
      Prefer: "return=representation",
    },
    body: JSON.stringify({
      product_id: productId,
      name,
      description: `${name} monthly subscription`,
      status: "ACTIVE",
      billing_cycles: [
        {
          frequency: {
            interval_unit: "MONTH",
            interval_count: 1,
          },
          tenure_type: "REGULAR",
          sequence: 1,
          total_cycles: 0,
          pricing_scheme: {
            fixed_price: {
              value: price,
              currency_code: currency,
            },
          },
        },
      ],
      payment_preferences: {
        auto_bill_outstanding: true,
        setup_fee: {
          value: "0",
          currency_code: currency,
        },
        setup_fee_failure_action: "CONTINUE",
        payment_failure_threshold: 2,
      },
      taxes: {
        percentage: "0",
        inclusive: false,
      },
    }),
  });
}

console.log(`Creating PayPal catalog in ${env.toUpperCase()}...`);

const product = await createProduct();
const pro = await createPlan(product.id, "eStamp Pro Pro", proPrice);
const business = await createPlan(
  product.id,
  "eStamp Pro Business",
  businessPrice
);

console.log("");
console.log("Created successfully.");
console.log(`PAYPAL_PRODUCT_ID=${product.id}`);
console.log(`PAYPAL_PRO_PLAN_ID=${pro.id}`);
console.log(`PAYPAL_BUSINESS_PLAN_ID=${business.id}`);
console.log("");
console.log("Add those three values to Render, then redeploy.");
