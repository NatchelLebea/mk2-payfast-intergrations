require("dotenv").config();
const express   = require("express");
const crypto    = require("crypto");
const cors      = require("cors");
const axios     = require("axios");
const admin     = require("firebase-admin");
const rateLimit = require("express-rate-limit");
const helmet    = require("helmet");
const nodemailer = require("nodemailer");

// ─── Firebase Admin ───────────────────────────────────────────────────────────
let serviceAccount;

if (process.env.FIREBASE_KEY) {
  serviceAccount = JSON.parse(process.env.FIREBASE_KEY);

  // 🔥 CRITICAL FIX
  serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');

} else {
  throw new Error("Missing FIREBASE_KEY env variable");
}

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DATABASE_URL,
});
const db = admin.database();

// ─── App ──────────────────────────────────────────────────────────────────────
const app = express();
app.use(helmet());

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",").map(o => o.trim()).filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    if (!origin && process.env.NODE_ENV !== "production") return cb(null, true);
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    cb(new Error(`CORS blocked: ${origin}`));
  },
  methods: ["GET", "POST", "PUT"],
  allowedHeaders: ["Content-Type"],
}));

app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: "10kb" }));

// ─── Rate limiters ────────────────────────────────────────────────────────────
const signLimiter   = rateLimit({ windowMs: 60_000, max: 20, message: { error: "Too many requests." } });
const cancelLimiter = rateLimit({ windowMs: 60_000, max: 5,  message: { error: "Too many requests." } });

// ─── Config ───────────────────────────────────────────────────────────────────
const {
  PAYFAST_MERCHANT_ID,
  PAYFAST_MERCHANT_KEY,
  PAYFAST_PASSPHRASE,
  BASE_URL,
  FRONTEND_URL,
  NODE_ENV,
} = process.env;

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

process.on("uncaughtException", err => {
  console.error("💥 Uncaught Exception:", err);
});

process.on("unhandledRejection", err => {
  console.error("💥 Unhandled Rejection:", err);
});

async function sendEmail(to, subject, text) {
  try {
    await transporter.sendMail({
      from: `"MK2 Fitness" <${process.env.EMAIL_USER}>`,
      to,
      subject,
      text,
    });
    console.log("📧 Email sent to:", to);
  } catch (err) {
    console.error("Email error:", err.message);
  }
}

const IS_LIVE      = NODE_ENV === "production";
const PAYFAST_HOST = "https://www.payfast.co.za"; // LIVE only

const PAYFAST_IPS = [
  "197.97.145.144", "197.97.145.145", "197.97.145.146", "197.97.145.147",
  "41.74.179.194",  "41.74.179.195",  "41.74.179.196",  "41.74.179.197",
];

// ─── Signature ────────────────────────────────────────────────────────────────
function generateSignature(data, passphrase = "") {
  const pfData = { ...data };

  if (passphrase && passphrase.trim() !== "") {
    pfData.passphrase = passphrase.trim();
  }

  const str = Object.keys(pfData)
    .sort()
    .map(k =>
      `${k}=${encodeURIComponent(String(pfData[k])).replace(/%20/g, "+")}`
    )
    .join("&");

  console.log("🔐 SIGN STRING:\n", str);

  return crypto.createHash("md5").update(str).digest("hex");
}

// ─── Find user ────────────────────────────────────────────────────────────────
async function findUserRef(userId, email) {
  if (userId) {
    const snap = await db.ref(`mk2_users/${userId}`).get();
    if (snap.exists()) return { ref: db.ref(`mk2_users/${userId}`), key: userId };
  }
  if (email) {
    const snap = await db.ref("mk2_users")
      .orderByChild("email").equalTo(email).limitToFirst(1).get();
    if (snap.exists()) {
      const key = Object.keys(snap.val())[0];
      return { ref: db.ref(`mk2_users/${key}`), key };
    }
  }
  return null;
}

// ─── POST /api/payfast-sign ───────────────────────────────────────────────────
app.post("/api/payfast-sign", signLimiter, (req, res) => {
  try {
    const {
      email_address, name_first, name_last,
      item_name, amount, recurring_amount,
      frequency, custom_str1, custom_str2, custom_str3,
    } = req.body;

    if (!item_name || !amount || !frequency || !email_address || !custom_str1) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    const parsedAmount = parseFloat(amount);
    if (isNaN(parsedAmount) || parsedAmount <= 0) {
      return res.status(400).json({ error: "Invalid amount" });
    }
    if (!["3", "6"].includes(String(frequency))) {
      return res.status(400).json({ error: "Invalid frequency" });
    }

    const frontendBase = (FRONTEND_URL || "https://gym-pro-20ee6.web.app").replace(/\/$/, "");

const params = {
  merchant_id: PAYFAST_MERCHANT_ID,
  merchant_key: PAYFAST_MERCHANT_KEY,

  return_url: `${frontendBase}/membership`,
  cancel_url: `${frontendBase}/membership`,
  notify_url: `${BASE_URL}/api/payfast-itn`,

  email_address,
  item_name,
  amount: parsedAmount.toFixed(2),

  subscription_type: "1",
  billing_date: new Date().toISOString().split("T")[0],
  recurring_amount: parseFloat(recurring_amount || amount).toFixed(2),
  frequency: String(frequency),
  cycles: "0",

  custom_str1,

  ...(name_first && { name_first }),
  ...(name_last && { name_last }),
  ...(custom_str2 && { custom_str2 }),
  ...(custom_str3 && { custom_str3 }),
};

console.log("FINAL PARAMS:", params);
    const signature = generateSignature(params, PAYFAST_PASSPHRASE);
const qs = Object.keys(params)
  .sort()
  .map(k =>
    `${k}=${encodeURIComponent(String(params[k])).replace(/%20/g, "+")}`
  )
  .join("&");

    console.log("✅ Signed URL generated for:", email_address, "→", item_name);
    res.json({ url: `${PAYFAST_HOST}/eng/process?${qs}&signature=${signature}` });

  } catch (err) {
    console.error("Sign error:", err);
    res.status(500).json({ error: "Failed to sign request" });
  }
});

// ─── POST /api/payfast-itn ────────────────────────────────────────────────────
app.post("/api/payfast-itn", async (req, res) => {
  res.sendStatus(200); // Always respond immediately

  const data = req.body;
  console.log("📩 ITN received:", JSON.stringify(data));

  try {
    // Security 1: IP whitelist
    const callerIp = (
      req.headers["x-forwarded-for"]?.split(",")[0] ||
      req.socket.remoteAddress || ""
    ).trim();
    if (IS_LIVE && !PAYFAST_IPS.includes(callerIp)) {
      console.error(`ITN blocked — bad IP: ${callerIp}`);
      return;
    }

    // Security 2: Signature
    const received = { ...data };
    const theirSig = received.signature;
    delete received.signature;
    const ourSig = generateSignature(received, PAYFAST_PASSPHRASE);
    if (ourSig !== theirSig) {
      console.error(`ITN blocked — signature mismatch`);
      return;
    }

    // Security 3: Confirm with PayFast
    const confirmBody = Object.entries(data)
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
      .join("&");
    const confirmRes = await axios.post(
      `${PAYFAST_HOST}/eng/query/validate`,
      confirmBody,
      { headers: { "Content-Type": "application/x-www-form-urlencoded" }, timeout: 8000 }
    );
    if (confirmRes.data?.trim() !== "VALID") {
      console.error("ITN blocked — PayFast validation failed:", confirmRes.data);
      return;
    }

    // Parse
    const status  = data.payment_status;
    const userId  = data.custom_str1;
    const tierId  = data.custom_str2 || inferTier(data.item_name);
    const billing = data.custom_str3 || "monthly";
    const token   = data.token;
    const email   = data.email_address;

    const found = await findUserRef(userId, email);
    if (!found) {
      console.error(`ITN: user not found — userId=${userId}, email=${email}`);
      return;
    }

    const { ref: userRef, key: userKey } = found;
    const userSnap = await userRef.get();
    const userData = userSnap.val() || {};

    // ── COMPLETE ──────────────────────────────────────────────────────────────
    if (status === "COMPLETE") {
      const isNewGold   = tierId === "gold"   && userData.membership !== "gold";
      const isNewSilver = tierId === "silver" && userData.membership !== "silver";

      const update = {
        membership:          tierId,
        membershipBilling:   billing,         // "monthly" or "yearly"
        membershipSince:     userData.membershipSince || Date.now(),
        membershipUpdatedAt: Date.now(),
        subscriptionToken:   token || null,   // needed for cancellation
        lastPaymentId:       data.pf_payment_id,
        lastPaymentAmount:   data.amount_gross,
        cancelledAt:         null,
        membershipFailedAt:  null,
      };

      // Gold: 10 free class credits on first activation
      if (isNewGold) {
        update.classCredits = (userData.classCredits || 0) + 10;
        update.aiQuota = {
          remaining: 200,
          resetDate: nextMonthFirst(),
        };
      }

      // Silver: AI quota on first activation
      if (isNewSilver) {
        update.aiQuota = {
          remaining: 50,
          resetDate: nextMonthFirst(),
        };
      }

      await userRef.update(update);

      // Log payment history
      await db.ref(`paymentHistory/${userKey}`).push({
        event:     "complete",
        tier:      tierId,
        billing,
        amount:    data.amount_gross,
        paymentId: data.pf_payment_id,
        token:     token || null,
        date:      Date.now(),
      });

      console.log(`✅ COMPLETE: ${userId || email} → ${tierId} (${billing}) R${data.amount_gross}`);

           await sendEmail(
  email,
  "✅ Payment Successful - MK2 Membership",
  `Hi,

Your payment was successful 🎉

Plan: ${tierId.toUpperCase()}
Billing: ${billing}
Amount: R${data.amount_gross}

Welcome to MK2 Fitness!

- MK2 Team`
);


    // ── CANCELLED ─────────────────────────────────────────────────────────────
    } else if (status === "CANCELLED") {
      await userRef.update({
        membership:          "basic",
        membershipBilling:   null,
        subscriptionToken:   null,
        membershipUpdatedAt: Date.now(),
        cancelledAt:         Date.now(),
        aiQuota:             null,
      });
      await db.ref(`paymentHistory/${userKey}`).push({
        event: "cancelled",
        date:  Date.now(),
      });
      console.log(`⚠️ CANCELLED: ${userId || email} → basic`);

      await sendEmail(
  email,
  "❌ Subscription Cancelled - MK2 Membership",
  `Hi,

Your subscription has been cancelled.

You are now on the Basic plan.

We're sorry to see you go — you're always welcome back!

- MK2 Team`
);

    // ── FAILED (card declined etc) ────────────────────────────────────────────
    } else if (status === "FAILED") {
      // Log the failure — PayFast will retry automatically
      // If too many failures, PayFast sends CANCELLED
      await userRef.update({ membershipFailedAt: Date.now() });
      await db.ref(`paymentHistory/${userKey}`).push({
        event:     "failed",
        paymentId: data.pf_payment_id || null,
        date:      Date.now(),
      });
      console.log(`❌ FAILED: ${userId || email} — PayFast will retry`);

      await sendEmail(
  email,
  "⚠️ Payment Failed - MK2 Membership",
  `Hi,

Your recent payment attempt failed.

PayFast will retry automatically, but please ensure:
- Your card has sufficient funds
- Your payment method is valid

If the issue continues, your subscription may be cancelled.

- MK2 Team`
);

    } else {
      console.log(`ℹ️ ITN status: ${status}`);
    }

  } catch (err) {
    console.error("ITN error:", err);
  }
});

// ─── POST /api/cancel-subscription ───────────────────────────────────────────
app.post("/api/cancel-subscription", cancelLimiter, async (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: "userId required" });

  try {
    const snap = await db.ref(`mk2_users/${userId}`).get();
    if (!snap.exists()) return res.status(404).json({ error: "User not found" });

    const userData = snap.val();

    if (!userData.subscriptionToken) {
      // No token — just downgrade locally
      await db.ref(`mk2_users/${userId}`).update({
        membership:          "basic",
        membershipBilling:   null,
        subscriptionToken:   null,
        membershipUpdatedAt: Date.now(),
        cancelledAt:         Date.now(),
        aiQuota:             null,
      });
      await db.ref(`paymentHistory/${userId}`).push({
        event: "cancelled_via_app",
        date:  Date.now(),
      });
await sendEmail(
  userData.email,
  "❌ Subscription Cancelled",
  `Hi,

Your subscription has been successfully cancelled via the app.

You are now on the Basic plan.

- MK2 Team`
);

      return res.json({ success: true });
    }

    if (userData.membership === "basic") {
      return res.status(400).json({ error: "Already on basic plan" });
    }

    // Call PayFast API to cancel subscription
    const timestamp = new Date().toISOString();
    const version   = "v1";
    const apiParams = {
      "merchant-id": PAYFAST_MERCHANT_ID,
      passphrase:    PAYFAST_PASSPHRASE,
      timestamp,
      version,
    };
    const apiSigStr = Object.keys(apiParams)
      .sort()
      .map(k => `${k}=${encodeURIComponent(String(apiParams[k]))}`)
      .join("&");
    const apiSig = crypto.createHash("md5").update(apiSigStr).digest("hex");

    try {
      await axios.put(
        `${PAYFAST_HOST}/api/subscriptions/${userData.subscriptionToken}/cancel`,
        {},
        {
          headers: {
            "merchant-id":  PAYFAST_MERCHANT_ID,
            "version":      version,
            "timestamp":    timestamp,
            "signature":    apiSig,
            "Content-Type": "application/json",
          },
          timeout: 8000,
        }
      );
    } catch (pfErr) {
      console.error("PayFast cancel API error:", pfErr.response?.data || pfErr.message);
      // Continue anyway — still downgrade locally
    }

    // Downgrade in DB regardless
    await db.ref(`mk2_users/${userId}`).update({
      membership:          "basic",
      membershipBilling:   null,
      subscriptionToken:   null,
      membershipUpdatedAt: Date.now(),
      cancelledAt:         Date.now(),
      aiQuota:             null,
    });
    await db.ref(`paymentHistory/${userId}`).push({
      event: "cancelled_via_app",
      date:  Date.now(),
    });

    res.json({ success: true });

  } catch (err) {
    console.error("Cancel error:", err.message);
    res.status(500).json({ error: "Cancellation failed" });
  }
});

// ─── Helpers ──────────────────────────────────────────────────────────────────
function inferTier(itemName = "") {
  const n = itemName.toLowerCase();
  if (n.includes("gold"))   return "gold";
  if (n.includes("silver")) return "silver";
  return "basic";
}

function nextMonthFirst() {
  const d = new Date();
  d.setMonth(d.getMonth() + 1);
  d.setDate(1);
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}

// ─── Health check ─────────────────────────────────────────────────────────────
app.get("/health", (_, res) => res.json({
  ok:   true,
  mode: IS_LIVE ? "live" : "dev",
  base: BASE_URL,
}));


// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 5000;
console.log("PORT FROM ENV:", process.env.PORT);

app.get("/", (_, res) => {
  res.send("Server is running 🚀");
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`\n🚀 Server on port ${PORT} [${IS_LIVE ? "LIVE" : "dev"}]`);
  console.log(`🔔 ITN:    ${BASE_URL}/api/payfast-itn`);
  console.log(`🔑 Sign:   ${BASE_URL}/api/payfast-sign`);
  console.log(`❌ Cancel: ${BASE_URL}/api/cancel-subscription\n`);
});