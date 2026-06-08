require("dotenv").config();
const express   = require("express");
const crypto    = require("crypto");
const cors      = require("cors");
const axios     = require("axios");
const admin     = require("firebase-admin");
const rateLimit = require("express-rate-limit");
const helmet    = require("helmet");
const nodemailer = require("nodemailer");

// ─── Firebase Admin (initialised asynchronously after server starts) ──────────
let db = null;
let firebaseReady = false;

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

// ─── PayFast subscription cancel helper ──────────────────────────────────────
async function cancelPayFastSubscription(token) {
  const timestamp = new Date().toISOString();
  const version   = "v1";
  const sigParams = {
    "merchant-id": PAYFAST_MERCHANT_ID,
    passphrase:    PAYFAST_PASSPHRASE,
    timestamp,
    version,
  };
  const sigStr = Object.keys(sigParams)
    .sort()
    .map(k => `${k}=${encodeURIComponent(sigParams[k])}`)
    .join("&");
  const signature = crypto.createHash("md5").update(sigStr).digest("hex");

  await axios.put(
    `${PAYFAST_HOST}/api/subscriptions/${token}/cancel`,
    {},
    {
      headers: {
        "merchant-id":  PAYFAST_MERCHANT_ID,
        version,
        timestamp,
        signature,
        "Content-Type": "application/json",
      },
      timeout: 8000,
    }
  );
}

// ─── Firebase readiness guard ─────────────────────────────────────────────────
function requireFirebase(res) {
  if (!firebaseReady || !db) {
    res.status(503).json({ error: "Service temporarily unavailable — database not ready yet" });
    return false;
  }
  return true;
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
app.post("/api/payfast-sign", signLimiter, async (req, res) => {
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

    let finalAmount = parsedAmount;

    // ── Pro-rata credit + cancel old sub if upgrading ─────────────────────────
    if (db && custom_str1) {
      const userSnap = await db.ref(`mk2_users/${custom_str1}`).get();

      if (userSnap.exists()) {
        const user = userSnap.val();
        const isUpgrade = user.membership && user.membership !== "basic" && user.membership !== custom_str2;

        if (isUpgrade) {
          // 1. Calculate pro-rata credit
          const now          = Date.now();
          const start        = user.membershipSince || now;
          const totalDays    = (custom_str3 === "yearly") ? 365 : 30;
          const currentPrice =
            user.membership === "silver"
              ? (custom_str3 === "yearly" ? 228 : 24)
              : (custom_str3 === "yearly" ? 588 : 54);

          const usedDays      = Math.floor((now - start) / (1000 * 60 * 60 * 24));
          const remainingDays = Math.max(totalDays - usedDays, 0);
          const credit        = (remainingDays / totalDays) * currentPrice;

          finalAmount = Math.max(parsedAmount - credit, 5);
          console.log(`💰 Credit: R${credit.toFixed(2)} → Final: R${finalAmount.toFixed(2)}`);

          // 2. Cancel old subscription NOW before creating the new one
          if (user.subscriptionToken) {
            try {
              await cancelPayFastSubscription(user.subscriptionToken);
              console.log("✅ Old subscription cancelled before upgrade");
            } catch (err) {
              console.error("⚠️ Could not cancel old sub (continuing anyway):", err.message);
            }
          }
        }
      }
    }

    const frontendBase = (FRONTEND_URL || "https://gym-pro-20ee6.web.app").replace(/\/$/, "");

    const params = {
      merchant_id:       PAYFAST_MERCHANT_ID,
      merchant_key:      PAYFAST_MERCHANT_KEY,
      return_url:        `${frontendBase}/membership`,
      cancel_url:        `${frontendBase}/membership`,
      notify_url:        `${BASE_URL}/api/payfast-itn`,
      email_address,
      item_name,
      amount:            finalAmount.toFixed(2),
      subscription_type: "1",
      billing_date:      new Date().toISOString().split("T")[0],
      recurring_amount:  parseFloat(recurring_amount || amount).toFixed(2),
      frequency:         String(frequency),
      cycles:            "0",
      custom_str1,
      ...(name_first  && { name_first }),
      ...(name_last   && { name_last }),
      ...(custom_str2 && { custom_str2 }),
      ...(custom_str3 && { custom_str3 }),
    };

    console.log("FINAL PARAMS:", params);

    const signature = generateSignature(params, PAYFAST_PASSPHRASE);
    const qs = Object.keys(params)
      .sort()
      .map(k => `${k}=${encodeURIComponent(String(params[k])).replace(/%20/g, "+")}`)
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

  // Deduplicate
  const paymentId = data.pf_payment_id;
  if (paymentId) {
    const existing = await db.ref(`processedPayments/${paymentId}`).get();
    if (existing.exists()) {
      console.log("⚠️ Duplicate ITN ignored:", paymentId);
      return;
    }
    await db.ref(`processedPayments/${paymentId}`).set(true);
  }

  console.log("📩 ITN received:", JSON.stringify(data));

  if (!firebaseReady || !db) {
    console.error("ITN received but Firebase is not ready — skipping DB update");
    return;
  }

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
    const received  = { ...data };
    const theirSig  = received.signature;
    delete received.signature;
    const ourSig    = generateSignature(received, PAYFAST_PASSPHRASE);
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
    const userData  = userSnap.val() || {};

    // ── COMPLETE ──────────────────────────────────────────────────────────────
    if (status === "COMPLETE") {
      const isNewGold   = tierId === "gold"   && userData.membership !== "gold";
      const isNewSilver = tierId === "silver" && userData.membership !== "silver";

      const update = {
        membership:               tierId,
        membershipBilling:        billing,
        membershipSince:          Date.now(),
        membershipUpdatedAt:      Date.now(),
        subscriptionToken:        token || null,
        lastPaymentId:            data.pf_payment_id,
        lastPaymentAmount:        data.amount_gross,
        cancelledAt:              null,
        membershipFailedAt:       null,
        cancellationPending:      false,
        cancellationRequestedAt:  null,
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
        `Hi,\n\nYour payment was successful 🎉\n\nPlan: ${tierId.toUpperCase()}\nBilling: ${billing}\nAmount: R${data.amount_gross}\n\nWelcome to MK2 Fitness!\n\n- MK2 Team`
      );

    // ── CANCELLED — fires at end of billing period ────────────────────────────
    } else if (status === "CANCELLED") {
      await userRef.update({
        membership:               "basic",
        membershipBilling:        null,
        subscriptionToken:        null,
        membershipUpdatedAt:      Date.now(),
        cancelledAt:              Date.now(),
        aiQuota:                  null,
        cancellationPending:      false,
        cancellationRequestedAt:  null,
      });

      await db.ref(`paymentHistory/${userKey}`).push({
        event: "cancelled",
        date:  Date.now(),
      });

      console.log(`⚠️ CANCELLED: ${userId || email} → basic`);

      await sendEmail(
        email,
        "❌ Subscription Cancelled - MK2 Membership",
        `Hi,\n\nYour subscription has now ended and you have been moved to the Basic plan.\n\nWe're sorry to see you go — you're always welcome back!\n\n- MK2 Team`
      );

    // ── FAILED (card declined etc) ────────────────────────────────────────────
    } else if (status === "FAILED") {
      // Do NOT downgrade — PayFast retries automatically.
      // Only downgrades when PayFast gives up and sends CANCELLED.
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
        `Hi,\n\nYour recent payment attempt failed.\n\nPayFast will retry automatically, but please ensure:\n- Your card has sufficient funds\n- Your payment method is valid\n\nIf the issue continues, your subscription may be cancelled.\n\n- MK2 Team`
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
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const token   = authHeader.split("Bearer ")[1];
  const decoded = await admin.auth().verifyIdToken(token);

  if (decoded.uid !== req.body.userId) {
    return res.status(403).json({ error: "Forbidden" });
  }

  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: "userId required" });
  if (!requireFirebase(res)) return;

  try {
    const snap = await db.ref(`mk2_users/${userId}`).get();
    if (!snap.exists()) return res.status(404).json({ error: "User not found" });

    const userData = snap.val();

    if (userData.membership === "basic") {
      return res.status(400).json({ error: "Already on basic plan" });
    }

    if (userData.cancellationPending) {
      return res.status(400).json({ error: "Cancellation already requested" });
    }

    // Tell PayFast to stop future renewals
    if (userData.subscriptionToken) {
      try {
        await cancelPayFastSubscription(userData.subscriptionToken);
        console.log("✅ PayFast subscription cancelled for:", userId);
      } catch (pfErr) {
        console.error("PayFast cancel API error:", pfErr.response?.data || pfErr.message);
        // Continue anyway — we still mark pending locally
      }
    }

    // Mark as pending — DO NOT downgrade yet.
    // The actual downgrade to basic happens when PayFast sends the CANCELLED ITN
    // at the end of the current billing period.
    await db.ref(`mk2_users/${userId}`).update({
      cancellationPending:     true,
      cancellationRequestedAt: Date.now(),
    });

    await db.ref(`paymentHistory/${userId}`).push({
      event: "cancellation_requested",
      date:  Date.now(),
    });

    await sendEmail(
      userData.email,
      "Subscription Cancellation Requested - MK2 Fitness",
      `Hi,\n\nYour cancellation has been requested.\n\nYou will keep full access to your current plan until your billing period ends, after which you'll be moved to the Basic plan.\n\n- MK2 Team`
    );

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
  ok:       true,
  firebase: firebaseReady,
  mode:     IS_LIVE ? "live" : "dev",
  base:     BASE_URL,
}));

app.get("/", (_, res) => {
  res.send("Server is running 🚀");
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 8080;
console.log("PORT FROM ENV:", process.env.PORT);

app.listen(PORT, "0.0.0.0", () => {
  console.log(`\n🚀 Server on port ${PORT} [${IS_LIVE ? "LIVE" : "dev"}]`);
  console.log(`🔔 ITN:    ${BASE_URL}/api/payfast-itn`);
  console.log(`🔑 Sign:   ${BASE_URL}/api/payfast-sign`);
  console.log(`❌ Cancel: ${BASE_URL}/api/cancel-subscription\n`);

  // ─── Firebase initialisation (async, after server is already listening) ────
  (async () => {
    try {
      if (!process.env.FIREBASE_KEY) {
        console.error("⚠️  Missing FIREBASE_KEY env variable — Firebase disabled");
        return;
      }

      const serviceAccount = JSON.parse(process.env.FIREBASE_KEY);
      serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, "\n");

      admin.initializeApp({
        credential:  admin.credential.cert(serviceAccount),
        databaseURL: process.env.FIREBASE_DATABASE_URL,
      });

      db = admin.database();
      firebaseReady = true;
      console.log("🔥 Firebase initialised successfully");
    } catch (err) {
      console.error("🔥 Firebase initialisation failed — app continues without it:", err.message);
    }
  })();
});