require("dotenv").config();
const express    = require("express");
const crypto     = require("crypto");
const cors       = require("cors");
const axios      = require("axios");
const admin      = require("firebase-admin");
const rateLimit  = require("express-rate-limit");
const helmet     = require("helmet");
const nodemailer = require("nodemailer");
const morgan     = require("morgan");
const fs         = require("fs");
const path       = require("path");

// ─── Env var validation — crash loudly on startup if anything is missing ──────
const REQUIRED_ENV = [
  "PAYFAST_MERCHANT_ID", "PAYFAST_MERCHANT_KEY", "PAYFAST_PASSPHRASE",
  "BASE_URL", "FIREBASE_KEY", "FIREBASE_DATABASE_URL",
];
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) {
    console.error(`❌ Missing required environment variable: ${key}`);
    process.exit(1);
  }
}

// ─── Firebase Admin ───────────────────────────────────────────────────────────
let db            = null;
let firebaseReady = false;

// ─── App ──────────────────────────────────────────────────────────────────────
const app = express();
app.use(helmet());

// ─── Request logging (Morgan) ─────────────────────────────────────────────────
// Logs every request to logs/access.log and to the console
const logsDir = path.join(__dirname, "logs");
if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir);

const accessLogStream = fs.createWriteStream(
  path.join(logsDir, "access.log"),
  { flags: "a" }
);
app.use(morgan("combined", { stream: accessLogStream }));  // file
app.use(morgan("dev"));                                    // console

// ─── Payment event logger ─────────────────────────────────────────────────────
// Writes structured payment events (ITN, cancel, upgrade) to logs/payments.log
const paymentLogStream = fs.createWriteStream(
  path.join(logsDir, "payments.log"),
  { flags: "a" }
);
function logPaymentEvent(event) {
  const line = JSON.stringify({ ts: new Date().toISOString(), ...event });
  paymentLogStream.write(line + "\n");
  console.log("💳 Payment event:", line);
}

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",").map(o => o.trim()).filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    if (!origin && process.env.NODE_ENV !== "production") return cb(null, true);
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    cb(new Error(`CORS blocked: ${origin}`));
  },
  methods: ["GET", "POST", "PUT"],
  allowedHeaders: ["Content-Type", "Authorization"],
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

process.on("uncaughtException",  err => console.error("💥 Uncaught Exception:",  err));
process.on("unhandledRejection", err => console.error("💥 Unhandled Rejection:", err));

async function sendEmail(to, subject, text) {
  try {
    await transporter.sendMail({
      from: `"MK2 Fitness" <${process.env.EMAIL_USER}>`,
      to, subject, text,
    });
    console.log("📧 Email sent to:", to);
  } catch (err) {
    console.error("Email error:", err.message);
  }
}

const IS_LIVE      = NODE_ENV === "production";
const PAYFAST_HOST = "https://www.payfast.co.za";

const PAYFAST_IPS = [
  "197.97.145.144","197.97.145.145","197.97.145.146","197.97.145.147",
  "41.74.179.194", "41.74.179.195", "41.74.179.196", "41.74.179.197",
];

// ─── Helpers ──────────────────────────────────────────────────────────────────
function generateSignature(data, passphrase = "") {
  const pfData = { ...data };
  if (passphrase && passphrase.trim() !== "") pfData.passphrase = passphrase.trim();
  const str = Object.keys(pfData).sort()
    .map(k => `${k}=${encodeURIComponent(String(pfData[k])).replace(/%20/g, "+")}`)
    .join("&");
  console.log("🔐 SIGN STRING:\n", str);
  return crypto.createHash("md5").update(str).digest("hex");
}

function requireFirebase(res) {
  if (!firebaseReady || !db) {
    res.status(503).json({ error: "Service temporarily unavailable — database not ready yet" });
    return false;
  }
  return true;
}

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

/**
 * Calculate the next billing date based on membershipSince.
 * Keeps rolling 30-day (monthly) or 365-day (yearly) cycles.
 */
function getNextBillingDate(membershipSince, billing = "monthly") {
  const periodMs = billing === "yearly"
    ? 365 * 24 * 60 * 60 * 1000
    :  30 * 24 * 60 * 60 * 1000;

  const now  = Date.now();
  let next   = membershipSince;

  // Roll forward until next is in the future
  while (next <= now) next += periodMs;

  return next; // timestamp ms
}

/**
 * Cancel a PayFast subscription token via their API.
 */
async function cancelPayFastSubscription(token) {
  const timestamp = new Date().toISOString();
  const version   = "v1";

  const sigParams = {
    "merchant-id": PAYFAST_MERCHANT_ID,
    passphrase:    PAYFAST_PASSPHRASE,
    timestamp,
    version,
  };

  const sigStr = Object.keys(sigParams).sort()
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

// ─── Scheduled downgrade checker (runs every hour) ───────────────────────────
// Checks all users with a pending scheduledDowngrade and applies it if
// their accessUntil timestamp has passed.
function startDowngradeScheduler() {
  const ONE_HOUR = 60 * 60 * 1000;

  async function runCheck() {
    if (!firebaseReady || !db) return;

    try {
      const snap = await db.ref("mk2_users")
        .orderByChild("scheduledDowngrade")
        .startAt("basic")  // any non-null value
        .get();

      if (!snap.exists()) return;

      const now   = Date.now();
      const users = snap.val();

      for (const [uid, user] of Object.entries(users)) {
        if (!user.scheduledDowngrade) continue;
        if (!user.accessUntil || now < user.accessUntil) continue;

        // Access period has expired — apply downgrade now
        console.log(`⏰ Applying scheduled downgrade for ${uid} → ${user.scheduledDowngrade}`);

        await db.ref(`mk2_users/${uid}`).update({
          membership:          user.scheduledDowngrade,
          membershipBilling:   null,
          subscriptionToken:   null,
          membershipUpdatedAt: now,
          aiQuota:             null,
          scheduledDowngrade:  null,
          accessUntil:         null,
        });

        await db.ref(`paymentHistory/${uid}`).push({
          event: "downgraded",
          to:    user.scheduledDowngrade,
          date:  now,
        });

        if (user.email) {
          await sendEmail(
            user.email,
            "📉 Plan Downgraded - MK2 Membership",
            `Hi,

Your membership has been updated as scheduled.

New plan: ${user.scheduledDowngrade.toUpperCase()}

If this was a mistake, you can upgrade again at any time in the app.

- MK2 Team`
          );
        }
      }
    } catch (err) {
      console.error("Downgrade scheduler error:", err.message);
    }
  }

  // Run immediately on start, then every hour
  setTimeout(runCheck, 5000);
  setInterval(runCheck, ONE_HOUR);
  console.log("⏰ Downgrade scheduler started");
}

// ─── Processed payments cleanup (runs daily) ──────────────────────────────────
// Deletes processedPayments entries older than 90 days to prevent unbounded growth
function startPaymentCleanup() {
  const ONE_DAY     = 24 * 60 * 60 * 1000;
  const NINETY_DAYS = 90 * ONE_DAY;

  async function runCleanup() {
    if (!firebaseReady || !db) return;
    try {
      const snap = await db.ref("processedPayments").get();
      if (!snap.exists()) return;

      const now     = Date.now();
      const entries = snap.val();
      let   deleted = 0;

      for (const [id, val] of Object.entries(entries)) {
        // entries are stored as true — use the payment ID timestamp if embedded,
        // otherwise delete anything that looks old (IDs are sequential at PayFast)
        const ts = typeof val === "object" && val.ts ? val.ts : null;
        if (ts && now - ts > NINETY_DAYS) {
          await db.ref(`processedPayments/${id}`).remove();
          deleted++;
        }
      }

      if (deleted > 0) console.log(`🧹 Cleaned up ${deleted} old processedPayments entries`);
    } catch (err) {
      console.error("Payment cleanup error:", err.message);
    }
  }

  // Run once 10s after startup, then every 24 hours
  setTimeout(runCleanup, 10_000);
  setInterval(runCleanup, ONE_DAY);
  console.log("🧹 Payment cleanup scheduler started");
}

// ─── POST /api/payfast-sign ───────────────────────────────────────────────────
app.post("/api/payfast-sign", signLimiter, async (req, res) => {
  // Auth check — must be a logged-in Firebase user
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Unauthorized" });

  const idToken = authHeader.split("Bearer ")[1];
  let decoded;
  try {
    decoded = await admin.auth().verifyIdToken(idToken);
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }

  // Ensure uid in token matches custom_str1
  // Prevents one user generating a payment URL on behalf of another
  if (decoded.uid !== req.body.custom_str1) {
    logPaymentEvent({ event: "sign_forbidden", uid: decoded.uid, attempted: req.body.custom_str1 });
    return res.status(403).json({ error: "Forbidden — uid mismatch" });
  }

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

    // ── Upgrade credit calculation ──────────────────────────────────────────
    // If the user already has a paid plan and is upgrading to a different tier,
    // credit them for the unused days in their current billing period.
    if (custom_str1 && db) {
      const userSnap = await db.ref(`mk2_users/${custom_str1}`).get();

      if (userSnap.exists()) {
        const user = userSnap.val();

        const isUpgrade =
          user.membership &&
          user.membership !== "basic" &&
          user.membership !== custom_str2;

        if (isUpgrade) {
          const billing      = custom_str3 || "monthly";
          const periodMs     = billing === "yearly"
            ? 365 * 24 * 60 * 60 * 1000
            :  30 * 24 * 60 * 60 * 1000;

          const now          = Date.now();
          const since        = user.membershipSince || now;
          const nextBilling  = getNextBillingDate(since, billing);
          const remainingMs  = nextBilling - now;
          const remainingPct = Math.min(remainingMs / periodMs, 1);

          const currentPrice =
            user.membership === "silver"
              ? (billing === "yearly" ? 228 : 24)
              : (billing === "yearly" ? 588 : 54);

          const credit = remainingPct * currentPrice;
          finalAmount  = Math.max(parsedAmount - credit, 5);

          console.log(`💰 Upgrade credit: R${credit.toFixed(2)} (${Math.round(remainingPct * 100)}% of R${currentPrice}) → Final charge: R${finalAmount.toFixed(2)}`);
          console.log(`📅 Next billing was: ${new Date(nextBilling).toISOString()}`);
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
    const qs = Object.keys(params).sort()
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

  if (!firebaseReady || !db) {
    console.error("ITN received but Firebase is not ready — skipping DB update");
    return;
  }

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
      console.error("ITN blocked — signature mismatch");
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

      // Auto cancel old subscription if upgrading
      if (userData.subscriptionToken && userData.membership !== tierId) {
        console.log("🔄 Auto-cancelling old subscription token:", userData.subscriptionToken);
        try {
          await cancelPayFastSubscription(userData.subscriptionToken);
        } catch (err) {
          console.error("Auto cancel failed:", err.message);
        }
      }

      const isNewGold   = tierId === "gold"   && userData.membership !== "gold";
      const isNewSilver = tierId === "silver" && userData.membership !== "silver";

      const update = {
        membership:          tierId,
        membershipBilling:   billing,
        membershipSince:     Date.now(),
        membershipUpdatedAt: Date.now(),
        subscriptionToken:   token || null,
        lastPaymentId:       data.pf_payment_id,
        lastPaymentAmount:   data.amount_gross,
        cancelledAt:         null,
        membershipFailedAt:  null,
        // Clear any pending scheduled downgrade since they just paid
        scheduledDowngrade:  null,
        accessUntil:         null,
      };

      if (isNewGold) {
        update.classCredits = (userData.classCredits || 0) + 10;
        update.aiQuota = { remaining: 200, resetDate: nextMonthFirst() };
      }
      if (isNewSilver) {
        update.aiQuota = { remaining: 50, resetDate: nextMonthFirst() };
      }

      await userRef.update(update);

      await db.ref(`paymentHistory/${userKey}`).push({
        event: "complete", tier: tierId, billing,
        amount: data.amount_gross, paymentId: data.pf_payment_id,
        token: token || null, date: Date.now(),
      });

      console.log(`✅ COMPLETE: ${userId || email} → ${tierId} (${billing}) R${data.amount_gross}`);
      logPaymentEvent({ event: "itn_complete", userId: userId || email, tier: tierId, billing, amount: data.amount_gross, paymentId: data.pf_payment_id });

      await sendEmail(email, "✅ Payment Successful - MK2 Membership",
`Hi,

Your payment was successful 🎉

Plan: ${tierId.toUpperCase()}
Billing: ${billing}
Amount: R${data.amount_gross}

Welcome to MK2 Fitness!

- MK2 Team`);

    // ── CANCELLED (from PayFast side, e.g. too many failed retries) ──────────
    } else if (status === "CANCELLED") {
      // PayFast cancelled — downgrade immediately (they stopped billing)
      await userRef.update({
        membership:          "basic",
        membershipBilling:   null,
        subscriptionToken:   null,
        membershipUpdatedAt: Date.now(),
        cancelledAt:         Date.now(),
        aiQuota:             null,
        scheduledDowngrade:  null,
        accessUntil:         null,
      });
      await db.ref(`paymentHistory/${userKey}`).push({ event: "cancelled", date: Date.now() });
      console.log(`⚠️ CANCELLED by PayFast: ${userId || email} → basic`);
      logPaymentEvent({ event: "itn_cancelled", userId: userId || email });

      await sendEmail(email, "❌ Subscription Cancelled - MK2 Membership",
`Hi,

Your subscription has been cancelled.

You are now on the Basic plan.

We're sorry to see you go — you're always welcome back!

- MK2 Team`);

    // ── FAILED ────────────────────────────────────────────────────────────────
    } else if (status === "FAILED") {
      await userRef.update({ membershipFailedAt: Date.now() });
      await db.ref(`paymentHistory/${userKey}`).push({
        event: "failed", paymentId: data.pf_payment_id || null, date: Date.now(),
      });
      console.log(`❌ FAILED: ${userId || email} — PayFast will retry`);
      logPaymentEvent({ event: "itn_failed", userId: userId || email, paymentId: data.pf_payment_id });

      await sendEmail(email, "⚠️ Payment Failed - MK2 Membership",
`Hi,

Your recent payment attempt failed.

PayFast will retry automatically, but please ensure:
- Your card has sufficient funds
- Your payment method is valid

If the issue continues, your subscription may be cancelled.

- MK2 Team`);

    } else {
      console.log(`ℹ️ ITN status: ${status}`);
    }

  } catch (err) {
    console.error("ITN error:", err);
  }
});

// ─── POST /api/cancel-subscription ───────────────────────────────────────────
// Cancels billing immediately with PayFast but keeps the user's access
// until the end of their current billing period (membershipSince + 30/365 days).
app.post("/api/cancel-subscription", cancelLimiter, async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Unauthorized" });

  const idToken = authHeader.split("Bearer ")[1];
  let decoded;
  try {
    decoded = await admin.auth().verifyIdToken(idToken);
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }

  if (decoded.uid !== req.body.userId) return res.status(403).json({ error: "Forbidden" });

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

    // Work out when their access actually expires
    const billing     = userData.membershipBilling || "monthly";
    const since       = userData.membershipSince   || Date.now();
    const accessUntil = getNextBillingDate(since, billing);

    console.log(`🗓 Cancel: access until ${new Date(accessUntil).toISOString()} for ${userId}`);

    // 1. Cancel with PayFast so no more charges
    if (userData.subscriptionToken) {
      try {
        await cancelPayFastSubscription(userData.subscriptionToken);
        console.log("✅ PayFast subscription cancelled:", userData.subscriptionToken);
      } catch (pfErr) {
        console.error("PayFast cancel API error:", pfErr.response?.data || pfErr.message);
        // Continue — still schedule the local downgrade
      }
    }

    // 2. Schedule downgrade — keep current tier until billing period ends
    await db.ref(`mk2_users/${userId}`).update({
      subscriptionToken:   null,       // no more billing
      membershipUpdatedAt: Date.now(),
      scheduledDowngrade:  "basic",    // what to downgrade to
      accessUntil,                     // timestamp when access expires
      cancelledAt:         Date.now(),
    });

    await db.ref(`paymentHistory/${userId}`).push({
      event:       "cancelled_via_app",
      accessUntil,
      date:        Date.now(),
    });

    const accessDate = new Date(accessUntil).toLocaleDateString("en-ZA", {
      day: "numeric", month: "long", year: "numeric",
    });

    await sendEmail(
      userData.email,
      "❌ Subscription Cancelled - MK2 Membership",
`Hi,

Your subscription has been cancelled. No further payments will be taken.

You will keep full access to your ${userData.membership.toUpperCase()} plan until ${accessDate}.

After that, your account will move to the Basic (free) plan automatically.

You're always welcome to re-subscribe at any time.

- MK2 Team`
    );

    res.json({
      success: true,
      accessUntil,
      message: `Subscription cancelled. Access continues until ${accessDate}.`,
    });

  } catch (err) {
    console.error("Cancel error:", err.message);
    res.status(500).json({ error: "Cancellation failed" });
  }
});

// ─── POST /api/downgrade ──────────────────────────────────────────────────────
// Schedules a downgrade to a lower tier at the next billing date.
// The user keeps their current plan until then.
app.post("/api/downgrade", cancelLimiter, async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Unauthorized" });

  const idToken = authHeader.split("Bearer ")[1];
  let decoded;
  try {
    decoded = await admin.auth().verifyIdToken(idToken);
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }

  if (decoded.uid !== req.body.userId) return res.status(403).json({ error: "Forbidden" });

  const { userId, targetTier } = req.body;
  if (!userId || !targetTier) return res.status(400).json({ error: "userId and targetTier required" });
  if (!["basic", "silver"].includes(targetTier)) return res.status(400).json({ error: "Invalid targetTier" });
  if (!requireFirebase(res)) return;

  try {
    const snap = await db.ref(`mk2_users/${userId}`).get();
    if (!snap.exists()) return res.status(404).json({ error: "User not found" });

    const userData = snap.val();

    if (userData.membership === targetTier) {
      return res.status(400).json({ error: "Already on that plan" });
    }

    const tierOrder = { basic: 0, silver: 1, gold: 2 };
    if (tierOrder[targetTier] >= tierOrder[userData.membership]) {
      return res.status(400).json({ error: "Use the upgrade flow for upgrades" });
    }

    const billing     = userData.membershipBilling || "monthly";
    const since       = userData.membershipSince   || Date.now();
    const accessUntil = getNextBillingDate(since, billing);

    console.log(`📉 Downgrade scheduled: ${userId} → ${targetTier} at ${new Date(accessUntil).toISOString()}`);

    // Cancel PayFast subscription — new one will be created when they
    // sign up to the lower tier after downgrade takes effect
    if (userData.subscriptionToken) {
      try {
        await cancelPayFastSubscription(userData.subscriptionToken);
      } catch (pfErr) {
        console.error("PayFast cancel for downgrade error:", pfErr.response?.data || pfErr.message);
      }
    }

    await db.ref(`mk2_users/${userId}`).update({
      subscriptionToken:   null,
      membershipUpdatedAt: Date.now(),
      scheduledDowngrade:  targetTier,
      accessUntil,
    });

    await db.ref(`paymentHistory/${userId}`).push({
      event:       "downgrade_scheduled",
      to:          targetTier,
      accessUntil,
      date:        Date.now(),
    });

    const accessDate = new Date(accessUntil).toLocaleDateString("en-ZA", {
      day: "numeric", month: "long", year: "numeric",
    });

    await sendEmail(
      userData.email,
      "📉 Plan Change Scheduled - MK2 Membership",
`Hi,

Your plan change has been scheduled.

Current plan: ${userData.membership.toUpperCase()}
New plan: ${targetTier.toUpperCase()} (takes effect ${accessDate})

You will keep full access to your current plan until then.

- MK2 Team`
    );

    res.json({
      success: true,
      accessUntil,
      message: `Downgrade to ${targetTier} scheduled for ${accessDate}.`,
    });

  } catch (err) {
    console.error("Downgrade error:", err.message);
    res.status(500).json({ error: "Downgrade failed" });
  }
});

// ─── Health check ─────────────────────────────────────────────────────────────
app.get("/health", (_, res) => res.json({
  ok: true, firebase: firebaseReady,
  mode: IS_LIVE ? "live" : "dev", base: BASE_URL,
}));

app.get("/", (_, res) => res.send("Server is running 🚀"));

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 8080;
console.log("PORT FROM ENV:", process.env.PORT);

app.listen(PORT, "0.0.0.0", () => {
  console.log(`\n🚀 Server on port ${PORT} [${IS_LIVE ? "LIVE" : "dev"}]`);
  console.log(`🔔 ITN:       ${BASE_URL}/api/payfast-itn`);
  console.log(`🔑 Sign:      ${BASE_URL}/api/payfast-sign`);
  console.log(`❌ Cancel:    ${BASE_URL}/api/cancel-subscription`);
  console.log(`📉 Downgrade: ${BASE_URL}/api/downgrade\n`);

  // ─── Firebase initialisation ─────────────────────────────────────────────
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

      // Start the hourly downgrade checker after Firebase is ready
      startDowngradeScheduler();

    } catch (err) {
      console.error("🔥 Firebase initialisation failed:", err.message);
    }
  })();
});