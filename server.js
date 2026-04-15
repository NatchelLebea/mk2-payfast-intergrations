require("dotenv").config();
const express = require("express");
const crypto = require("crypto");
const cors = require("cors");
const axios = require("axios"); // npm install axios
const admin = require("firebase-admin"); // npm install firebase-admin

// ── Firebase Admin init ───────────────────────────────────────────────────────
// Download your service account key from Firebase Console → Project Settings
// → Service Accounts → Generate new private key
// Save it as serviceAccountKey.json in the same folder as server.js
// NEVER commit this file to git — add it to .gitignore
const serviceAccount = JSON.parse(process.env.FIREBASE_KEY);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://gym-pro-20ee6-default-rtdb.europe-west1.firebasedatabase.app"
});
//const db = admin.firestore();
// If you use Realtime Database instead of Firestore, swap to:
const db = admin.database();

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ── Config ────────────────────────────────────────────────────────────────────
// Set all of these in your .env file — never hardcode secrets
const {
  PAYFAST_MERCHANT_ID,
  PAYFAST_MERCHANT_KEY,
  PAYFAST_PASSPHRASE, // Set this in PayFast: Settings → Integration → Passphrase
  BASE_URL,
} = process.env;

// Switch to live when ready:
// Sandbox: "https://sandbox.payfast.co.za/eng/process"
// Live:    "https://www.payfast.co.za/eng/process"
const PAYFAST_BASE = "https://www.payfast.co.za/eng/process";

// PayFast IP whitelist for ITN validation (keep up to date)
// https://developers.payfast.co.za/docs#step_5_itn
const VALID_PAYFAST_IPS = [
  "197.97.145.144",
  "197.97.145.145",
  "197.97.145.146",
  "197.97.145.147",
  "41.74.179.194",
  "41.74.179.195",
  "41.74.179.196",
  "41.74.179.197",
];

// ── Signature generation ──────────────────────────────────────────────────────
// PayFast requires an MD5 signature of all params (in submission order)
// appended with your passphrase. Keys must be in the ORDER they appear in
// the form / URL — so always build the object in the right order.
function generateSignature(data, passphrase = "") {
  const pfData = { ...data };

  if (passphrase && passphrase.trim() !== "") {
    pfData.passphrase = passphrase;
  }

  const pfOutput = Object.keys(pfData)
    .sort() // ✅ VERY IMPORTANT
    .map(
      key =>
        `${key}=${encodeURIComponent(String(pfData[key])).replace(/%20/g, "+")}`
    )
    .join("&");

  console.log("🔐 SIGNATURE STRING:\n", pfOutput);

  return crypto.createHash("md5").update(pfOutput).digest("hex");
}


app.use(cors({
  origin: "*", // for testing (later restrict to your domain)
}));

// ── /api/payfast-sign ─────────────────────────────────────────────────────────
// Called by Membership.tsx to get a signed PayFast URL.
// This keeps your passphrase server-side only.
app.post("/api/payfast-sign", (req, res) => {
  try {
    const params = req.body;

    const signableParams = {
      merchant_id: process.env.PAYFAST_MERCHANT_ID,
      merchant_key: process.env.PAYFAST_MERCHANT_KEY,

      // ✅ MUST match frontend EXACTLY
      return_url: params.return_url,
      cancel_url: params.cancel_url,
      notify_url: params.notify_url,

      email_address: params.email_address,
      name_first: params.name_first,
      name_last: params.name_last,
      item_name: params.item_name,
      amount: params.amount,

      subscription_type: "1",
      billing_date: new Date().toISOString().split("T")[0],
      recurring_amount: params.recurring_amount || params.amount,
      frequency: params.frequency,
      cycles: "0",
    };

    const signature = generateSignature(
      signableParams,
      process.env.PAYFAST_PASSPHRASE
    );

    const queryString = Object.keys(signableParams)
      .sort() // ✅ MUST MATCH SIGNATURE ORDER
      .map(
        key =>
          `${key}=${encodeURIComponent(signableParams[key])}`
      )
      .join("&");

    const url = `https://www.payfast.co.za/eng/process?${queryString}&signature=${signature}`;

    res.json({ url });
  } catch (err) {
    console.error("❌ SIGN ERROR:", err);
    res.status(500).json({ error: "Failed to sign PayFast request" });
  }
});


async function updateUserMembership(email, tier, extra = {}) {
  try {
    const usersRef = db.ref("mk2_users");

    const snapshot = await usersRef.once("value");
    const users = snapshot.val();

    if (!users) {
      console.error("No users found in DB");
      return;
    }

    let foundUserId = null;

    // 🔍 Find user by email
    for (const uid in users) {
      if (users[uid].email === email) {
        foundUserId = uid;
        break;
      }
    }

    if (!foundUserId) {
      console.error(`❌ No user found for email: ${email}`);
      return;
    }

    // ✅ Update membership
    await usersRef.child(foundUserId).update({
      membership: tier,
      membershipUpdatedAt: Date.now(),

      subscription: {
        tier,
        status: tier === "basic" ? "cancelled" : "active",
        updatedAt: Date.now(),
        ...extra,
      },
    });

    console.log(`✅ Updated ${email} → ${tier}`);
  } catch (err) {
    console.error("❌ DB update error:", err);
  }
}
// ── /api/payfast-itn ──────────────────────────────────────────────────────────
// PayFast calls this endpoint after every payment event (new subscription,
// recurring payment, cancellation, failed payment, etc.)
// PayFast requires a 200 response within 10 seconds — do heavy work async.
app.post("/api/payfast-itn", async (req, res) => {
  // ✅ ALWAYS respond immediately
  res.sendStatus(200);

  const data = req.body;
  console.log("📩 ITN received:", data);

  try {
    // ── STEP 1: Validate IP ─────────────────────────────────────
    const callerIp =
      req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
      req.socket.remoteAddress;

    if (!VALID_PAYFAST_IPS.includes(callerIp)) {
      console.error("❌ Invalid PayFast IP:", callerIp);
      return;
    }

    // ── STEP 2: Validate signature ─────────────────────────────
    const received = { ...data };
    const theirSignature = received.signature;
    delete received.signature;

    const ourSignature = generateSignature(received, PAYFAST_PASSPHRASE);

    if (ourSignature !== theirSignature) {
      console.error("❌ Signature mismatch");
      return;
    }

    // ── STEP 3: Confirm with PayFast ───────────────────────────
    const pfHost =
      PAYFAST_BASE.includes("sandbox")
        ? "https://sandbox.payfast.co.za"
        : "https://www.payfast.co.za";

    const confirmBody = Object.entries(data)
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
      .join("&");

    const confirmRes = await axios.post(
      `${pfHost}/eng/query/validate`,
      confirmBody,
      {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      }
    );

    if (confirmRes.data.trim() !== "VALID") {
      console.error("❌ PayFast validation failed:", confirmRes.data);
      return;
    }

    // ── STEP 4: Extract info ───────────────────────────────────
    const email = data.email_address;
    const status = data.payment_status;
    const itemName = (data.item_name || "").toLowerCase();

    let tier = "basic";
    if (itemName.includes("gold")) tier = "gold";
    else if (itemName.includes("silver")) tier = "silver";

    // ── STEP 5: Handle payment status ──────────────────────────

    if (status === "COMPLETE") {
      console.log(`✅ COMPLETE: ${email} → ${tier}`);

      await updateUserMembership(email, tier, {
        payfastPaymentId: data.pf_payment_id,
        subscriptionToken: data.token, // 🔥 VERY IMPORTANT
        billingFrequency: data.frequency === "6" ? "yearly" : "monthly",
        nextBillingDate: data.billing_date || null,
      });

    } else if (status === "CANCELLED") {
      console.log(`⚠️ CANCELLED: ${email}`);

      await updateUserMembership(email, "basic", {
        cancelledAt: Date.now(),
      });

    } else if (status === "FAILED") {
      console.log(`❌ FAILED: ${email}`);

    } else if (status === "PENDING") {
      console.log(`⏳ PENDING: ${email}`);

    } else {
      console.log(`ℹ️ UNKNOWN STATUS: ${status}`);
    }

  } catch (err) {
    console.error("❌ ITN processing error:", err.message);
  }
});

// ── Update user membership in Firestore ───────────────────────────────────────
// Adjust the collection/document path to match your Firestore structure.
async function updateUserMembership(email, tier, extra = {}) {
  // Find user doc by email field
  const snapshot = await db
    .collection("users")
    .where("email", "==", email)
    .limit(1)
    .get();

  if (snapshot.empty) {
    console.error(`No user found for email: ${email}`);
    return;
  }

  const userDoc = snapshot.docs[0];
  await userDoc.ref.update({
    membership: tier,
    membershipUpdatedAt: admin.firestore.FieldValue.serverTimestamp(),
    ...extra,
  });

  console.log(`✅ Updated ${email} → membership: ${tier}`);
}

// ── /api/payfast-cancel ───────────────────────────────────────────────────────
// Optional: If you want to cancel a subscription programmatically (e.g.
// from an admin panel) rather than through the PayFast portal.
// Requires the subscription token saved from the ITN COMPLETE event.
app.post("/api/payfast-cancel", async (req, res) => {
  const { subscriptionToken } = req.body;
  if (!subscriptionToken) {
    return res.status(400).json({ error: "subscriptionToken required" });
  }
  try {
    const pfHost =
      PAYFAST_BASE.includes("sandbox")
        ? "https://sandbox.payfast.co.za"
        : "https://www.payfast.co.za";

    // PayFast cancel endpoint requires a signed request
    // https://developers.payfast.co.za/docs#cancel-subscription
    const timestamp = new Date().toISOString();
    const headers = {
      "merchant-id": PAYFAST_MERCHANT_ID,
      version: "v1",
      timestamp,
      // For full API key-signed requests, PayFast uses HMAC-SHA256 — see their API docs
    };

    const cancelRes = await axios.put(
      `${pfHost}/api/subscriptions/${subscriptionToken}/cancel`,
      {},
      { headers },
    );

    if (cancelRes.data.data?.response === 200) {
      res.json({ success: true });
    } else {
      res.status(400).json({ error: "Cancel failed", data: cancelRes.data });
    }
  } catch (err) {
    console.error("Cancel error:", err.response?.data || err.message);
    res.status(500).json({ error: "Cancel request failed" });
  }
});

// ── Success / Cancel redirect pages ──────────────────────────────────────────
// These are redirect targets after PayFast payment completes or is cancelled.
// In your SPA setup you likely handle this in React — these are fallbacks.
app.get("/membership", (req, res) => {
  // Redirect back to your React app's membership page
  res.redirect("https://gym-pro-20ee6.web.app/membership");
});

// ── Start server ──────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🔔 ITN endpoint: ${BASE_URL}/api/payfast-itn`);
  console.log(`🔑 Signing endpoint: ${BASE_URL}/api/payfast-sign`);
});