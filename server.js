import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import Stripe from 'stripe';
import rateLimit from 'express-rate-limit';
import crypto from 'crypto';
import dotenv from 'dotenv';
import pkg from 'pg';
const { Pool } = pkg;
import bodyParser from 'body-parser';

dotenv.config();

const {
  PORT = 8080,
  STRIPE_SECRET_KEY,
  STRIPE_PAYMENT_LINK_URL,
  STRIPE_PRICE_ID,
  STRIPE_WEBHOOK_SECRET,
  JWT_SECRET,
  COOKIE_NAME = 'ptc_auth', // Push The Ceiling auth
  COOKIE_DOMAIN,
  COOKIE_SECURE = 'true',
  APP_DOMAIN_ORIGIN,
  DATABASE_URL
} = process.env;

if (!STRIPE_SECRET_KEY || !STRIPE_PAYMENT_LINK_URL || !STRIPE_PRICE_ID || !JWT_SECRET || !APP_DOMAIN_ORIGIN) {
  console.error('Missing required env vars. Please set STRIPE_SECRET_KEY, STRIPE_PAYMENT_LINK_URL, STRIPE_PRICE_ID, JWT_SECRET, APP_DOMAIN_ORIGIN');
  process.exit(1);
}

const app = express();

// CORS: Support both web and React Native mobile
const allowedOrigins = String(APP_DOMAIN_ORIGIN || '').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, cb) => {
    // Allow React Native (no origin header) and configured origins
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
    return cb(null, false);
  },
  credentials: true,
}));

app.use(cookieParser());
app.set('trust proxy', 1);

const stripe = new Stripe(STRIPE_SECRET_KEY);

// --- Database for cross-device premium unlock ---
let pool = null;
(async () => {
  if (DATABASE_URL) {
    pool = new Pool({ 
      connectionString: DATABASE_URL, 
      ssl: { rejectUnauthorized: false } 
    });
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ptc_premium_users (
        user_id TEXT PRIMARY KEY,
        email TEXT,
        device_id TEXT,
        price_id TEXT,
        session_id TEXT UNIQUE,
        active BOOLEAN DEFAULT TRUE,
        purchased_at TIMESTAMPTZ DEFAULT now(),
        updated_at TIMESTAMPTZ DEFAULT now()
      );
      CREATE INDEX IF NOT EXISTS ptc_premium_email_idx ON ptc_premium_users ((lower(email)));
      CREATE INDEX IF NOT EXISTS ptc_premium_device_idx ON ptc_premium_users (device_id);
    `);
    console.log('✓ Database initialized');
  }
})().catch(e => console.error('DB init error', e));

// --- Helpers ---
function deviceHash(deviceId) {
  return crypto.createHash('sha256').update(String(deviceId || '')).digest('hex');
}

function signAuthToken(deviceId) {
  return jwt.sign(
    { 
      deviceId: deviceHash(deviceId), 
      scope: 'premium_unlocked',
      iat: Math.floor(Date.now() / 1000)
    }, 
    JWT_SECRET, 
    { expiresIn: '1095d' } // 3 years
  );
}

function verifyAuthToken(token, deviceId) {
  if (!token) return false;
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const expectedHash = deviceHash(deviceId);
    if (decoded.deviceId !== expectedHash) return false;
    if (decoded.scope !== 'premium_unlocked') return false;
    return true;
  } catch (e) {
    return false;
  }
}

// --- Rate limiting ---
const validateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
});

// --- STRIPE WEBHOOK (must be BEFORE express.json()) ---
app.post('/webhooks/stripe', bodyParser.raw({ type: 'application/json' }), async (req, res) => {
  if (!STRIPE_WEBHOOK_SECRET) return res.status(400).send('Webhook not configured');
  
  let event;
  try {
    const sig = req.headers['stripe-signature'];
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('⚠️ Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      if (session.payment_status !== 'paid') return res.json({ received: true });

      const full = await stripe.checkout.sessions.retrieve(session.id, { 
        expand: ['line_items.data.price'] 
      });

      const items = full.line_items?.data || [];
      const hasExpectedPrice = items.some(i => i.price?.id === STRIPE_PRICE_ID);
      if (!hasExpectedPrice) return res.json({ received: true });

      // Store premium unlock in database
      if (pool) {
        const email = full.customer_details?.email || null;
        const customerId = full.customer || null;
        const deviceId = full.metadata?.device_id || null;

        await pool.query(`
          INSERT INTO ptc_premium_users (user_id, email, device_id, price_id, session_id, active)
          VALUES ($1, $2, $3, $4, $5, TRUE)
          ON CONFLICT (user_id) DO UPDATE SET
            email = EXCLUDED.email,
            device_id = EXCLUDED.device_id,
            price_id = EXCLUDED.price_id,
            session_id = EXCLUDED.session_id,
            active = TRUE,
            updated_at = now();
        `, [
          customerId || `device:${deviceId || 'unknown'}`, 
          email, 
          deviceId,
          STRIPE_PRICE_ID, 
          full.id
        ]);

        console.log(`✓ Premium unlocked for: ${email || deviceId}`);
      }

      res.json({ received: true });
    } else {
      res.json({ received: true });
    }
  } catch (e) {
    console.error('⚠️ Webhook handler error', e);
    res.status(500).send('Webhook handler error');
  }
});

// Parse JSON for API routes (AFTER webhook)
app.use(express.json());

// --- API ROUTES ---

app.get('/api/health', (req, res) => {
  res.json({ ok: true, service: 'push-the-ceiling' });
});

// Create Stripe Checkout Session (for React Native WebView)
app.post('/api/create-checkout', async (req, res) => {
  try {
    const { device_id, return_url } = req.body || {};
    if (!device_id) return res.status(400).json({ error: 'device_id required' });

    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      line_items: [{
        price: STRIPE_PRICE_ID,
        quantity: 1,
      }],
      success_url: return_url || `${APP_DOMAIN_ORIGIN}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: return_url || `${APP_DOMAIN_ORIGIN}/cancel`,
      metadata: {
        device_id: device_id,
        app: 'push-the-ceiling'
      },
      allow_promotion_codes: true,
    });

    res.json({ 
      checkout_url: session.url,
      session_id: session.id 
    });
  } catch (err) {
    console.error('Checkout creation error:', err);
    res.status(500).json({ error: 'Failed to create checkout session' });
  }
});

// Validate session after payment (called by app)
app.post('/api/validate-session', validateLimiter, async (req, res) => {
  try {
    const { session_id, device_id } = req.body || {};
    if (!session_id || !device_id) {
      return res.status(400).json({ error: 'Missing session_id or device_id' });
    }

    const session = await stripe.checkout.sessions.retrieve(session_id, { 
      expand: ['line_items.data.price'] 
    });

    if (!session || session.mode !== 'payment') {
      return res.status(400).json({ error: 'Invalid session' });
    }

    const paid = (session.payment_status === 'paid') || (session.status === 'complete');
    if (!paid) {
      return res.status(402).json({ error: 'Payment not completed' });
    }

    const items = session.line_items?.data || [];
    const hasExpectedPrice = items.some(i => i.price?.id === STRIPE_PRICE_ID);
    if (!hasExpectedPrice) {
      return res.status(400).json({ error: 'Unexpected price' });
    }

    // Store in database
    const email = session.customer_details?.email || null;
    const customerId = session.customer || null;

    if (pool) {
      try {
        await pool.query(`
          INSERT INTO ptc_premium_users (user_id, email, device_id, price_id, session_id, active)
          VALUES ($1, $2, $3, $4, $5, TRUE)
          ON CONFLICT (user_id) DO UPDATE SET
            email = EXCLUDED.email,
            device_id = EXCLUDED.device_id,
            price_id = EXCLUDED.price_id,
            session_id = EXCLUDED.session_id,
            active = TRUE,
            updated_at = now();
        `, [
          customerId || `device:${device_id}`, 
          email, 
          device_id,
          STRIPE_PRICE_ID, 
          session.id
        ]);
      } catch (dbErr) {
        console.error('DB upsert error', dbErr);
      }
    }

    // Generate auth token for device
    const token = signAuthToken(device_id);

    res.json({ 
      unlocked: true, 
      token: token,
      email: email 
    });
  } catch (err) {
    console.error('Validate session error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Check premium status (by device_id and token)
app.post('/api/premium-status', async (req, res) => {
  try {
    const { device_id, token } = req.body || {};
    if (!device_id) return res.status(400).json({ error: 'device_id required' });

    // First check JWT token
    if (token && verifyAuthToken(token, device_id)) {
      return res.json({ premium: true, method: 'token' });
    }

    // Fallback: check database
    if (pool) {
      const result = await pool.query(`
        SELECT user_id FROM ptc_premium_users 
        WHERE device_id = $1 AND active = TRUE 
        LIMIT 1
      `, [device_id]);

      if (result.rows.length > 0) {
        const newToken = signAuthToken(device_id);
        return res.json({ 
          premium: true, 
          method: 'database',
          token: newToken 
        });
      }
    }

    res.json({ premium: false });
  } catch (err) {
    console.error('Premium status error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Restore premium by email (cross-device)
app.post('/api/restore-premium', async (req, res) => {
  try {
    if (!pool) {
      return res.status(500).json({ error: 'Database required for restore' });
    }

    const { email, device_id } = req.body || {};
    if (!email || !device_id) {
      return res.status(400).json({ error: 'Email and device_id required' });
    }

    const normalizedEmail = String(email).trim().toLowerCase();

    const result = await pool.query(`
      SELECT user_id FROM ptc_premium_users 
      WHERE lower(email) = $1 AND active = TRUE 
      LIMIT 1
    `, [normalizedEmail]);

    if (result.rows.length === 0) {
      return res.status(404).json({ 
        error: 'No premium purchase found for this email' 
      });
    }

    // Update device_id for this user
    await pool.query(`
      UPDATE ptc_premium_users 
      SET device_id = $1, updated_at = now()
      WHERE user_id = $2
    `, [device_id, result.rows.user_id]);

    const token = signAuthToken(device_id);

    res.json({ 
      premium: true, 
      restored: true,
      token: token 
    });
  } catch (err) {
    console.error('Restore error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Push The Ceiling backend running on :${PORT}`);
  console.log(`✓ Stripe integration active`);
  console.log(`✓ Webhook endpoint: /webhooks/stripe`);
});