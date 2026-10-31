const admin = require('firebase-admin');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const buckets = new Map();
const WINDOW_MS = 60 * 1000;
const MAX_ATTEMPTS_PER_WINDOW = 15;

function requestKey(req, restaurantId) {
  const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  const ip = forwarded || req.socket?.remoteAddress || 'unknown';
  return `${ip}:${restaurantId}`;
}

function rateLimited(req, restaurantId) {
  const key = requestKey(req, restaurantId);
  const now = Date.now();
  const bucket = buckets.get(key);
  if (!bucket || now - bucket.startedAt > WINDOW_MS) {
    buckets.set(key, {startedAt: now, attempts: 1});
    return false;
  }
  bucket.attempts += 1;
  return bucket.attempts > MAX_ATTEMPTS_PER_WINDOW;
}

// ── Limiteur PERSISTANT (Firestore) ─────────────────────────────────────
// Sur Vercel chaque requête peut tomber sur une instance différente : le
// compteur en mémoire ci-dessus se remet à zéro et n'arrête donc pas un
// attaquant qui teste les 10 000 codes à 4 chiffres. Ces compteurs sont
// stockés dans Firestore (inaccessibles aux téléphones : aucune règle ne les
// expose, seul le SDK Admin y écrit).
const FAIL_WINDOW_MS = 15 * 60 * 1000;
const MAX_FAILS_PER_IP = 8;          // échecs / 15 min / adresse IP
const MAX_FAILS_PER_RESTAURANT = 60; // échecs / 15 min / restaurant (attaque distribuée)

function ipDigest(req) {
  const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  const ip = forwarded || req.socket?.remoteAddress || 'unknown';
  return crypto.createHash('sha256').update(ip).digest('hex').slice(0, 24);
}

function attemptRefs(db, restaurantId, ipHash) {
  const col = db.collection('restaurants').doc(restaurantId).collection('staffLoginAttempts');
  return { ip: col.doc('ip_' + ipHash), all: col.doc('_all') };
}

async function isBlocked(ref, max) {
  const snap = await ref.get();
  if (!snap.exists) return false;
  const d = snap.data() || {};
  return Date.now() - Number(d.windowStart || 0) <= FAIL_WINDOW_MS && Number(d.failures || 0) >= max;
}

async function recordFailure(db, ref) {
  await db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    const d = snap.exists ? snap.data() || {} : {};
    const now = Date.now();
    if (!snap.exists || now - Number(d.windowStart || 0) > FAIL_WINDOW_MS) {
      tx.set(ref, { failures: 1, windowStart: now });
    } else {
      tx.set(ref, { failures: Number(d.failures || 0) + 1, windowStart: d.windowStart });
    }
  });
}

function getAdmin() {
  if (admin.apps.length) return admin;
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (!raw) throw new Error('FIREBASE_SERVICE_ACCOUNT_JSON is missing');
  const serviceAccount = JSON.parse(raw);
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
  return admin;
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ message: 'Method not allowed' });

  try {
    const { restaurantId, code } = req.body || {};
    if (!/^[A-Za-z0-9_-]{2,64}$/.test(String(restaurantId || ''))) {
      return res.status(400).json({ message: 'Invalid restaurantId' });
    }
    if (!/^\d{4}$/.test(String(code || ''))) {
      return res.status(400).json({ message: 'Le code doit contenir 4 chiffres.' });
    }
    if (rateLimited(req, String(restaurantId))) {
      return res.status(429).json({ message: 'Trop de tentatives. Réessayez plus tard.' });
    }

    const firebaseAdmin = getAdmin();
    const db = firebaseAdmin.firestore();

    const refs = attemptRefs(db, String(restaurantId), ipDigest(req));
    if ((await isBlocked(refs.ip, MAX_FAILS_PER_IP)) || (await isBlocked(refs.all, MAX_FAILS_PER_RESTAURANT))) {
      return res.status(429).json({ message: 'Trop de tentatives. Réessayez dans 15 minutes.' });
    }
    const snap = await db
      .collection('restaurants')
      .doc(restaurantId)
      .collection('staffCodes')
      .where('active', '==', true)
      .get();

    let match = null;
    for (const doc of snap.docs) {
      const data = doc.data() || {};
      const hash = String(data.codeHash || '');
      if (!hash) continue;
      if (await bcrypt.compare(String(code), hash)) {
        match = { id: doc.id, ...data };
        break;
      }
    }

    if (!match) {
      await Promise.all([recordFailure(db, refs.ip), recordFailure(db, refs.all)]).catch(() => {});
      return res.status(401).json({ message: 'Code incorrect ou désactivé.' });
    }
    // Connexion réussie : on repart de zéro pour cette adresse IP.
    await refs.ip.delete().catch(() => {});

    const allowedRoles = new Set(['directeur', 'caissier', 'cuisine', 'livreur']);
    if (!allowedRoles.has(String(match.role || ''))) {
      return res.status(403).json({ message: 'Rôle invalide.' });
    }

    const uid = `staff_${restaurantId}_${match.id}`;
    const user = await firebaseAdmin.auth().getUser(uid).catch(async (error) => {
      if (error.code !== 'auth/user-not-found') throw error;
      return firebaseAdmin.auth().createUser({ uid, disabled: false });
    });

    await firebaseAdmin.auth().setCustomUserClaims(user.uid, {
      restaurantId,
      role: String(match.role),
      staffName: String(match.staffName || match.name || ''),
      staffCodeId: match.id,
    });

    const token = await firebaseAdmin.auth().createCustomToken(user.uid, {
      restaurantId,
      role: String(match.role),
      staffName: String(match.staffName || match.name || ''),
      staffCodeId: match.id,
    });

    return res.status(200).json({
      allowed: true,
      role: String(match.role),
      staffName: String(match.staffName || match.name || ''),
      authToken: token,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Erreur serveur.' });
  }
};
