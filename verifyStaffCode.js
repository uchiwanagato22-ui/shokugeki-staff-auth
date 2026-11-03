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

function diagError(code, message) {
  const error = new Error(message || code);
  error.diag = code;
  return error;
}

// Accepte le JSON du compte de service tel quel, ou encodé en base64.
function parseServiceAccount(raw) {
  let text = String(raw).trim();
  if (!text.startsWith('{')) {
    try {
      text = Buffer.from(text, 'base64').toString('utf8').trim();
    } catch (_) {
      // on laisse JSON.parse échouer ci-dessous
    }
  }
  let account;
  try {
    account = JSON.parse(text);
  } catch (_) {
    throw diagError('json_invalide', 'Service account JSON is not valid JSON');
  }
  if (account.private_key) account.private_key = String(account.private_key).replace(/\\n/g, '\n');
  return account;
}

function readServiceAccount() {
  // 1) Un seul champ JSON (nom recommandé : FIREBASE_SERVICE_ACCOUNT_JSON).
  const jsonNames = [
    'FIREBASE_SERVICE_ACCOUNT_JSON',
    'FIREBASE_SERVICE_ACCOUNT',
    'FIREBASE_SERVICE_ACCOUNT_KEY',
    'FIREBASE_SERVICE_ACCOUNT_BASE64',
    'FIREBASE_CREDENTIALS',
    'GOOGLE_SERVICE_ACCOUNT_JSON',
  ];
  for (const name of jsonNames) {
    const value = process.env[name];
    if (value && value.trim()) return parseServiceAccount(value);
  }
  // 2) Trois champs séparés (ancien format possible).
  const projectId = process.env.FIREBASE_PROJECT_ID;
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  const privateKey = process.env.FIREBASE_PRIVATE_KEY;
  if (projectId && clientEmail && privateKey) {
    return {
      project_id: projectId,
      client_email: clientEmail,
      private_key: String(privateKey).replace(/\\n/g, '\n'),
    };
  }
  throw diagError('env_manquante', 'FIREBASE_SERVICE_ACCOUNT_JSON is missing');
}

function getAdmin() {
  if (admin.apps.length) return admin;
  const account = readServiceAccount();
  try {
    admin.initializeApp({ credential: admin.credential.cert(account) });
  } catch (_) {
    throw diagError('cle_invalide', 'Service account key rejected');
  }
  return admin;
}

// Code court et sans secret, renvoyé au téléphone pour savoir quoi réparer.
function classifyError(error) {
  if (error && error.diag) return error.diag;
  const code = error && error.code;
  if (code === 7 || code === 'permission-denied') return 'firestore_refuse';
  if (code === 16 || code === 'unauthenticated') return 'identifiants_refuses';
  if (code === 5) return 'firestore_introuvable';
  if (typeof code === 'string' && code) return code.slice(0, 60);
  return 'inconnue';
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
      let same = false;
      try {
        same = await bcrypt.compare(String(code), hash);
      } catch (_) {
        console.error('hash illisible pour le code', doc.id);
      }
      if (same) {
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
    const diag = classifyError(error);
    console.error('verifyStaffCode', diag, error && error.message);
    return res.status(500).json({ message: 'Erreur serveur.', code: diag });
  }
};
