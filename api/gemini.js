// Relais Gemini pour le Chef IA : la clé Gemini reste ICI (variable d'environnement
// Vercel) et n'est plus jamais dans l'APK.
//
// Variables d'environnement Vercel :
//   GEMINI_API_KEY                 obligatoire  (clé Google AI Studio)
//   FIREBASE_SERVICE_ACCOUNT_JSON  obligatoire  (déjà configurée pour verifyStaffCode)
//   GEMINI_MODELS                  facultatif   modèles essayés dans l'ordre,
//                                  ex: "gemini-2.5-flash,gemini-3.5-flash-lite"
//   GEMINI_USER_HOURLY_LIMIT       facultatif   défaut 20 messages / heure / utilisateur
//   GEMINI_GLOBAL_DAILY_LIMIT      facultatif   défaut 200 messages / jour pour TOUS (UTC)
const admin = require('firebase-admin');

const MODELS = (process.env.GEMINI_MODELS || process.env.GEMINI_MODEL || 'gemini-2.5-flash,gemini-3.5-flash-lite')
  .split(',')
  .map((m) => m.trim())
  .filter(Boolean);
const USER_HOURLY_LIMIT = Number(process.env.GEMINI_USER_HOURLY_LIMIT || 20);
const GLOBAL_DAILY_LIMIT = Number(process.env.GEMINI_GLOBAL_DAILY_LIMIT || 200);

const MAX_MESSAGES = 40;
const MAX_CHARS_PER_MESSAGE = 8000;
const MAX_TOTAL_CHARS = 24000;

function getAdmin() {
  if (admin.apps.length) return admin;
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (!raw) throw new Error('FIREBASE_SERVICE_ACCOUNT_JSON is missing');
  admin.initializeApp({ credential: admin.credential.cert(JSON.parse(raw)) });
  return admin;
}

// Valide la conversation et fusionne les messages consécutifs du même rôle
// (Gemini attend une alternance user / model).
function buildContents(messages) {
  if (!Array.isArray(messages) || messages.length === 0 || messages.length > MAX_MESSAGES) return null;
  let total = 0;
  const contents = [];
  for (const m of messages) {
    if (!m || (m.role !== 'user' && m.role !== 'model') || typeof m.text !== 'string') return null;
    const text = m.text.trim();
    if (!text) continue;
    if (text.length > MAX_CHARS_PER_MESSAGE) return null;
    total += text.length;
    if (total > MAX_TOTAL_CHARS) return null;
    const last = contents[contents.length - 1];
    if (last && last.role === m.role) {
      last.parts[0].text += '\n\n' + text;
    } else {
      contents.push({ role: m.role, parts: [{ text }] });
    }
  }
  if (!contents.length || contents[0].role !== 'user' || contents[contents.length - 1].role !== 'user') return null;
  return contents;
}

// Compteurs dans Firestore (aucune règle ne les expose : seul le SDK Admin y accède).
async function takeQuota(db, uid) {
  const iso = new Date().toISOString();
  const hour = iso.slice(0, 13);
  const day = iso.slice(0, 10);
  const userRef = db.collection('aiUsage').doc(`u_${uid}_${hour}`);
  const dayRef = db.collection('aiUsage').doc(`day_${day}`);
  return db.runTransaction(async (tx) => {
    const [u, d] = await Promise.all([tx.get(userRef), tx.get(dayRef)]);
    const userCount = u.exists ? Number(u.data().count || 0) : 0;
    const dayCount = d.exists ? Number(d.data().count || 0) : 0;
    if (dayCount >= GLOBAL_DAILY_LIMIT) return 'global';
    if (userCount >= USER_HOURLY_LIMIT) return 'user';
    tx.set(userRef, { uid, hour, count: userCount + 1 }, { merge: true });
    tx.set(dayRef, { day, count: dayCount + 1 }, { merge: true });
    return 'ok';
  });
}

async function callGemini(model, contents, apiKey) {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`;
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-goog-api-key': apiKey },
    body: JSON.stringify({
      contents,
      generationConfig: { maxOutputTokens: 2048, temperature: 0.7 },
    }),
    signal: AbortSignal.timeout(25000),
  });
  const status = response.status;
  if (status !== 200) return { status };
  const data = await response.json();
  const parts = data?.candidates?.[0]?.content?.parts || [];
  const text = parts.map((p) => (typeof p.text === 'string' ? p.text : '')).join('').trim();
  return { status, text };
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ message: 'Method not allowed' });

  try {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) return res.status(500).json({ message: 'Chef IA non configuré.' });

    // 1) L'appelant doit être connecté à l'app (client, staff ou anonyme).
    const header = String(req.headers.authorization || '');
    const idToken = header.startsWith('Bearer ') ? header.slice(7).trim() : '';
    if (!idToken) return res.status(401).json({ message: 'Connexion requise.' });

    const firebaseAdmin = getAdmin();
    let uid;
    try {
      uid = (await firebaseAdmin.auth().verifyIdToken(idToken)).uid;
    } catch (_) {
      return res.status(401).json({ message: 'Connexion requise.' });
    }

    // 2) Conversation valide et de taille raisonnable.
    const contents = buildContents((req.body || {}).messages);
    if (!contents) return res.status(400).json({ message: 'Requête invalide.' });

    // 3) Quotas (par utilisateur et global) pour protéger ton quota Gemini.
    const quota = await takeQuota(firebaseAdmin.firestore(), uid);
    if (quota !== 'ok') {
      return res.status(429).json({ message: 'Le Chef IA est très sollicité. Réessaie plus tard.' });
    }

    // 4) On essaie les modèles dans l'ordre (modèle retiré, quota épuisé ou panne => suivant).
    let lastStatus = 0;
    for (const model of MODELS) {
      try {
        const result = await callGemini(model, contents, apiKey);
        lastStatus = result.status;
        if (result.status === 200) {
          return res.status(200).json({ text: result.text || '', model });
        }
        if (![400, 404, 429, 500, 503].includes(result.status)) break;
      } catch (error) {
        console.error('gemini', model, error && error.name);
        lastStatus = 503;
      }
    }
    return res.status(lastStatus === 429 ? 429 : 502).json({ message: 'Chef IA indisponible.' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Erreur serveur.' });
  }
};
