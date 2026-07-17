// api/verifyStaffCode.js
//
// Remplace la Cloud Function Firebase "verifyStaffCode" — même logique,
// hébergée sur Vercel (gratuit, aucune carte bancaire requise) au lieu
// de Firebase Cloud Functions (qui demande le plan payant Blaze).
//
// Tes règles Firestore ne changent PAS : staffCodes reste totalement
// verrouillé (allow read, write: if false). Cette fonction utilise le
// SDK Admin, qui ignore les règles de sécurité — exactement comme le
// faisait la Cloud Function.
//
// ─────────────────────────────────────────────────────────
// MISE EN PLACE (une seule fois, 10 minutes, gratuit) :
// 1. Crée un compte sur vercel.com (gratuit, aucune carte demandée)
// 2. Firebase Console → ⚙️ Paramètres du projet → Comptes de service
//    → "Générer une nouvelle clé privée" → télécharge le fichier JSON
// 3. Dans ce dossier : `npm install`
// 4. Sur vercel.com, crée un projet à partir de ce dossier, puis dans
//    Settings → Environment Variables, ajoute (valeurs depuis le JSON) :
//      FIREBASE_PROJECT_ID     = project_id
//      FIREBASE_CLIENT_EMAIL   = client_email
//      FIREBASE_PRIVATE_KEY    = private_key (garde les \n tels quels)
// 5. Déploie (`vercel --prod` ou bouton Deploy sur le site)
// 6. Tu obtiens une URL du genre https://ton-projet.vercel.app
//    → colle-la dans staff_access_service.dart (voir commentaire là-bas)
// ─────────────────────────────────────────────────────────

const admin = require('firebase-admin');

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      // Vercel stocke les retours à la ligne échappés (\n littéral) —
      // on les reconvertit en vrais retours à la ligne.
      privateKey: (process.env.FIREBASE_PRIVATE_KEY || '').replace(/\\n/g, '\n'),
    }),
  });
}

const db = admin.firestore();

// Anti brute-force simple : max 5 tentatives ratées par restaurant
// toutes les 10 minutes (même principe que l'ancienne Cloud Function).
async function tropDeTentatives(restaurantId) {
  const ref = db.collection('_loginAttempts').doc(restaurantId);
  const snap = await ref.get();
  const now = Date.now();
  const data = snap.exists ? snap.data() : { count: 0, windowStart: now };

  if (now - data.windowStart > 10 * 60 * 1000) {
    await ref.set({ count: 1, windowStart: now });
    return false;
  }
  if (data.count >= 5) return true;
  await ref.set({ count: data.count + 1, windowStart: data.windowStart });
  return false;
}

module.exports = async (req, res) => {
  // Autorise les appels depuis l'app Flutter (web) — restreins à ton
  // domaine si tu publies une version web plus tard.
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'method-not-allowed' });

  try {
    const { restaurantId, code } = req.body || {};

    if (!restaurantId || !/^\d{4}$/.test(code || '')) {
      return res.status(400).json({ error: 'invalid-argument', message: 'restaurantId et code (4 chiffres) requis.' });
    }

    if (await tropDeTentatives(restaurantId)) {
      return res.status(429).json({ error: 'resource-exhausted', message: 'Trop de tentatives. Réessaie dans quelques minutes.' });
    }

    const snap = await db
      .collection('restaurants').doc(restaurantId)
      .collection('staffCodes')
      .where('code', '==', code)
      .where('active', '==', true)
      .limit(1)
      .get();

    if (snap.empty) {
      return res.status(404).json({ error: 'not-found', message: 'Code incorrect ou désactivé.' });
    }

    const doc = snap.docs[0];
    const data = doc.data();
    const role = data.role;

    // Jeton Firebase Auth avec le rôle et le restaurant en "claims" —
    // exactement ce que faisait la Cloud Function. Tes règles Firestore
    // (estStaff()) continuent de fonctionner sans aucun changement.
    const uid = `staff_${restaurantId}_${doc.id}`;
    const authToken = await admin.auth().createCustomToken(uid, {
      role,
      restaurantId,
    });

    return res.status(200).json({
      role,
      staffName: data.name || role,
      authToken,
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'internal', message: 'Erreur serveur.' });
  }
};
