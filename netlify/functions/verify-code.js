/**
 * Netlify Serverless Function: verify-code
 *
 * Kullanıcının girdiği kodu ve düğün tarihini doğrular.
 * Başarılıysa kısa ömürlü bir session token + Supabase credentials döndürür.
 * Supabase URL ve key yalnızca PIN doğrulandıktan sonra istemciye gönderilir —
 * HTML kaynak koduna gömülmez.
 *
 * Gerekli ortam değişkenleri (Netlify → Environment variables):
 *   WEDDING_CODE         → Masalara yazacağınız gizli kelime (örn: GUMUS2025)
 *   SESSION_SECRET       → Rastgele uzun bir string (token imzalamak için)
 *   SUPABASE_URL         → https://xyzxyz.supabase.co
 *   SUPABASE_ANON_KEY    → Supabase project anon key
 *   SUPABASE_BUCKET      → Storage bucket adı (örn: wedding-photos)
 */

const crypto = require('crypto');

// Brute-force koruması (in-memory — Lambda restart'ta sıfırlanır)
const attempts  = {};
const MAX_TRIES = 10;
const LOCK_MS   = 30 * 60 * 1000; // 30 dakika

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: cors() };
  }
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  const ip = (event.headers['x-forwarded-for'] || 'unknown').split(',')[0].trim();

  if (isLocked(ip)) {
    return {
      statusCode: 429,
      headers: cors(),
      body: JSON.stringify({ error: 'Çok fazla hatalı deneme. 30 dakika bekleyin.' }),
    };
  }

  let code;
  try {
    ({ code } = JSON.parse(event.body || '{}'));
  } catch {
    return { statusCode: 400, headers: cors(), body: JSON.stringify({ error: 'Geçersiz istek' }) };
  }

  const expectedCode = (process.env.WEDDING_CODE || '').toUpperCase().trim();
  const secret       = process.env.SESSION_SECRET || 'degistir-bunu';

  // Kod kontrolü
  if (!code || code.toUpperCase().trim() !== expectedCode) {
    recordFail(ip);
    const left = MAX_TRIES - (attempts[ip]?.count || 0);
    return {
      statusCode: 401,
      headers: cors(),
      body: JSON.stringify({
        error: left > 0
          ? `Hatalı kod. ${left} deneme hakkınız kaldı.`
          : 'Çok fazla hatalı deneme. Hesap kilitlendi.',
      }),
    };
  }

  // Başarılı — session token üret (4 saat geçerli)
  clearFails(ip);
  const exp     = Date.now() + 4 * 60 * 60 * 1000;
  const sig     = crypto.createHmac('sha256', secret).update(String(exp)).digest('hex');
  const token   = `${exp}.${sig}`;

  return {
    statusCode: 200,
    headers: cors(),
    body: JSON.stringify({
      token,
      supabaseUrl:    process.env.SUPABASE_URL    || '',
      supabaseKey:    process.env.SUPABASE_ANON_KEY || '',
      supabaseBucket: process.env.SUPABASE_BUCKET || 'wedding-photos',
    }),
  };
};

// ── Yardımcılar ────────────────────────────────────────────────────

function isLocked(ip) {
  const r = attempts[ip];
  return r?.lockedUntil && Date.now() < r.lockedUntil;
}

function recordFail(ip) {
  if (!attempts[ip]) attempts[ip] = { count: 0 };
  attempts[ip].count++;
  if (attempts[ip].count >= MAX_TRIES) {
    attempts[ip].lockedUntil = Date.now() + LOCK_MS;
  }
}

function clearFails(ip) { delete attempts[ip]; }

function cors() {
  return {
    'Access-Control-Allow-Origin':  '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json',
  };
}
