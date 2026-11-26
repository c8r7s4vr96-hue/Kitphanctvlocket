'use strict';
const crypto = require('node:crypto');
const { firebase, jsonError, error } = require('../lib/shop-common');
const { calculateDepositBonus } = require('../lib/deposit-bonus');

async function readRawBody(req) {
  if (typeof req.rawBody === 'string' || Buffer.isBuffer(req.rawBody)) {
    return Buffer.from(req.rawBody);
  }
  if (!req.readableEnded) {
    const chunks = [];
    for await (const chunk of req) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }
    if (chunks.length > 0) {
      return Buffer.concat(chunks);
    }
  }
  // @vercel/node pre-parses JSON requests into req.body and consumes the stream.
  if (req.body !== undefined && req.body !== null) {
    if (Buffer.isBuffer(req.body)) return req.body;
    if (typeof req.body === 'string') return Buffer.from(req.body, 'utf8');
    if (typeof req.body === 'object') return Buffer.from(JSON.stringify(req.body), 'utf8');
  }
  return Buffer.alloc(0);
}

function timingSafeSigMatch(secret, rawBody, candidate) {
  const clean = String(candidate || '').trim().replace(/^sha256=/i, '');
  if (!clean) return false;
  const hmac = crypto.createHmac('sha256', secret).update(rawBody);
  if (/^[a-f0-9]{64}$/i.test(clean)) {
    return crypto.timingSafeEqual(hmac.digest(), Buffer.from(clean, 'hex'));
  }
  const expectedB64 = hmac.digest('base64');
  const a = Buffer.from(expectedB64, 'utf8');
  const b = Buffer.from(clean, 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function verifySepayHmac(req, rawBody) {
  const secret = String(process.env.SEPAY_LIVE_WEBHOOK_SECRET || '').trim();
  if (!secret) throw error('Webhook secret chưa được cấu hình.', 503);

  const sigHeader =
    req.headers['x-sepay-signature'] ||
    req.headers['x-webhook-signature'] ||
    req.headers['x-signature'] ||
    '';

  if (sigHeader && timingSafeSigMatch(secret, rawBody, sigHeader)) return true;

  const auth = String(req.headers.authorization || '').trim();
  const bearer = auth.replace(/^(Bearer|Apikey|Api-Key)\s+/i, '').trim();
  const apiKeyHeader = String(req.headers['x-api-key'] || '').trim();
  const candidateKey = bearer || apiKeyHeader;
  const secretBuf = Buffer.from(secret, 'utf8');
  const candBuf = Buffer.from(candidateKey, 'utf8');
  if (candidateKey && candBuf.length === secretBuf.length && crypto.timingSafeEqual(secretBuf, candBuf)) {
    return true;
  }

  if (!sigHeader && !candidateKey) {
    throw error('Thiếu header xác thực từ SePay. Hãy chọn kiểu chứng thực API Key trong cài đặt Webhook SePay.', 401);
  }
  if (candidateKey) {
    throw error('API Key từ SePay không khớp biến SEPAY_LIVE_WEBHOOK_SECRET trên Vercel.', 401);
  }
  throw error('Chữ ký HMAC-SHA256 không khớp. Hãy đổi kiểu chứng thực trên SePay sang API Key.', 401);
}

function extractCtvUsernameCandidates(content) {
  const text = String(content || '').trim();
  const match = text.match(/KITPHANCTV[\s_.:/-]*([^\r\n]+)/i);
  if (!match) return { candidates: [], afterPrefix: '' };

  const afterPrefix = match[1].trim();
  const seen = new Set();
  const add = (val) => {
    const v = String(val || '').toLowerCase().trim();
    if (/^[a-z0-9_-]{3,60}$/.test(v)) seen.add(v);
  };

  const firstTokenMatch = afterPrefix.match(/^([a-z0-9_-]{3,60})/i);
  if (firstTokenMatch) {
    const raw = firstTokenMatch[1].toLowerCase();
    add(raw);
    // Strip trailing bank suffixes separated by '-' or '_' from right to left
    // e.g. "long_le-CHUYENTIEN" -> "long_le" -> "long"
    let cur = raw;
    while (/[-_]/.test(cur)) {
      const idx = Math.max(cur.lastIndexOf('-'), cur.lastIndexOf('_'));
      if (idx <= 0) break;
      cur = cur.slice(0, idx);
      add(cur);
    }
  }

  // Handle banks replacing '_' or '-' with spaces (e.g. "KITPHANCTV long le" -> "long_le")
  const words = afterPrefix.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  if (words.length >= 2) {
    add(`${words[0]}_${words[1]}`);
    add(`${words[0]}-${words[1]}`);
    add(`${words[0]}${words[1]}`);
  }
  if (words.length >= 3) {
    add(`${words[0]}_${words[1]}_${words[2]}`);
    add(`${words[0]}-${words[1]}-${words[2]}`);
  }

  return { candidates: [...seen], afterPrefix };
}

async function resolveCtvUser(db, contentText) {
  const { candidates, afterPrefix } = extractCtvUsernameCandidates(contentText);
  if (!candidates.length && !afterPrefix) {
    return { reason: 'missing_ctv_username', username: null, uid: null };
  }

  for (const cand of candidates) {
    const [userSnap, claimSnap] = await Promise.all([
      db.ref(`users/${cand}`).once('value'),
      db.ref(`auth_username_uids/${cand}`).once('value'),
    ]);
    const val = userSnap.val();
    const uid = val?.authUid || (claimSnap.exists() ? claimSnap.val() : null);
    if (uid && typeof uid === 'string') {
      return { reason: null, username: cand, uid };
    }
  }

  // Fallback: match against existing users if bank stripped or altered separators
  const compactAfter = afterPrefix.toLowerCase().replace(/[^a-z0-9]/g, '');
  if (compactAfter.length >= 3) {
    const allUsersSnap = await db.ref('users').once('value');
    const allUsers = allUsersSnap.val() || {};
    let bestMatch = null;
    for (const [uname, val] of Object.entries(allUsers)) {
      if (!val || typeof val !== 'object' || !val.authUid) continue;
      const compactUname = uname.toLowerCase().replace(/[^a-z0-9]/g, '');
      if (compactUname.length >= 3 && compactAfter.startsWith(compactUname)) {
        if (!bestMatch || compactUname.length > bestMatch.compactLen) {
          bestMatch = { username: uname, uid: val.authUid, compactLen: compactUname.length };
        }
      }
    }
    if (bestMatch) {
      return { reason: null, username: bestMatch.username, uid: bestMatch.uid };
    }
  }

  return { reason: 'unknown_ctv_user', username: candidates[0] || null, uid: null };
}

async function logWebhookEvent(db, entry) {
  try {
    const id = 'wh_' + Date.now() + '_' + crypto.randomBytes(3).toString('hex');
    await db.ref(`sepay_webhook_logs/${id}`).set({
      id,
      ...entry,
      createdAt: Date.now(),
    });
  } catch {}
}

async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).json({ ok: false, error: 'Method not allowed' });

  try {
    const rawBody = await readRawBody(req);
    verifySepayHmac(req, rawBody);

    let payload;
    if (req.body && typeof req.body === 'object' && !Buffer.isBuffer(req.body) && rawBody.length > 0) {
      payload = req.body;
    } else {
      try {
        payload = JSON.parse(rawBody.toString('utf8'));
      } catch {
        throw error('Payload JSON không hợp lệ.', 400);
      }
    }

    const sdk = firebase();
    const db = sdk.database();

    const contentCombined = [payload.content, payload.description, payload.transactionContent]
      .filter((x) => typeof x === 'string' && x.trim())
      .join(' ')
      .trim();
    const rawAmount = payload.transferAmount ?? payload.amount ?? 0;
    const amount = Math.round(
      Number(typeof rawAmount === 'string' ? rawAmount.replace(/,/g, '').trim() : rawAmount)
    );
    const incomingAccount = String(payload.accountNumber || '').replace(/\s+/g, '').trim();
    const incomingSub = String(payload.subAccount || '').replace(/\s+/g, '').trim();
    const txId = String(payload.id || payload.referenceCode || crypto.createHash('sha256').update(rawBody).digest('hex').slice(0, 24))
      .replace(/[^a-zA-Z0-9_-]/g, '_');

    if (payload.transferType && String(payload.transferType).toLowerCase() !== 'in') {
      await logWebhookEvent(db, { status: 'ignored', reason: 'not_incoming_transfer', txId, amount, content: contentCombined.slice(0, 200) });
      return res.status(200).json({ ok: true, ignored: 'not_incoming_transfer' });
    }

    const expectedAccount = String(process.env.MB_BANK_ACCOUNT_NUMBER || '89123456789125').replace(/\s+/g, '').trim();
    if ((incomingAccount || incomingSub) && incomingAccount !== expectedAccount && incomingSub !== expectedAccount) {
      await logWebhookEvent(db, {
        status: 'ignored',
        reason: 'account_mismatch',
        txId,
        amount,
        incomingAccount,
        incomingSub,
        expectedAccount,
        content: contentCombined.slice(0, 200),
      });
      return res.status(200).json({ ok: true, ignored: 'account_mismatch' });
    }

    const minDeposit = Math.max(1000, Number(process.env.CTV_MIN_DEPOSIT_VND || 50000));
    const maxDeposit = Math.max(minDeposit, Number(process.env.CTV_MAX_DEPOSIT_VND || 1000000));

    if (!Number.isSafeInteger(amount) || amount < minDeposit || amount > maxDeposit) {
      await logWebhookEvent(db, {
        status: 'ignored',
        reason: 'amount_out_of_ctv_range',
        txId,
        amount,
        minDeposit,
        maxDeposit,
        content: contentCombined.slice(0, 200),
      });
      return res.status(200).json({
        ok: true,
        ignored: 'amount_out_of_ctv_range',
        minDeposit,
        maxDeposit,
        amount,
      });
    }

    const resolved = await resolveCtvUser(db, contentCombined);
    if (resolved.reason || !resolved.username || !resolved.uid) {
      await logWebhookEvent(db, {
        status: 'ignored',
        reason: resolved.reason || 'unknown_ctv_user',
        txId,
        amount,
        candidate: resolved.username || null,
        content: contentCombined.slice(0, 200),
      });
      return res.status(200).json({
        ok: true,
        ignored: resolved.reason || 'unknown_ctv_user',
        username: resolved.username || undefined,
      });
    }

    const { username, uid } = resolved;

    const lockTx = await db.ref(`sepay_processed_tx/${txId}`).transaction((cur) => {
      if (cur !== null) return undefined;
      return { txId, uid, username, amount, processedAt: Date.now() };
    });

    if (!lockTx.committed) {
      await logWebhookEvent(db, { status: 'duplicate', txId, username, amount, content: contentCombined.slice(0, 200) });
      return res.status(200).json({ ok: true, duplicate: true, txId });
    }

    const { bonusPercent, bonusVnd, creditedAmount } = calculateDepositBonus(amount);

    await db.ref(`live_deposits_v1/accounts/${uid}`).transaction((cur) => {
      const base = cur && typeof cur === 'object' ? cur : { uid, username, availableVnd: 0, heldVnd: 0, totalDepositedVnd: 0 };
      return {
        ...base,
        uid,
        username,
        availableVnd: Number(base.availableVnd || 0) + creditedAmount,
        totalDepositedVnd: Number(base.totalDepositedVnd || 0) + amount,
        updatedAt: Date.now(),
      };
    });

    await db.ref(`users/${username}/balance`).transaction((cur) => Number(cur || 0) + creditedAmount);
    await db.ref(`users/${username}/totalDeposited`).transaction((cur) => Number(cur || 0) + amount);
    await db.ref(`ctv_deposits/${uid}/${txId}`).set({
      id: txId,
      username,
      amount,
      bonusPercent,
      bonusVnd,
      creditedAmount,
      gateway: 'MB Bank (SePay)',
      content: contentCombined.slice(0, 200),
      status: 'Thành công',
      createdAt: Date.now(),
    });
    await logWebhookEvent(db, {
      status: 'credited',
      txId,
      username,
      amount,
      bonusPercent,
      bonusVnd,
      creditedAmount,
      content: contentCombined.slice(0, 200),
    });

    return res.status(200).json({ ok: true, credited: true, txId, username, amount, bonusPercent, bonusVnd, creditedAmount });
  } catch (e) {
    return jsonError(res, e);
  }
}

handler.config = { api: { bodyParser: false } };
module.exports = handler;
