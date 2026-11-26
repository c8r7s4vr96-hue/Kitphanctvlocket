'use strict';
const crypto = require('node:crypto');
const { firebase, jsonError, error } = require('../lib/shop-common');

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

function timingSafeHexMatch(expectedHex, candidate) {
  const clean = String(candidate || '').trim().replace(/^sha256=/i, '').toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(clean)) return false;
  return crypto.timingSafeEqual(Buffer.from(expectedHex, 'hex'), Buffer.from(clean, 'hex'));
}

function verifySepayHmac(req, rawBody) {
  const secret = String(process.env.SEPAY_LIVE_WEBHOOK_SECRET || '').trim();
  if (!secret) throw error('Webhook secret chưa được cấu hình.', 503);

  const expectedHex = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
  const sigHeader =
    req.headers['x-sepay-signature'] ||
    req.headers['x-webhook-signature'] ||
    req.headers['x-signature'] ||
    '';

  if (timingSafeHexMatch(expectedHex, sigHeader)) return true;

  const auth = String(req.headers.authorization || '').trim();
  const bearer = auth.replace(/^(Bearer|Apikey)\s+/i, '').trim();
  const secretBuf = Buffer.from(secret, 'utf8');
  const bearerBuf = Buffer.from(bearer, 'utf8');
  if (bearer && bearerBuf.length === secretBuf.length && crypto.timingSafeEqual(secretBuf, bearerBuf)) {
    return true;
  }

  throw error('Chữ ký HMAC-SHA256 không hợp lệ.', 401);
}

function extractCtvUsernameCandidates(content) {
  const text = String(content || '').trim();
  const match = text.match(/KITPHANCTV[\s_:-]*([a-z0-9_-]{3,60})/i);
  if (!match) return [];
  const raw = match[1].toLowerCase();
  const candidates = [raw];
  const base = raw.split(/[-_]/)[0];
  if (base && base.length >= 3 && base !== raw) {
    candidates.push(base);
  }
  return candidates;
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

    if (payload.transferType && String(payload.transferType).toLowerCase() !== 'in') {
      return res.status(200).json({ ok: true, ignored: 'not_incoming_transfer' });
    }

    const expectedAccount = String(process.env.MB_BANK_ACCOUNT_NUMBER || '89123456789125').replace(/\s+/g, '').trim();
    const incomingAccount = String(payload.accountNumber || '').replace(/\s+/g, '').trim();
    const incomingSub = String(payload.subAccount || '').replace(/\s+/g, '').trim();
    if ((incomingAccount || incomingSub) && incomingAccount !== expectedAccount && incomingSub !== expectedAccount) {
      return res.status(200).json({ ok: true, ignored: 'account_mismatch' });
    }

    const amount = Math.round(Number(payload.transferAmount ?? payload.amount ?? 0));
    const minDeposit = Math.max(1000, Number(process.env.CTV_MIN_DEPOSIT_VND || 50000));
    const maxDeposit = Math.max(minDeposit, Number(process.env.CTV_MAX_DEPOSIT_VND || 1000000));

    if (!Number.isSafeInteger(amount) || amount < minDeposit || amount > maxDeposit) {
      return res.status(200).json({
        ok: true,
        ignored: 'amount_out_of_ctv_range',
        minDeposit,
        maxDeposit,
        amount,
      });
    }

    const candidates = extractCtvUsernameCandidates(payload.content || payload.description || '');
    if (!candidates.length) {
      return res.status(200).json({ ok: true, ignored: 'missing_ctv_username' });
    }

    const sdk = firebase();
    const db = sdk.database();
    let username = null;
    let userRecord = null;
    for (const cand of candidates) {
      const snap = await db.ref(`users/${cand}`).once('value');
      const val = snap.val();
      if (snap.exists() && val?.authUid) {
        username = cand;
        userRecord = val;
        break;
      }
    }
    if (!username || !userRecord?.authUid) {
      return res.status(200).json({ ok: true, ignored: 'unknown_ctv_user', username: candidates[0] });
    }

    const txId = String(payload.id || payload.referenceCode || crypto.createHash('sha256').update(rawBody).digest('hex').slice(0, 24))
      .replace(/[^a-zA-Z0-9_-]/g, '_');

    const lockTx = await db.ref(`sepay_processed_tx/${txId}`).transaction((cur) => {
      if (cur !== null) return undefined;
      return { txId, uid: userRecord.authUid, username, amount, processedAt: Date.now() };
    });

    if (!lockTx.committed) {
      return res.status(200).json({ ok: true, duplicate: true, txId });
    }

    const uid = userRecord.authUid;
    await db.ref(`live_deposits_v1/accounts/${uid}`).transaction((cur) => {
      const base = cur && typeof cur === 'object' ? cur : { uid, username, availableVnd: 0, heldVnd: 0, totalDepositedVnd: 0 };
      return {
        ...base,
        uid,
        username,
        availableVnd: Number(base.availableVnd || 0) + amount,
        totalDepositedVnd: Number(base.totalDepositedVnd || 0) + amount,
        updatedAt: Date.now(),
      };
    });

    await db.ref(`users/${username}/balance`).transaction((cur) => Number(cur || 0) + amount);
    await db.ref(`users/${username}/totalDeposited`).transaction((cur) => Number(cur || 0) + amount);
    await db.ref(`ctv_deposits/${uid}/${txId}`).set({
      id: txId,
      username,
      amount,
      gateway: 'MB Bank (SePay)',
      content: String(payload.content || payload.description || '').slice(0, 200),
      status: 'Thành công',
      createdAt: Date.now(),
    });

    return res.status(200).json({ ok: true, credited: true, txId, username, amount });
  } catch (e) {
    return jsonError(res, e);
  }
}

handler.config = { api: { bodyParser: false } };
module.exports = handler;
