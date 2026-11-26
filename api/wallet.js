'use strict';
const { identity } = require('../lib/secure-accounts');
const { jsonError } = require('../lib/shop-common');

const DEPOSIT_BONUS_TIERS = [
  { minVnd: 1000000, bonusPercent: 35 },
  { minVnd: 500000, bonusPercent: 20 },
  { minVnd: 200000, bonusPercent: 5 },
  { minVnd: 50000, bonusPercent: 0 },
];

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'private, no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (req.method !== 'GET') return res.status(405).json({ ok: false, error: 'Method not allowed' });

  try {
    const ctx = await identity(req);
    const minDepositVnd = Math.max(1000, Number(process.env.CTV_MIN_DEPOSIT_VND || 50000));
    const maxDepositVnd = Math.max(minDepositVnd, Number(process.env.CTV_MAX_DEPOSIT_VND || 1000000));
    const accountNumber = String(process.env.MB_BANK_ACCOUNT_NUMBER || '89123456789125').trim();
    const accountName = String(process.env.MB_BANK_ACCOUNT_NAME || 'PHAN GIA TU').trim();

    const [walletSnap, depositsSnap] = await Promise.all([
      ctx.db.ref(`live_deposits_v1/accounts/${ctx.uid}`).once('value'),
      ctx.db.ref(`ctv_deposits/${ctx.uid}`).limitToLast(30).once('value'),
    ]);

    const wallet = walletSnap.val() || {};
    const availableVnd = Number.isSafeInteger(wallet.availableVnd) ? wallet.availableVnd : (ctx.profile?.balance || 0);
    const totalDepositedVnd = Number.isSafeInteger(wallet.totalDepositedVnd) ? wallet.totalDepositedVnd : (ctx.profile?.totalDeposited || 0);
    const deposits = Object.values(depositsSnap.val() || {}).sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));

    return res.status(200).json({
      ok: true,
      bank: 'MB',
      accountNumber,
      accountName,
      transferContent: `KITPHANCTV ${ctx.username}`,
      minDepositVnd,
      maxDepositVnd,
      availableVnd,
      totalDepositedVnd,
      bonusTiers: DEPOSIT_BONUS_TIERS,
      deposits,
    });
  } catch (e) {
    return jsonError(res, e);
  }
};
