'use strict';
const { checkOrigin, error, identity, verifiedIdentity, createAccount, clean, now } = require('../lib/secure-accounts');
const { jsonError } = require('../lib/shop-common');

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'private, no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (!['GET', 'POST'].includes(req.method)) return res.status(405).json({ ok: false });

  try {
    if (req.method === 'GET') {
      const ctx = await identity(req, { allowUnmapped: true });
      if (!ctx.username) {
        return res.status(200).json({ ok: true, setupRequired: true, verifiedEmail: ctx.email });
      }
      const [walletSnap, ordersSnap, depositsSnap] = await Promise.all([
        ctx.db.ref(`live_deposits_v1/accounts/${ctx.uid}`).once('value'),
        ctx.db.ref(`ctv_orders/${ctx.uid}`).limitToLast(50).once('value'),
        ctx.db.ref(`ctv_deposits/${ctx.uid}`).limitToLast(30).once('value'),
      ]);
      const wallet = walletSnap.val() || {};
      const availableVnd = Number.isSafeInteger(wallet.availableVnd) ? wallet.availableVnd : (ctx.profile?.balance || 0);
      const totalDepositedVnd = Number.isSafeInteger(wallet.totalDepositedVnd) ? wallet.totalDepositedVnd : (ctx.profile?.totalDeposited || 0);
      const orders = Object.values(ordersSnap.val() || {}).sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
      const deposits = Object.values(depositsSnap.val() || {}).sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));

      return res.status(200).json({
        ok: true,
        profile: {
          ...ctx.profile,
          role: 'Cộng Tác Viên',
          zalo: clean(ctx.record?.zalo || '', 30),
          balance: availableVnd,
          totalDeposited: totalDepositedVnd,
        },
        orders,
        deposits,
      });
    }

    checkOrigin(req);
    const action = String(req.body?.action || '');
    if (action === 'login_username') {
      const { signInLinkedUsername } = require('../lib/username-auth');
      return res.status(200).json(await signInLinkedUsername(req, { firebase: require('../lib/shop-common').firebase }));
    }

    if (action === 'register') {
      const ctx = await verifiedIdentity(req, true);
      const username = String(req.body?.username || '').trim().toLowerCase();
      const fullname = String(req.body?.fullname || '').trim();
      const zalo = clean(req.body?.zalo || '', 25);
      const profile = await createAccount(ctx, username, fullname);
      const db = ctx.sdk.database();
      await db.ref(`users/${username}`).update({
        role: 'Cộng Tác Viên',
        zalo,
      });
      await db.ref(`live_deposits_v1/accounts/${ctx.uid}`).transaction((cur) => {
        if (cur) return cur;
        return { uid: ctx.uid, username, availableVnd: 0, heldVnd: 0, totalDepositedVnd: 0, createdAt: now() };
      });
      return res.status(201).json({ ok: true, profile: { ...profile, role: 'Cộng Tác Viên', zalo } });
    }

    const ctx = await identity(req);
    if (action === 'profile') {
      const name = clean(req.body?.fullname, 90);
      const zalo = clean(req.body?.zalo, 25);
      if (name.length < 2) throw error('Tên hiển thị phải có từ 2 ký tự.', 422);
      await ctx.db.ref(`users/${ctx.username}`).update({ fullname: name, zalo });
      return res.status(200).json({ ok: true });
    }

    throw error('Thao tác không hỗ trợ.', 400);
  } catch (e) {
    return jsonError(res, e);
  }
};
