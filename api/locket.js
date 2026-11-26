'use strict';
const { identity, checkOrigin } = require('../lib/secure-accounts');
const { jsonError, error } = require('../lib/shop-common');
const locketCatalog = require('../lib/locket-catalog');
const { fetchLocketCatalogPackages } = locketCatalog;
const { resolveLocketUsername, checkLocketUid, createLocketOrder } = require('../lib/locket-provider');

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'private, no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  const action = String(req.query?.action || (req.method === 'GET' ? 'catalog' : '')).trim();

  try {
    if (req.method === 'GET' && action === 'catalog') {
      return await locketCatalog(req, res);
    }

    if (req.method === 'GET' && action === 'orders') {
      const ctx = await identity(req);
      const snap = await ctx.db.ref(`ctv_orders/${ctx.uid}`).limitToLast(50).once('value');
      const orders = Object.values(snap.val() || {}).sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
      return res.status(200).json({ ok: true, orders });
    }

    if (req.method !== 'POST') {
      return res.status(405).json({ ok: false, error: 'Method not allowed' });
    }

    checkOrigin(req);
    const ctx = await identity(req);

    if (action === 'lookup') {
      const identifier = String(req.body?.identifier || '').trim().replace(/^@/, '');
      if (!identifier) throw error('Vui lòng nhập username Locket.', 422);
      const resolved = await resolveLocketUsername(identifier);
      let check = null;
      try {
        check = await checkLocketUid(resolved?.username || identifier);
      } catch {
        check = null;
      }
      return res.status(200).json({ ok: true, data: { ...resolved, check } });
    }

    if (action === 'export') {
      const locketUsername = String(req.body?.locketUsername || '').trim().replace(/^@/, '');
      const productId = String(req.body?.productId || '').trim();
      const requestId = String(req.body?.requestId || '').trim().replace(/[^a-zA-Z0-9_-]/g, '_');

      if (!locketUsername) throw error('Vui lòng nhập username Locket của khách.', 422);
      if (!productId) throw error('Vui lòng chọn gói Locket Gold.', 422);
      if (!requestId || requestId.length < 6) throw error('Thiếu mã requestId hợp lệ.', 422);

      const existingSnap = await ctx.db.ref(`ctv_orders/${ctx.uid}/${requestId}`).once('value');
      if (existingSnap.exists()) {
        const existing = existingSnap.val();
        if (existing.status === 'delivered') {
          return res.status(200).json({ ok: true, ...existing, idempotent: true });
        }
        throw error(existing.error || 'Đơn hàng này đang được xử lý hoặc đã thất bại.', 409);
      }

      const packages = await fetchLocketCatalogPackages();
      const pkg = packages.find(
        (p) => (p.packageId && String(p.packageId) === productId) || p.code === productId
      );
      if (!pkg || !pkg.available || !Number.isSafeInteger(pkg.priceVnd)) {
        throw error('Gói Locket Gold không khả dụng hoặc chưa có giá.', 422);
      }

      const priceVnd = pkg.priceVnd;
      const walletRef = ctx.db.ref(`live_deposits_v1/accounts/${ctx.uid}`);
      const preSnap = await walletRef.once('value');
      const preWallet = preSnap.val();
      const preAvail = Number(preWallet?.availableVnd || 0);
      if (!preSnap.exists() || preAvail < priceVnd) {
        throw error(`Số dư ví CTV không đủ (cần ${priceVnd.toLocaleString('vi-VN')}đ, hiện có ${preAvail.toLocaleString('vi-VN')}đ). Vui lòng nạp thêm!`, 402);
      }

      const holdTx = await walletRef.transaction((cur) => {
        // Firebase RTDB transaction() may invoke updateFn(null) on its first local pass;
        // returning a probe object forces RTDB to fetch the real server value instead of aborting.
        if (cur === null) {
          return { uid: ctx.uid, username: ctx.username, _probe: Date.now() };
        }
        const avail = Number(cur.availableVnd || 0);
        if (avail < priceVnd) return undefined;
        return {
          ...cur,
          availableVnd: avail - priceVnd,
          heldVnd: Number(cur.heldVnd || 0) + priceVnd,
          updatedAt: Date.now(),
        };
      });

      if (!holdTx.committed) {
        throw error(`Số dư ví CTV không đủ (cần ${priceVnd.toLocaleString('vi-VN')}đ). Vui lòng nạp thêm!`, 402);
      }

      try {
        const exported = await createLocketOrder({
          username: locketUsername,
          packageId: pkg.packageId,
          packageCode: pkg.code,
        });

        await walletRef.transaction((cur) => ({
          ...cur,
          heldVnd: Math.max(0, Number(cur?.heldVnd || 0) - priceVnd),
          updatedAt: Date.now(),
        }));
        await ctx.db.ref(`users/${ctx.username}/balance`).transaction((cur) => Math.max(0, Number(cur || 0) - priceVnd));

        const orderRecord = {
          id: requestId,
          orderId: requestId,
          ctvUsername: ctx.username,
          service: 'locket',
          productName: pkg.name,
          price: priceVnd,
          status: 'delivered',
          createdAt: Date.now(),
          locket: {
            uid: exported.uid || null,
            username: exported.username || locketUsername,
            packageId: exported.packageId || pkg.packageId,
            packageCode: exported.packageCode || pkg.code,
            packageName: exported.packageName || pkg.name,
            activationCode: exported.activationCode || null,
            expiresAt: exported.expiresAt || null,
            dnsUrl: exported.dnsUrl || null,
            reused: Boolean(exported.reused),
          },
        };

        await ctx.db.ref(`ctv_orders/${ctx.uid}/${requestId}`).set(orderRecord);
        return res.status(200).json({ ok: true, ...orderRecord });
      } catch (providerErr) {
        await walletRef.transaction((cur) => ({
          ...cur,
          availableVnd: Number(cur?.availableVnd || 0) + priceVnd,
          heldVnd: Math.max(0, Number(cur?.heldVnd || 0) - priceVnd),
          updatedAt: Date.now(),
        }));

        const errMsg = providerErr?.message || 'Nhà cung cấp Locket từ chối kích hoạt.';
        return res.status(providerErr?.status >= 400 && providerErr?.status < 500 ? providerErr.status : 502).json({
          ok: false,
          status: 'refunded',
          error: `${errMsg} (Đã hoàn lại ${priceVnd.toLocaleString('vi-VN')}đ vào ví CTV)`,
        });
      }
    }

    throw error('Action không hợp lệ.', 400);
  } catch (e) {
    return jsonError(res, e);
  }
};
