'use strict';
const crypto = require('node:crypto');
const {
  checkOrigin,
  error,
  identity,
  verifiedIdentity,
  createAccount,
  clean,
  now,
  USERNAME,
  EMAIL,
  configuredAdminUsername,
} = require('../lib/secure-accounts');
const { firebase, jsonError } = require('../lib/shop-common');

const SEVEN_DAYS_MS = 7 * 86400000;

function tokenHash(raw) {
  return crypto.createHash('sha256').update(String(raw || '')).digest('hex');
}

function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function baseUrlFromReq(req) {
  const proto = String(req.headers['x-forwarded-proto'] || 'https').split(',')[0].trim();
  const host = String(req.headers['x-forwarded-host'] || req.headers.host || 'kitphanctvlocket.vercel.app').split(',')[0].trim();
  return `${proto}://${host}`;
}

async function sendActivationEmail({ to, username, fullname, activateUrl }) {
  const apiKey = String(process.env.RESEND_API_KEY || '').trim();
  if (!apiKey) return { sent: false, reason: 'RESEND_API_KEY_NOT_CONFIGURED' };

  const from = String(process.env.EMAIL_FROM || 'Locket KitPhan <onboarding@resend.dev>').trim();
  const safeName = escapeHtml(fullname || username);
  const safeUser = escapeHtml(username);
  const safeUrl = escapeHtml(activateUrl);

  const html = `
  <div style="background:#f4f4f5;padding:32px 16px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#18181b;">
    <div style="max-width:520px;margin:0 auto;background:#ffffff;border:1px solid #e4e4e7;border-radius:16px;padding:32px;">
      <div style="font-size:18px;font-weight:800;margin-bottom:20px;color:#18181b;">👑 Locket KitPhan CTV</div>
      <h1 style="font-size:22px;font-weight:800;margin:0 0 14px;color:#09090b;">Kích hoạt tài khoản CTV</h1>
      <p style="font-size:15px;line-height:1.6;color:#3f3f46;margin:0 0 22px;">
        Xin chào <b>${safeUser}</b> (${safeName}), bạn vừa được duyệt trở thành <b>Cộng tác viên Locket KitPhan</b>. Bấm nút bên dưới để đặt mật khẩu và kích hoạt tài khoản — chỉ mất một phút.
      </p>
      <a href="${safeUrl}" style="display:inline-block;background:#0f172a;color:#ffffff;text-decoration:none;font-weight:700;font-size:14px;padding:13px 24px;border-radius:10px;">
        Đặt mật khẩu &amp; kích hoạt
      </a>
      <p style="font-size:13px;color:#71717a;margin:18px 0 22px;">Link có hiệu lực trong <b>7 ngày</b>.</p>
      <div style="border-top:1px solid #e4e4e7;padding-top:16px;font-size:12px;color:#71717a;line-height:1.6;">
        Nút không bấm được? Dán link này vào trình duyệt:<br>
        <a href="${safeUrl}" style="color:#2563eb;word-break:break-all;">${safeUrl}</a>
      </div>
    </div>
    <div style="text-align:center;font-size:11px;color:#a1a1aa;margin-top:16px;">
      Email tự động từ Locket KitPhan — vui lòng không trả lời.
    </div>
  </div>`;

  const resp = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from,
      to: [to],
      subject: 'Kích hoạt tài khoản CTV Locket KitPhan',
      html,
    }),
    signal: AbortSignal.timeout(10000),
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    return { sent: false, reason: data?.message || `HTTP ${resp.status}` };
  }
  return { sent: true, id: data?.id || null };
}

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'private, no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (!['GET', 'POST'].includes(req.method)) return res.status(405).json({ ok: false });

  try {
    const queryAction = String(req.query?.action || '').trim();

    if (req.method === 'GET' && queryAction === 'check_activate') {
      const rawToken = String(req.query?.token || '').trim();
      if (!/^[a-f0-9]{32,128}$/i.test(rawToken)) throw error('Link kích hoạt không hợp lệ.', 400);
      const db = firebase().database();
      const snap = await db.ref(`ctv_activation_tokens/${tokenHash(rawToken)}`).once('value');
      const rec = snap.val();
      if (!snap.exists() || !rec) throw error('Link kích hoạt không tồn tại hoặc đã bị thu hồi.', 404);
      if (rec.used) throw error('Link kích hoạt này đã được sử dụng. Hãy đăng nhập.', 409);
      if (!rec.expiresAt || Date.now() > rec.expiresAt) throw error('Link kích hoạt đã hết hạn (7 ngày). Hãy liên hệ Admin.', 410);
      return res.status(200).json({
        ok: true,
        username: rec.username,
        fullname: rec.fullname,
        email: rec.email,
      });
    }

    if (req.method === 'GET' && queryAction === 'admin_requests') {
      const ctx = await identity(req, { adminOnly: true });
      const snap = await ctx.db.ref('ctv_registration_requests').limitToLast(100).once('value');
      const requests = Object.values(snap.val() || {})
        .filter((x) => x && typeof x === 'object')
        .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
      return res.status(200).json({ ok: true, requests });
    }

    if (req.method === 'GET') {
      const ctx = await identity(req, { allowUnmapped: true });
      if (!ctx.isAdmin && ctx.token?.firebase?.sign_in_provider === 'google.com') {
        throw error('Chỉ tài khoản Google Admin mới được phép đăng nhập bằng Google. CTV vui lòng đăng ký chờ Admin duyệt qua Email.', 403);
      }
      if (!ctx.username) {
        throw error('Tài khoản chưa được Admin kích hoạt. Vui lòng đăng ký chờ Admin duyệt qua Email.', 403);
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
          role: ctx.isAdmin ? 'Administrator' : 'Cộng Tác Viên',
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
      return res.status(200).json(await signInLinkedUsername(req, { firebase }));
    }

    if (action === 'request_register') {
      const username = String(req.body?.username || '').trim().toLowerCase();
      const fullname = clean(req.body?.fullname || '', 90);
      const zalo = clean(req.body?.zalo || '', 25);
      const email = String(req.body?.email || '').trim().toLowerCase();

      if (fullname.length < 2) throw error('Vui lòng nhập họ và tên hợp lệ.', 422);
      if (!USERNAME.test(username) || username === configuredAdminUsername() || username.startsWith('google_') || ['admin', 'administrator', 'root'].includes(username)) {
        throw error('Username phải gồm 3–60 ký tự chữ thường, số, _ hoặc -.', 422);
      }
      if (!zalo || zalo.length < 8) throw error('Vui lòng nhập số Zalo hợp lệ.', 422);
      if (!EMAIL.test(email)) throw error('Email không hợp lệ.', 422);

      const sdk = firebase();
      const db = sdk.database();
      const [userSnap, claimSnap, reqSnap] = await Promise.all([
        db.ref(`users/${username}`).once('value'),
        db.ref(`auth_username_uids/${username}`).once('value'),
        db.ref('ctv_registration_requests').orderByChild('email').equalTo(email).once('value'),
      ]);
      if (userSnap.exists() || claimSnap.exists()) {
        throw error('Username CTV này đã được sử dụng.', 409);
      }
      const existingReqs = Object.values(reqSnap.val() || {});
      if (existingReqs.some((r) => r && r.status === 'pending')) {
        throw error('Email này đã gửi yêu cầu đăng ký và đang chờ Admin duyệt.', 409);
      }

      const requestId = 'req_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex');
      await db.ref(`ctv_registration_requests/${requestId}`).set({
        id: requestId,
        username,
        fullname,
        zalo,
        email,
        status: 'pending',
        createdAt: now(),
      });

      return res.status(201).json({
        ok: true,
        pending: true,
        message: 'Đã gửi yêu cầu đăng ký CTV! Admin sẽ duyệt và gửi email kích hoạt kèm link đặt mật khẩu cho bạn.',
      });
    }

    if (action === 'complete_activate') {
      const rawToken = String(req.body?.token || '').trim();
      const password = String(req.body?.password || '');
      if (!/^[a-f0-9]{32,128}$/i.test(rawToken)) throw error('Link kích hoạt không hợp lệ.', 400);
      if (password.length < 10 || password.length > 1024) throw error('Mật khẩu phải có từ 10 ký tự trở lên.', 422);

      const sdk = firebase();
      const db = sdk.database();
      const tHash = tokenHash(rawToken);
      const tokenRef = db.ref(`ctv_activation_tokens/${tHash}`);
      const snap = await tokenRef.once('value');
      const rec = snap.val();
      if (!snap.exists() || !rec) throw error('Link kích hoạt không tồn tại.', 404);
      if (rec.used) throw error('Link kích hoạt đã được sử dụng.', 409);
      if (!rec.expiresAt || Date.now() > rec.expiresAt) throw error('Link kích hoạt đã hết hạn (7 ngày).', 410);

      let userRecord;
      try {
        userRecord = await sdk.auth().getUserByEmail(rec.email);
        userRecord = await sdk.auth().updateUser(userRecord.uid, {
          password,
          displayName: rec.fullname || rec.username,
          emailVerified: true,
          disabled: false,
        });
      } catch (e) {
        if (e?.code === 'auth/user-not-found') {
          userRecord = await sdk.auth().createUser({
            email: rec.email,
            password,
            displayName: rec.fullname || rec.username,
            emailVerified: true,
          });
        } else {
          throw e;
        }
      }

      const uid = userRecord.uid;
      const username = String(rec.username).toLowerCase();
      await db.ref(`auth_username_uids/${username}`).set(uid);
      await db.ref(`auth_bindings/${uid}`).set({ username, linkedAt: now(), kind: 'fresh_auth' });
      await db.ref(`users/${username}`).update({
        username,
        fullname: clean(rec.fullname, 90) || username,
        email: rec.email,
        zalo: clean(rec.zalo, 25),
        role: 'Cộng Tác Viên',
        authUid: uid,
        createdAt: now(),
        avatar: 'https://placehold.co/100x100/27272a/ffffff?text=User',
      });
      await db.ref(`live_deposits_v1/accounts/${uid}`).transaction((cur) => {
        if (cur) return cur;
        return { uid, username, availableVnd: 0, heldVnd: 0, totalDepositedVnd: 0, createdAt: now() };
      });
      await tokenRef.update({ used: true, usedAt: now(), uid });
      if (rec.requestId) {
        await db.ref(`ctv_registration_requests/${rec.requestId}`).update({ status: 'activated', activatedAt: now() });
      }

      const customToken = await sdk.auth().createCustomToken(uid, { login_method: 'activation_link' });
      return res.status(200).json({ ok: true, customToken, username });
    }

    if (action === 'register') {
      throw error('Tính năng tự đăng ký trực tiếp đã tắt. Vui lòng gửi yêu cầu đăng ký để Admin duyệt qua Email.', 403);
    }

    if (action === 'admin_approve') {
      const ctx = await identity(req, { adminOnly: true });
      const requestId = clean(req.body?.requestId, 100);
      if (!requestId) throw error('Thiếu requestId.', 422);
      const reqRef = ctx.db.ref(`ctv_registration_requests/${requestId}`);
      const reqSnap = await reqRef.once('value');
      const reqData = reqSnap.val();
      if (!reqSnap.exists() || !reqData) throw error('Không tìm thấy yêu cầu đăng ký.', 404);

      const rawToken = crypto.randomBytes(32).toString('hex');
      const tHash = tokenHash(rawToken);
      const expiresAt = now() + SEVEN_DAYS_MS;

      await ctx.db.ref(`ctv_activation_tokens/${tHash}`).set({
        requestId,
        username: reqData.username,
        fullname: reqData.fullname,
        zalo: reqData.zalo,
        email: reqData.email,
        expiresAt,
        used: false,
        createdAt: now(),
      });

      const activateUrl = `${baseUrlFromReq(req)}/ctv.html?activate=${rawToken}`;
      const mailRes = await sendActivationEmail({
        to: reqData.email,
        username: reqData.username,
        fullname: reqData.fullname,
        activateUrl,
      });

      await reqRef.update({
        status: 'approved',
        approvedAt: now(),
        approvedBy: ctx.email,
        emailSent: mailRes.sent,
      });

      return res.status(200).json({
        ok: true,
        emailSent: mailRes.sent,
        emailError: mailRes.sent ? null : mailRes.reason,
        activateUrl,
      });
    }

    if (action === 'admin_reject') {
      const ctx = await identity(req, { adminOnly: true });
      const requestId = clean(req.body?.requestId, 100);
      if (!requestId) throw error('Thiếu requestId.', 422);
      await ctx.db.ref(`ctv_registration_requests/${requestId}`).update({
        status: 'rejected',
        rejectedAt: now(),
        rejectedBy: ctx.email,
      });
      return res.status(200).json({ ok: true });
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
