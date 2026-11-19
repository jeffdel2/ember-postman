require('dotenv').config();
const express = require('express');
const session = require('express-session');
const crypto = require('crypto');

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'ember-dev-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

const {
  AUTH0_DOMAIN,
  CO_CLIENT_ID,
  DB_CONNECTION,
  PORT = 3000
} = process.env;

const SCOPE = 'openid profile email offline_access read:me:authentication_methods create:me:authentication_methods read:me:factors';
const AUDIENCE = `https://${AUTH0_DOMAIN}/me/`;

// ---------------------------------------------------------------------------
// PKCE helpers
// ---------------------------------------------------------------------------

function generateCodeVerifier() {
  const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  const bytes = crypto.randomBytes(43);
  return Array.from(bytes).map(b => charset[b % charset.length]).join('');
}

function generateCodeChallenge(verifier) {
  return crypto.createHash('sha256')
    .update(verifier)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

// ---------------------------------------------------------------------------
// Auth0 /e/authorize helper
// ---------------------------------------------------------------------------

async function embeddedAuthorize(body) {
  const res = await fetch(`https://${AUTH0_DOMAIN}/e/authorize`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  const data = await res.json();
  return { status: res.status, data };
}

// ---------------------------------------------------------------------------
// Token exchange (shared by both OTP and password paths)
// ---------------------------------------------------------------------------

async function exchangeCodeForTokens(authCode, pkceCodeVerifier) {
  const res = await fetch(`https://${AUTH0_DOMAIN}/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'authorization_code',
      client_id: CO_CLIENT_ID,
      code_verifier: pkceCodeVerifier,
      code: authCode,
      scope: SCOPE,
      audience: AUDIENCE,
      identifier: 'ember-app-dev',
      rmd: 'true'
    })
  });
  const data = await res.json();
  return { status: res.status, data };
}

// ---------------------------------------------------------------------------
// Journey presets — each defines a named set of capabilities sent at initiate
// ---------------------------------------------------------------------------

const JOURNEYS = {
  all: {
    label: 'All methods',
    icon: 'layers',
    capabilities: [
      'action:identify:email:v1',
      'action:challenge:email:v1',
      'action:verify:otp:v1',
      'action:challenge:password:v1',
      'action:verify:password:v1',
      'action:enroll:password:v1',
      'action:signup:confirm:v1',
    ],
  },
  passwordless: {
    label: 'Passwordless',
    icon: 'mail',
    capabilities: [
      'action:identify:email:v1',
      'action:challenge:email:v1',
      'action:verify:otp:v1',
    ],
  },
  password: {
    label: 'Password',
    icon: 'lock',
    capabilities: [
      'action:identify:email:v1',
      'action:challenge:password:v1',
      'action:verify:password:v1',
    ],
  },
};

const DEFAULT_JOURNEY = 'all';

// ---------------------------------------------------------------------------
// Map raw action strings to human-readable labels + Lucide icon names
// ---------------------------------------------------------------------------

const METHOD_LABELS = {
  'action:challenge:email:v1':  { label: 'Email code',  icon: 'mail',   sub: 'We\'ll send a one-time code to your email' },
  'action:verify:password:v1':  { label: 'Password',    icon: 'lock',   sub: 'Sign in with your password' },
};

const SUPPORTED_METHODS = new Set(Object.keys(METHOD_LABELS));

// ---------------------------------------------------------------------------
// JWT decode (no verification — display only)
// ---------------------------------------------------------------------------

function decodeJwtPayload(token) {
  try {
    const payload = token.split('.')[1];
    return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Render token claims as a compact table
// ---------------------------------------------------------------------------

function renderTokenClaims(claims) {
  if (!claims) return '<p style="color:#999;font-size:13px">Could not decode token.</p>';

  const PRIORITY = ['email', 'name', 'nickname', 'sub', 'aud', 'iat', 'exp'];
  const fmt = (key, val) => {
    if ((key === 'iat' || key === 'exp') && typeof val === 'number') {
      return new Date(val * 1000).toLocaleString();
    }
    if (Array.isArray(val)) return val.join(', ');
    return String(val);
  };

  const ordered = [
    ...PRIORITY.filter(k => k in claims),
    ...Object.keys(claims).filter(k => !PRIORITY.includes(k))
  ];

  const rows = ordered.map(k => `
    <tr>
      <td class="claim-key">${k}</td>
      <td class="claim-val">${fmt(k, claims[k])}</td>
    </tr>`).join('');

  return `
    <details>
      <summary class="raw-toggle">View token claims</summary>
      <table class="claims-table" style="margin-top:10px">
        <tbody>${rows}</tbody>
      </table>
    </details>`;
}

// ---------------------------------------------------------------------------
// Minimal HTML layout
// ---------------------------------------------------------------------------

function page(title, body) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title} — Ember</title>
  <script src="https://unpkg.com/lucide@latest/dist/umd/lucide.min.js"></script>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: #f0eff5;
      margin: 0;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
    }
    .card {
      background: #fff;
      border: 1px solid #e4e3ec;
      border-radius: 16px;
      padding: 40px;
      width: 100%;
      max-width: 560px;
      box-shadow: 0 4px 24px rgba(1,33,105,.08), 0 1px 4px rgba(0,0,0,.05);
      position: relative;
    }
    .logo {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 28px;
    }
    .logo-mark {
      width: 28px; height: 28px;
      background: linear-gradient(135deg, #012169, #98a6c6);
      border-radius: 7px;
      display: flex; align-items: center; justify-content: center;
    }
    .logo-name { font-size: 15px; font-weight: 600; color: #1d1d1f; letter-spacing: .01em; }
    h1 { margin: 0 0 6px; font-size: 20px; font-weight: 600; color: #1d1d1f; }
    p.sub { color: #888; margin: 0 0 24px; font-size: 14px; }
    p.sub strong { color: #555; font-weight: 500; }
    label { font-size: 13px; font-weight: 500; color: #555; display: block; margin-bottom: 6px; }
    input[type=email], input[type=text], input[type=password] {
      width: 100%;
      padding: 10px 12px;
      font-size: 15px;
      background: #fafafa;
      border: 1px solid #e0dff0;
      border-radius: 10px;
      margin-bottom: 16px;
      outline: none;
      color: #1d1d1f;
      transition: border-color .15s, box-shadow .15s;
    }
    input::placeholder { color: #bbb; }
    input:focus { border-color: #012169; box-shadow: 0 0 0 3px rgba(1,33,105,.12); }
    .btn-primary {
      display: block;
      width: 100%;
      background: #012169;
      color: white;
      border: none;
      padding: 11px;
      font-size: 15px;
      border-radius: 10px;
      cursor: pointer;
      font-weight: 500;
      transition: background .15s, transform .1s;
    }
    .btn-primary:hover { background: #01195a; }
    .btn-primary:active { transform: scale(.98); }

    /* Side-by-side method cards */
    .method-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
      margin-bottom: 20px;
    }
    .method-card {
      background: #fafafa;
      border: 1px solid #e4e3ec;
      border-radius: 12px;
      padding: 20px 14px;
      cursor: pointer;
      text-align: center;
      transition: border-color .15s, box-shadow .15s, transform .1s;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 10px;
    }
    .method-card:hover {
      border-color: #012169;
      box-shadow: 0 2px 12px rgba(1,33,105,.1);
      transform: translateY(-1px);
    }
    .method-card:active { transform: translateY(0); }
    .method-icon {
      width: 40px; height: 40px;
      background: rgba(1,33,105,.07);
      border-radius: 10px;
      display: flex; align-items: center; justify-content: center;
      color: #012169;
    }
    .method-card-label { font-size: 14px; font-weight: 600; color: #1d1d1f; }
    .method-card-sub { font-size: 11px; color: #999; line-height: 1.4; }

    .error {
      background: #fff5f5;
      border: 1px solid #fecaca;
      border-radius: 10px;
      padding: 12px;
      font-size: 13px;
      color: #c0392b;
      margin-bottom: 16px;
    }
    .error pre { margin: 6px 0 0; font-size: 11px; overflow: auto; color: #888; }

    /* Claims table */
    .claims-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
      margin-top: 4px;
    }
    .claims-table tr { border-bottom: 1px solid #f0eff5; }
    .claims-table tr:last-child { border-bottom: none; }
    .claim-key {
      padding: 7px 10px 7px 0;
      color: #aaa;
      font-weight: 500;
      white-space: nowrap;
      width: 1%;
      vertical-align: top;
    }
    .claim-val {
      padding: 7px 0;
      color: #444;
      word-break: break-all;
    }
    .raw-toggle {
      cursor: pointer;
      font-size: 12px;
      color: #012169;
      user-select: none;
    }
    .raw-toggle:hover { text-decoration: underline; }

    .success-wrap {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 20px;
    }
    .success-badge {
      width: 34px; height: 34px;
      background: #f0fdf4;
      border: 1px solid #bbf7d0;
      border-radius: 50%;
      display: flex; align-items: center; justify-content: center;
      color: #16a34a;
      flex-shrink: 0;
    }
    .success-wrap h1 { margin: 0; font-size: 20px; }
    a { color: #012169; text-decoration: none; font-size: 13px; }
    a:hover { text-decoration: underline; }
    .divider { border: none; border-top: 1px solid #f0eff5; margin: 20px 0; }

    /* Journey dropdown — top-right corner of card */
    .journey-select-wrap {
      position: absolute;
      top: 16px;
      right: 16px;
    }
    .journey-select {
      appearance: none;
      background: #f5f4fb url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'%3E%3Cpath d='M1 1l4 4 4-4' stroke='%23999' stroke-width='1.5' fill='none' stroke-linecap='round'/%3E%3C/svg%3E") no-repeat right 8px center;
      border: 1px solid #e0dff0;
      border-radius: 8px;
      padding: 5px 26px 5px 10px;
      font-size: 12px;
      color: #666;
      cursor: pointer;
      outline: none;
      transition: border-color .15s;
    }
    .journey-select:hover { border-color: #012169; }
    .journey-select:focus { border-color: #012169; box-shadow: 0 0 0 2px rgba(1,33,105,.12); }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">
      <div class="logo-mark">
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
          <circle cx="8" cy="8" r="4" fill="white" fill-opacity=".95"/>
          <circle cx="8" cy="8" r="6.5" stroke="white" stroke-opacity=".5" stroke-width="1"/>
        </svg>
      </div>
      <span class="logo-name">Ember</span>
    </div>
    ${body}
  </div>
  <script>lucide.createIcons();</script>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

// Step 0: Email form
app.get('/', (req, res) => {
  const active = req.query.journey || DEFAULT_JOURNEY;

  const options = Object.entries(JOURNEYS).map(([key, j]) =>
    `<option value="${key}" ${key === active ? 'selected' : ''}>${j.label}</option>`
  ).join('');

  const journeyDropdown = `
    <div class="journey-select-wrap">
      <select class="journey-select" onchange="location='/?journey='+this.value">
        ${options}
      </select>
    </div>`;

  res.send(page('Sign In', `
    ${journeyDropdown}
    <h1>Sign in</h1>
    <p class="sub">Enter your email to continue.</p>
    <form method="POST" action="/signin/start">
      <input type="hidden" name="journey" value="${active}">
      <label for="email">Email address</label>
      <input type="email" id="email" name="email" placeholder="you@example.com" required autofocus>
      <button type="submit" class="btn-primary">Continue</button>
    </form>
  `));
});

// Step 1: Initiate + Identify → show method choice based on `next`
app.post('/signin/start', async (req, res) => {
  const { email, journey } = req.body;
  if (!email) return res.redirect('/');

  const selectedJourney = JOURNEYS[journey] ?? JOURNEYS[DEFAULT_JOURNEY];
  console.log(`[signin/start] journey="${journey}" capabilities:`, selectedJourney.capabilities);

  const verifier = generateCodeVerifier();
  const challenge = generateCodeChallenge(verifier);

  // Initiate
  let result = await embeddedAuthorize({
    client_id: CO_CLIENT_ID,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    connection: DB_CONNECTION,
    capabilities: selectedJourney.capabilities,
    scope: SCOPE,
    audience: AUDIENCE
  });

  if (result.status !== 403) {
    return res.send(page('Error', errorCard('Initiate failed', result)));
  }

  // Identify
  result = await embeddedAuthorize({
    client_id: CO_CLIENT_ID,
    auth_session: result.data.auth_session,
    action: 'action:identify:email:v1',
    email
  });

  if (result.status !== 403) {
    return res.send(page('Error', errorCard('Identify failed', result)));
  }

  //console.log('[identify response]', JSON.stringify(result.data, null, 2));

  req.session.auth_session = result.data.auth_session;
  req.session.pkce_code_verifier = verifier;
  req.session.email = email;
  req.session.next = result.data.next ?? [];

  const rawNext = req.session.next;
  const nextActions = rawNext.map(n => (typeof n === 'string' ? n : n.action ?? n.type ?? n)).filter(Boolean);
  const available = nextActions.filter(a => SUPPORTED_METHODS.has(a));

  if (available.length === 0) {
    console.warn('[signin/start] No supported methods in next:', rawNext, '— defaulting to OTP');
    available.push('action:challenge:email:v1');
  }

  const cards = available.map(action => {
    const info = METHOD_LABELS[action];
    return `
      <form method="POST" action="/signin/method" style="display:contents">
        <button type="submit" name="method" value="${action}" class="method-card">
          <div class="method-icon">
            <i data-lucide="${info.icon}" width="20" height="20"></i>
          </div>
          <span class="method-card-label">${info.label}</span>
          <span class="method-card-sub">${info.sub}</span>
        </button>
      </form>`;
  }).join('');

  res.send(page('How would you like to sign in?', `
    <h1>How would you like to sign in?</h1>
    <p class="sub">Signing in as <strong>${email}</strong></p>
    <div class="method-grid">${cards}</div>
    <hr class="divider">
    <a href="/">Use a different email</a>
  `));
});

// Step 2a: User chose a method
app.post('/signin/method', async (req, res) => {
  const { method } = req.body;
  const { auth_session, email } = req.session;

  if (!auth_session) return res.redirect('/');

  if (method === 'action:challenge:email:v1') {
    const nextObj = (req.session.next ?? []).find(n => n.action === 'action:challenge:email:v1');
    const index = nextObj?.index ?? 0;

    const result = await embeddedAuthorize({
      client_id: CO_CLIENT_ID,
      auth_session,
      action: 'action:challenge:email:v1',
      index
    });

    if (result.status !== 403) {
      return res.send(page('Error', errorCard('OTP challenge failed', result)));
    }

    req.session.auth_session = result.data.auth_session;

    return res.send(page('Check your email', `
      <h1>Check your email</h1>
      <p class="sub">We sent a one-time code to <strong>${email}</strong>.</p>
      <form method="POST" action="/signin/verify/otp">
        <label for="otp">One-time code</label>
        <input type="text" id="otp" name="otp" placeholder="123456" required autofocus
               inputmode="numeric" autocomplete="one-time-code" maxlength="8">
        <button type="submit" class="btn-primary">Verify</button>
      </form>
      <hr class="divider">
      <a href="/">Start over</a>
    `));
  }

  if (method === 'action:verify:password:v1') {
    return res.send(page('Enter your password', `
      <h1>Enter your password</h1>
      <p class="sub">Signing in as <strong>${email}</strong></p>
      <form method="POST" action="/signin/verify/password">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" required autofocus autocomplete="current-password">
        <button type="submit" class="btn-primary">Sign in</button>
      </form>
      <hr class="divider">
      <a href="/">Start over</a>
    `));
  }

  res.send(page('Error', errorCard(`Unsupported method: ${method}`, { status: 400, data: {} })));
});

// Step 2b: Verify OTP → exchange tokens
app.post('/signin/verify/otp', async (req, res) => {
  const { otp } = req.body;
  const { auth_session, pkce_code_verifier } = req.session;

  if (!auth_session || !pkce_code_verifier) return res.redirect('/');

  const result = await embeddedAuthorize({
    client_id: CO_CLIENT_ID,
    auth_session,
    action: 'action:verify:otp:v1',
    type: 'oob',
    otp
  });

  if (result.status !== 200) {
    return res.send(page('Invalid code', `
      <h1>Invalid code</h1>
      <div class="error">
        That code didn't work — it may have expired.
        <pre>${JSON.stringify(result.data, null, 2)}</pre>
      </div>
      <a href="/">Start over</a>
    `));
  }

  return finishSignIn(req, res, result.data.authorization_code);
});

// Step 2c: Verify password → exchange tokens
app.post('/signin/verify/password', async (req, res) => {
  const { password } = req.body;
  const { auth_session, pkce_code_verifier } = req.session;

  if (!auth_session || !pkce_code_verifier) return res.redirect('/');

  const result = await embeddedAuthorize({
    client_id: CO_CLIENT_ID,
    auth_session,
    action: 'action:verify:password:v1',
    password
  });

  if (result.status !== 200) {
    return res.send(page('Incorrect password', `
      <h1>Incorrect password</h1>
      <div class="error">
        That password didn't work.
        <pre>${JSON.stringify(result.data, null, 2)}</pre>
      </div>
      <a href="/">Start over</a>
    `));
  }

  return finishSignIn(req, res, result.data.authorization_code);
});

// ---------------------------------------------------------------------------
// Shared: exchange code and render success
// ---------------------------------------------------------------------------

async function finishSignIn(req, res, authCode) {
  const { pkce_code_verifier } = req.session;

  const { status, data: tokens } = await exchangeCodeForTokens(authCode, pkce_code_verifier);

  if (!tokens.access_token) {
    return res.send(page('Token error', errorCard('Token exchange failed', { status, data: tokens })));
  }

  req.session.access_token = tokens.access_token;
  req.session.refresh_token = tokens.refresh_token;

  const claims = decodeJwtPayload(tokens.access_token);

  res.send(page('Signed in', `
    <div class="success-wrap">
      <div class="success-badge">
        <i data-lucide="check" width="18" height="18"></i>
      </div>
      <h1>Signed in</h1>
    </div>
    ${renderTokenClaims(claims)}
    <hr class="divider">
    <a href="/">Sign in again</a>
  `));
}

// ---------------------------------------------------------------------------
// Error helper
// ---------------------------------------------------------------------------

function errorCard(label, result) {
  return `
    <h1>Something went wrong</h1>
    <div class="error">
      <strong>${label}</strong> (HTTP ${result.status})
      <pre>${JSON.stringify(result.data, null, 2)}</pre>
    </div>
    <a href="/">Start over</a>
  `;
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

app.listen(PORT, () => {
  console.log(`Ember app running at http://localhost:${PORT}`);
});
