/* kagi — passkey front-end. No frameworks, no build step. */
(() => {
  'use strict';

  const B64 = {
    toBytes(value) {
      let s = String(value).replace(/-/g, '+').replace(/_/g, '/');
      while (s.length % 4) s += '=';
      const bin = atob(s);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    },
    fromBytes(buffer) {
      const bytes = new Uint8Array(buffer);
      let bin = '';
      for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    },
  };

  const configEl = document.getElementById('kagi-config');
  const config = configEl ? JSON.parse(configEl.textContent || '{}') : {};
  const msgEl = document.getElementById('msg');

  function setMsg(text, ok = false) {
    if (!msgEl) return;
    msgEl.textContent = text || '';
    msgEl.classList.toggle('ok', !!ok && !!text);
    msgEl.classList.toggle('error', !ok && !!text);
  }

  async function post(url, body) {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify(body || {}),
      credentials: 'same-origin',
    });
    let data = null;
    try {
      data = await res.json();
    } catch (_) {
      /* non-JSON error page */
    }
    if (!res.ok) {
      const detail =
        (data && (data.error_description || data.error)) || `HTTP ${res.status}`;
      throw new Error(detail);
    }
    return data || {};
  }

  function humanError(err) {
    if (!err) return '不明なエラーが発生しました';
    switch (err.name) {
      case 'NotAllowedError':
        return '認証がキャンセルされたか、時間切れになりました。';
      case 'SecurityError':
        return 'このオリジンではパスキーを利用できません。';
      case 'InvalidStateError':
        return 'このパスキーは既に登録されています。';
      case 'NotSupportedError':
        return 'この端末・ブラウザではパスキーを利用できません。';
      case 'AbortError':
        return '';
      default:
        return err.message || String(err);
    }
  }

  function creationOptions(publicKey) {
    const pk = JSON.parse(JSON.stringify(publicKey));
    pk.challenge = B64.toBytes(publicKey.challenge);
    pk.user.id = B64.toBytes(publicKey.user.id);
    (pk.excludeCredentials || []).forEach((c) => {
      c.id = B64.toBytes(c.id);
    });
    return pk;
  }

  function requestOptions(publicKey) {
    const pk = JSON.parse(JSON.stringify(publicKey));
    pk.challenge = B64.toBytes(publicKey.challenge);
    (pk.allowCredentials || []).forEach((c) => {
      c.id = B64.toBytes(c.id);
    });
    return pk;
  }

  function serializeCredential(credential) {
    const r = credential.response;
    const out = {
      id: credential.id,
      rawId: B64.fromBytes(credential.rawId),
      type: credential.type,
      clientExtensionResults:
        typeof credential.getClientExtensionResults === 'function'
          ? credential.getClientExtensionResults()
          : {},
      response: {
        clientDataJSON: B64.fromBytes(r.clientDataJSON),
        userHandle: r.userHandle ? B64.fromBytes(r.userHandle) : null,
      },
    };
    if (r.attestationObject) {
      out.response.attestationObject = B64.fromBytes(r.attestationObject);
      out.response.transports =
        typeof r.getTransports === 'function' ? r.getTransports() : [];
    } else {
      out.response.authenticatorData = B64.fromBytes(r.authenticatorData);
      out.response.signature = B64.fromBytes(r.signature);
    }
    return out;
  }

  function passkeysSupported() {
    if (!window.PublicKeyCredential) {
      setMsg('このブラウザはパスキーに対応していません。');
      return false;
    }
    if (!window.isSecureContext) {
      setMsg('パスキーは HTTPS (または localhost) でのみ利用できます。');
      return false;
    }
    return true;
  }

  function markInvalid(input, invalid) {
    if (!input) return;
    if (invalid) input.setAttribute('aria-invalid', 'true');
    else input.removeAttribute('aria-invalid');
  }

  /**
   * Put a button into a pending state without losing its original label.
   * The original markup is restored when the request fails; successful
   * requests usually navigate away.
   */
  function setBusy(button, busy, label) {
    if (!button) return;
    if (busy) {
      if (button.dataset.idleHtml === undefined) {
        button.dataset.idleHtml = button.innerHTML;
      }
      button.textContent = '';
      const spinner = document.createElement('span');
      spinner.className = 'spinner';
      spinner.setAttribute('aria-hidden', 'true');
      const text = document.createElement('span');
      text.className = 'label';
      text.textContent = label || '処理中…';
      button.append(spinner, text);
      button.disabled = true;
      button.setAttribute('aria-busy', 'true');
    } else {
      if (button.dataset.idleHtml !== undefined) {
        button.innerHTML = button.dataset.idleHtml;
        delete button.dataset.idleHtml;
      }
      button.disabled = false;
      button.removeAttribute('aria-busy');
    }
  }

  // -------------------------------------------------------------------------
  // Theme
  // -------------------------------------------------------------------------

  const THEME_KEY = 'kagi-theme';
  const THEME_MODES = ['auto', 'light', 'dark'];
  const THEME_LABELS = { auto: '自動', light: 'ライト', dark: 'ダーク' };

  function readTheme() {
    try {
      const saved = window.localStorage.getItem(THEME_KEY);
      if (saved === 'light' || saved === 'dark') return saved;
    } catch (_) {
      /* storage unavailable */
    }
    return 'auto';
  }

  function applyTheme(mode) {
    const root = document.documentElement;
    if (mode === 'light' || mode === 'dark') root.dataset.theme = mode;
    else delete root.dataset.theme;
    try {
      window.localStorage.setItem(THEME_KEY, mode);
    } catch (_) {
      /* storage unavailable: the choice simply lasts for this page */
    }

    const button = document.getElementById('theme-toggle');
    if (!button) return;
    const label = THEME_LABELS[mode] || THEME_LABELS.auto;
    const text = button.querySelector('.theme-label');
    if (text) text.textContent = label;
    button.dataset.mode = mode;
    button.setAttribute('aria-label', `テーマ: ${label}`);
    button.setAttribute('title', `テーマ: ${label}（クリックで切り替え）`);
  }

  function initTheme() {
    let mode = readTheme();
    applyTheme(mode);
    const button = document.getElementById('theme-toggle');
    if (!button) return;
    button.addEventListener('click', () => {
      const index = THEME_MODES.indexOf(mode);
      mode = THEME_MODES[(index + 1) % THEME_MODES.length];
      applyTheme(mode);
    });
  }

  // -------------------------------------------------------------------------
  // One-time code inputs
  // -------------------------------------------------------------------------

  function initCodeInputs() {
    document.querySelectorAll('[data-code-format]').forEach((input) => {
      const recovery = input.dataset.codeFormat === 'recovery';
      const group = recovery ? 5 : 4;
      const max = recovery ? 10 : 8;

      const format = () => {
        const raw = input.value
          .toUpperCase()
          .replace(/[^A-Z0-9]/g, '')
          .slice(0, max);
        const groups = [];
        for (let i = 0; i < raw.length; i += group) {
          groups.push(raw.slice(i, i + group));
        }
        input.value = groups.join('-');
      };

      input.addEventListener('input', format);
      input.addEventListener('blur', format);
      input.addEventListener('paste', () => window.setTimeout(format, 0));
      format();
    });
  }

  // -------------------------------------------------------------------------
  // Full-page form submissions (consent, device approval, sign-out)
  // -------------------------------------------------------------------------

  function initSubmitBusy() {
    document.querySelectorAll('form[method="post"]').forEach((form) => {
      form.addEventListener('submit', (event) => {
        // Do not disable the submitter: a disabled button is not included in
        // the form data, which would drop the consent/device `decision` value.
        const button =
          event.submitter || form.querySelector('button[type="submit"]');
        if (button) button.setAttribute('aria-busy', 'true');
      });
    });
  }

  // -------------------------------------------------------------------------
  // Sign in
  // -------------------------------------------------------------------------

  function initLogin() {
    const form = document.getElementById('login-form');
    const btn = document.getElementById('btn-login');
    const username = document.getElementById('username');
    let controller = null;

    async function finish(credential) {
      const res = await post('/api/webauthn/login/verify', {
        rid: config.rid,
        credential: serializeCredential(credential),
      });
      location.href = res.next || '/';
    }

    async function interactive(event) {
      if (event) event.preventDefault();
      setMsg('');
      if (controller) {
        controller.abort();
        controller = null;
      }
      if (!passkeysSupported()) return;
      setBusy(btn, true, '確認中…');
      try {
        const { publicKey } = await post('/api/webauthn/login/options', {
          rid: config.rid,
        });
        const credential = await navigator.credentials.get({
          publicKey: requestOptions(publicKey),
        });
        await finish(credential);
      } catch (err) {
        setBusy(btn, false);
        setMsg(humanError(err));
      }
    }

    async function conditional() {
      if (!passkeysSupported()) return;
      if (typeof PublicKeyCredential.isConditionalMediationAvailable !== 'function')
        return;
      let available = false;
      try {
        available = await PublicKeyCredential.isConditionalMediationAvailable();
      } catch (_) {
        return;
      }
      if (!available) return;
      try {
        const { publicKey } = await post('/api/webauthn/login/options', {
          rid: config.rid,
        });
        controller = new AbortController();
        const credential = await navigator.credentials.get({
          publicKey: requestOptions(publicKey),
          mediation: 'conditional',
          signal: controller.signal,
        });
        if (credential) {
          controller = null;
          await finish(credential);
        }
      } catch (_) {
        /* user dismissed the sheet or the request was superseded */
      }
    }

    if (form) form.addEventListener('submit', interactive);
    else if (btn) btn.addEventListener('click', interactive);

    if (username) {
      username.addEventListener('input', () => markInvalid(username, false));
    }
    if (passkeysSupported()) conditional();
  }

  // -------------------------------------------------------------------------
  // Sign up
  // -------------------------------------------------------------------------

  function initSignup() {
    const form = document.getElementById('signup-form');
    const btn = document.getElementById('btn-signup');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      setMsg('');

      const usernameEl = document.getElementById('username');
      const displayEl = document.getElementById('display_name');
      const emailEl = document.getElementById('email');
      const username = usernameEl.value.trim();
      const displayName = displayEl.value.trim();
      const email = emailEl.value.trim();

      markInvalid(usernameEl, false);
      markInvalid(displayEl, false);

      if (username.length < 3 || !/^[A-Za-z0-9._-]+$/.test(username)) {
        markInvalid(usernameEl, true);
        usernameEl.focus();
        setMsg('ユーザー名は3〜64文字の英数字と . _ - で入力してください。');
        return;
      }
      if (!displayName) {
        markInvalid(displayEl, true);
        displayEl.focus();
        setMsg('表示名を入力してください。');
        return;
      }
      if (!passkeysSupported()) return;

      setBusy(btn, true, '作成中…');
      try {
        const start = await post('/api/webauthn/signup/options', {
          username,
          display_name: displayName,
          email: email || null,
          rid: config.rid || null,
        });
        const credential = await navigator.credentials.create({
          publicKey: creationOptions(start.publicKey),
        });
        const res = await post('/api/webauthn/signup/verify', {
          rid: start.rid,
          credential: serializeCredential(credential),
        });
        location.href = res.next || '/';
      } catch (err) {
        setBusy(btn, false);
        setMsg(humanError(err));
      }
    });
  }

  // -------------------------------------------------------------------------
  // Account
  // -------------------------------------------------------------------------

  function initAccount() {
    const btnAdd = document.getElementById('btn-add-passkey');

    if (btnAdd) {
      btnAdd.addEventListener('click', async () => {
        setMsg('');
        if (!passkeysSupported()) return;
        setBusy(btnAdd, true, '追加中…');
        try {
          const start = await post('/api/webauthn/passkey/options', {});
          const credential = await navigator.credentials.create({
            publicKey: creationOptions(start.publicKey),
          });
          await post('/api/webauthn/passkey/verify', {
            rid: start.rid,
            credential: serializeCredential(credential),
          });
          setMsg('パスキーを追加しました。', true);
          window.setTimeout(() => location.reload(), 700);
        } catch (err) {
          setBusy(btnAdd, false);
          setMsg(humanError(err));
        }
      });
    }

    // Row actions are delegated so that server-rendered lists need no inline JS.
    document.addEventListener('click', async (event) => {
      const el = event.target.closest('[data-action]');
      if (!el) return;
      const action = el.dataset.action;
      try {
        if (action === 'rename-passkey') {
          const next = window.prompt('パスキー名', el.dataset.name || 'パスキー');
          if (next === null) return;
          const name = next.trim();
          if (!name) {
            setMsg('パスキー名を入力してください。');
            return;
          }
          setBusy(el, true, '保存中…');
          await post('/api/account/passkey/rename', {
            id: el.dataset.id,
            name,
          });
          setMsg('パスキー名を変更しました。', true);
          window.setTimeout(() => location.reload(), 500);
        } else if (action === 'delete-passkey') {
          if (
            !window.confirm(
              'このパスキーを削除しますか？削除すると、このパスキーではサインインできなくなります。'
            )
          )
            return;
          setBusy(el, true, '削除中…');
          await post('/api/account/passkey/delete', { id: el.dataset.id });
          setMsg('パスキーを削除しました。', true);
          window.setTimeout(() => location.reload(), 500);
        } else if (action === 'revoke-session') {
          if (!window.confirm('このデバイスをサインアウトしますか？')) return;
          setBusy(el, true, '処理中…');
          const res = await post('/api/account/sessions/revoke', {
            id: el.dataset.id,
          });
          if (res.current) {
            location.href = '/login';
            return;
          }
          setMsg('デバイスをサインアウトしました。', true);
          window.setTimeout(() => location.reload(), 500);
        } else if (action === 'revoke-consent') {
          if (!window.confirm('このアプリへのアクセスを取り消しますか？')) return;
          setBusy(el, true, '処理中…');
          await post('/api/account/consent/revoke', {
            client_id: el.dataset.client,
          });
          setMsg('アクセスを取り消しました。', true);
          window.setTimeout(() => location.reload(), 500);
        }
      } catch (err) {
        setBusy(el, false);
        setMsg(humanError(err));
      }
    });

    const profile = document.getElementById('profile-form');
    if (profile) {
      profile.addEventListener('submit', async (event) => {
        event.preventDefault();
        setMsg('');
        const button = profile.querySelector('button[type="submit"]');
        const nameEl = document.getElementById('profile-display-name');
        const name = nameEl.value.trim();
        if (!name) {
          markInvalid(nameEl, true);
          nameEl.focus();
          setMsg('表示名を入力してください。');
          return;
        }
        markInvalid(nameEl, false);
        setBusy(button, true, '保存中…');
        try {
          await post('/api/account/profile', {
            display_name: name,
            email: document.getElementById('profile-email').value.trim() || null,
          });
          setMsg('プロフィールを保存しました。', true);
          window.setTimeout(() => location.reload(), 500);
        } catch (err) {
          setBusy(button, false);
          setMsg(humanError(err));
        }
      });
    }

    const revokeOthers = document.getElementById('btn-revoke-others');
    if (revokeOthers) {
      revokeOthers.addEventListener('click', async () => {
        if (!window.confirm('このデバイス以外をすべてサインアウトしますか？')) return;
        setBusy(revokeOthers, true, '処理中…');
        try {
          const res = await post('/api/account/sessions/revoke-others', {});
          setMsg(`${res.revoked || 0} 台のデバイスをサインアウトしました。`, true);
          window.setTimeout(() => location.reload(), 600);
        } catch (err) {
          setBusy(revokeOthers, false);
          setMsg(humanError(err));
        }
      });
    }

    const generate = document.getElementById('btn-generate-recovery');
    if (generate) {
      generate.addEventListener('click', async () => {
        if (
          !window.confirm(
            '既存のリカバリーコードはすべて無効になります。新しく生成しますか？'
          )
        )
          return;
        setBusy(generate, true, '生成中…');
        try {
          const res = await post('/api/account/recovery/generate', {});
          const list = document.getElementById('recovery-list');
          const output = document.getElementById('recovery-output');
          list.innerHTML = '';
          (res.codes || []).forEach((code) => {
            const li = document.createElement('li');
            li.textContent = code;
            list.appendChild(li);
          });
          output.hidden = false;
          setMsg('新しいリカバリーコードを生成しました。', true);
        } catch (err) {
          setMsg(humanError(err));
        } finally {
          setBusy(generate, false);
        }
      });
    }

    const copy = document.getElementById('btn-copy-recovery');
    if (copy) {
      copy.addEventListener('click', async () => {
        const codes = Array.from(
          document.querySelectorAll('#recovery-list li')
        ).map((li) => li.textContent);
        if (!codes.length) {
          setMsg('コピーするコードがありません。先に生成してください。');
          return;
        }
        try {
          await navigator.clipboard.writeText(codes.join('\n'));
          const original = copy.textContent;
          copy.textContent = 'コピーしました';
          setMsg('リカバリーコードをコピーしました。', true);
          window.setTimeout(() => {
            copy.textContent = original;
          }, 1600);
        } catch (_) {
          setMsg('コピーできませんでした。コードを選択して手動でコピーしてください。');
        }
      });
    }

    const del = document.getElementById('delete-form');
    if (del) {
      del.addEventListener('submit', async (event) => {
        event.preventDefault();
        const input = document.getElementById('confirm-username');
        const username = input.value.trim();
        const button = del.querySelector('button[type="submit"]');
        markInvalid(input, false);
        if (!username) {
          markInvalid(input, true);
          input.focus();
          setMsg('確認のためユーザー名を入力してください。');
          return;
        }
        if (config.username && username !== config.username) {
          markInvalid(input, true);
          input.focus();
          setMsg('入力されたユーザー名がアカウントと一致しません。');
          return;
        }
        if (!window.confirm('本当にアカウントを削除しますか？この操作は取り消せません。'))
          return;
        setBusy(button, true, '削除中…');
        try {
          await post('/api/account/delete', { username });
          location.href = '/login';
        } catch (err) {
          setBusy(button, false);
          setMsg(humanError(err));
        }
      });
    }
  }

  // -------------------------------------------------------------------------
  // Recovery-code sign in
  // -------------------------------------------------------------------------

  function initRecover() {
    const form = document.getElementById('recover-form');
    if (!form) return;
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      setMsg('');
      const usernameEl = document.getElementById('recover-username');
      const codeEl = document.getElementById('recover-code');
      const button = document.getElementById('btn-recover');
      const username = usernameEl.value.trim();
      const code = codeEl.value.trim();
      markInvalid(usernameEl, false);
      markInvalid(codeEl, false);

      if (!username) {
        markInvalid(usernameEl, true);
        usernameEl.focus();
        setMsg('ユーザー名を入力してください。');
        return;
      }
      if (code.replace(/[^A-Za-z0-9]/g, '').length < 8) {
        markInvalid(codeEl, true);
        codeEl.focus();
        setMsg('リカバリーコードを確認してください。');
        return;
      }

      setBusy(button, true, '確認中…');
      try {
        const res = await post('/api/recover', {
          username,
          code,
          rid: config.rid || null,
        });
        location.href = res.next || '/';
      } catch (err) {
        setBusy(button, false);
        setMsg(humanError(err));
      }
    });
  }

  // -------------------------------------------------------------------------
  // Demo relying party (uses the public SDK in /static/kagi.js)
  // -------------------------------------------------------------------------

  function initDemo() {
    const btn = document.getElementById('demo-login');
    const logoutBtn = document.getElementById('demo-logout');
    const out = document.getElementById('demo-output');
    const sdk = window.Kagi;
    if (!btn || !sdk) return;

    sdk.configure({
      issuer: config.issuer,
      clientId: config.client_id,
      redirectUri: config.redirect_uri,
      scope: config.scope,
    });

    async function show(session) {
      const user = await sdk.userinfo(session.tokens.access_token);
      out.hidden = false;
      out.textContent = JSON.stringify(
        {
          id_token_claims: session.claims,
          userinfo: user,
          scope: session.tokens.scope,
          expires_in: session.tokens.expires_in,
        },
        null,
        2
      );
      btn.hidden = true;
      logoutBtn.hidden = false;
    }

    const params = new URLSearchParams(location.search);
    if (params.has('code') || params.has('error')) {
      sdk
        .handleCallback()
        .then((session) => (session ? show(session) : null))
        .catch((err) => setMsg(humanError(err)));
    } else {
      const session = sdk.session();
      if (session) show(session).catch((err) => setMsg(humanError(err)));
    }

    btn.addEventListener('click', () => {
      setMsg('');
      sdk.login().catch((err) => setMsg(humanError(err)));
    });

    logoutBtn.addEventListener('click', () => sdk.logout());
  }

  initTheme();
  initCodeInputs();
  initSubmitBusy();

  if (config.flow === 'login') initLogin();
  else if (config.flow === 'signup') initSignup();
  else if (config.flow === 'account') initAccount();
  else if (config.flow === 'recover') initRecover();
  else if (config.flow === 'demo') initDemo();
})();
