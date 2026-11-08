// Zenv DMZ CA: self-service UI.
//
// A thin client over the JSON API. Security notes:
// * All dynamic content is inserted with textContent (never innerHTML), so certificate
//   fields cannot inject markup.
// * The API token lives in sessionStorage only (cleared when the tab closes).
// * Private keys returned by the keygen endpoint are turned into downloads client-side
//   and never stored.
"use strict";

(() => {
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const TOKEN_KEY = "zenv-ca-token";
  const state = { token: null, me: null, ca: null, revokeSerial: null };

  // ---------- small helpers ----------
  function storage(op, value) {
    try {
      if (op === "get") return sessionStorage.getItem(TOKEN_KEY);
      if (op === "set") sessionStorage.setItem(TOKEN_KEY, value);
      if (op === "del") sessionStorage.removeItem(TOKEN_KEY);
    } catch (_) { /* storage unavailable (private mode): keep it in memory only */ }
    return null;
  }

  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") node.className = v;
      else if (k === "text") node.textContent = v;
      else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v === true ? "" : String(v));
    }
    for (const c of children.flat()) {
      if (c === null || c === undefined || c === false) continue;
      node.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return node;
  }

  function toast(message, kind = "info") {
    const t = $("#toast");
    t.textContent = message;
    t.className = `show ${kind}`;
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => { t.className = ""; }, 4500);
  }

  async function api(path, { method = "GET", body, raw = false, auth = true } = {}) {
    const headers = { Accept: raw ? "*/*" : "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (auth && state.token) headers.Authorization = `Bearer ${state.token}`;
    const res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    if (!res.ok) {
      let detail = `${res.status} ${res.statusText}`;
      try { const p = await res.json(); detail = p.detail || p.title || detail; } catch (_) { /* not JSON */ }
      if (res.status === 401 && auth && state.me) signOut(false);
      const err = new Error(detail);
      err.status = res.status;
      throw err;
    }
    return raw ? res : res.json();
  }

  function saveBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = el("a", { href: url, download: filename });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function filenameFrom(res, fallback) {
    const cd = res.headers.get("Content-Disposition") || "";
    const m = /filename="([^"]+)"/.exec(cd);
    return m ? m[1] : fallback;
  }

  async function downloadCert(serial, format) {
    try {
      const res = await api(`/api/v1/certificates/${encodeURIComponent(serial)}/download?format=${format}`, { raw: true });
      saveBlob(await res.blob(), filenameFrom(res, `${serial}.${format}`));
    } catch (e) { toast(e.message, "error"); }
  }

  function b64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function bytesToB64(bytes) {
    let bin = "";
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) bin += String.fromCharCode(...bytes.subarray(i, i + chunk));
    return btoa(bin);
  }

  const lines = (text) => (text || "").split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
  const fmtTime = (unix) => new Date(unix * 1000).toLocaleString();
  const daysLeft = (unix) => Math.round((unix * 1000 - Date.now()) / 86400000);

  function statusBadge(status) {
    const map = { active: "ok", revoked: "bad", expired: "muted" };
    return el("span", { class: `badge badge-${map[status] || "muted"}`, text: status });
  }

  // ---------- session ----------
  function renderSession() {
    const box = $("#session");
    box.replaceChildren();
    if (state.me) {
      box.append(
        el("span", { class: "who" }, el("span", { class: "muted", text: "Signed in as " }), el("strong", { text: state.me.name }),
          state.me.role === "admin" ? el("span", { class: "badge badge-info", text: "admin" }) : null),
        el("button", { class: "btn btn-small", type: "button", text: "Sign out", onclick: () => signOut(true) }),
      );
    }
    $('[data-tab="audit"]').hidden = !(state.me && state.me.role === "admin");
    for (const area of $$("[data-needs-auth]")) {
      const prev = area.previousElementSibling;
      const signin = prev && prev.matches("[data-signin]") ? prev : null;
      if (state.me) {
        area.hidden = false;
        if (signin) signin.remove();
      } else {
        area.hidden = true;
        if (!signin) {
          const form = $("#signin-template").content.firstElementChild.cloneNode(true);
          form.addEventListener("submit", onSignIn);
          area.before(form);
        }
      }
    }
  }

  async function onSignIn(ev) {
    ev.preventDefault();
    const token = new FormData(ev.target).get("token").trim();
    state.token = token;
    try {
      state.me = await api("/api/v1/me");
      storage("set", token);
      renderSession();
      toast(`Welcome, ${state.me.name}`, "ok");
      showTab(currentTab());
    } catch (e) {
      state.token = null;
      toast(e.status === 401 ? "That token was not accepted." : e.message, "error");
    }
  }

  function signOut(explicit) {
    state.token = null;
    state.me = null;
    storage("del");
    renderSession();
    toast(explicit ? "Signed out" : "Session expired; please sign in again");
  }

  // ---------- tabs ----------
  const currentTab = () => (location.hash || "#request").slice(1);

  function showTab(name) {
    const tabs = $$("[data-tab]");
    if (!tabs.some((t) => t.dataset.tab === name && !t.hidden)) name = "request";
    for (const t of tabs) t.setAttribute("aria-selected", String(t.dataset.tab === name));
    for (const p of $$("[data-panel]")) p.hidden = p.dataset.panel !== name;
    if (name === "certs" && state.me) loadCerts();
    if (name === "audit" && state.me) loadAudit();
    if (name === "trust") renderTrust();
  }

  // ---------- CA info / form defaults ----------
  const PROFILE_LABELS = { server: "TLS server", client: "TLS client (mTLS)", "server-client": "Server + client" };

  async function loadCaInfo() {
    try {
      state.ca = await api("/api/v1/ca", { auth: false });
    } catch (e) {
      toast(`Cannot reach the CA: ${e.message}`, "error");
      return;
    }
    for (const sel of $$("[data-profiles]")) {
      sel.replaceChildren(...state.ca.profiles.map((p) => el("option", { value: p, text: PROFILE_LABELS[p] || p })));
    }
    for (const sel of $$("[data-algorithms]")) {
      sel.replaceChildren(...state.ca.key_algorithms.map((a) => el("option", { value: a, text: a })));
    }
    for (const input of $$("[data-validity]")) {
      input.value = state.ca.default_validity_days;
      input.max = state.ca.max_validity_days;
    }
    if (!state.ca.allow_server_side_keygen) $('[data-mode="keygen"]').hidden = true;
    $("#helper-names").placeholder = `app.${state.ca.allowed_dns_suffixes[0] || "example.internal"}`;
    renderHelper();
  }

  // ---------- request ----------
  function setMode(mode) {
    for (const b of $$("[data-mode]")) b.setAttribute("aria-checked", String(b.dataset.mode === mode));
    for (const p of $$("[data-mode-panel]")) p.hidden = p.dataset.modePanel !== mode;
    $("#issue-result").replaceChildren();
  }

  function renderHelper() {
    const names = lines($("#helper-names").value);
    const first = names[0] || $("#helper-names").placeholder;
    const all = names.length ? names : [first];
    const base = first.split(".")[0].replace(/[^a-z0-9-]/gi, "_");
    const san = all.map((n) => (/^[\d.:]+$/.test(n) ? `IP:${n}` : `DNS:${n}`)).join(",");
    $("#helper-cmd").textContent =
      "openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \\\n" +
      `  -keyout ${base}.key -out ${base}.csr \\\n` +
      `  -subj "/CN=${first}" \\\n` +
      `  -addext "subjectAltName=${san}"`;
  }

  function certSummary(cert) {
    return el("dl", { class: "kv" },
      el("dt", { text: "Common name" }), el("dd", { text: cert.common_name }),
      el("dt", { text: "Names" }), el("dd", { text: [...cert.dns_names, ...cert.ip_addresses].join(", ") }),
      el("dt", { text: "Serial" }), el("dd", {}, el("code", { text: cert.serial })),
      el("dt", { text: "Profile" }), el("dd", { text: PROFILE_LABELS[cert.profile] || cert.profile }),
      el("dt", { text: "Key" }), el("dd", { text: cert.key_algorithm }),
      el("dt", { text: "Valid until" }), el("dd", { text: `${fmtTime(cert.not_after)} (${daysLeft(cert.not_after)} days)` }),
      el("dt", { text: "SHA-256" }), el("dd", {}, el("code", { class: "wrap", text: cert.fingerprint_sha256 })),
    );
  }

  function downloadButtons(serial) {
    const formats = [["chain", "Chain (PEM)"], ["pem", "Certificate (PEM)"], ["fullchain", "Full chain (PEM)"], ["der", "DER (.cer)"]];
    return el("div", { class: "btn-row" },
      ...formats.map(([fmt, label]) => el("button", { class: "btn btn-small", type: "button", text: label, onclick: () => downloadCert(serial, fmt) })));
  }

  function renderIssued(cert, keyMaterial) {
    const card = el("div", { class: "card result ok" },
      el("h2", { text: "Certificate issued" }),
      certSummary(cert),
      el("h3", { text: "Download" }),
      downloadButtons(cert.serial),
    );
    if (keyMaterial) {
      const base = cert.common_name.replace(/[^a-z0-9.-]/gi, "_");
      card.append(
        el("p", { class: "callout warn" }, el("strong", { text: "Save your private key now. " }), "It is not stored by the CA and cannot be downloaded again."),
        el("div", { class: "btn-row" },
          el("button", { class: "btn btn-primary btn-small", type: "button", text: "PKCS#12 bundle (.p12)",
            onclick: () => saveBlob(new Blob([b64ToBytes(keyMaterial.pkcs12_base64)], { type: "application/x-pkcs12" }), `${base}.p12`) }),
          el("button", { class: "btn btn-small", type: "button", text: "Private key (PEM)",
            onclick: () => saveBlob(new Blob([keyMaterial.private_key_pem], { type: "application/x-pem-file" }), `${base}.key`) }),
        ),
      );
    }
    $("#issue-result").replaceChildren(card);
    card.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  async function onCsrSubmit(ev) {
    ev.preventDefault();
    const f = new FormData(ev.target);
    const btn = ev.submitter;
    btn.disabled = true;
    try {
      const cert = await api("/api/v1/certificates", { method: "POST", body: {
        csr_pem: f.get("csr_pem"),
        profile: f.get("profile"),
        validity_days: Number(f.get("validity_days")) || undefined,
      } });
      renderIssued(cert, null);
      toast("Certificate issued", "ok");
    } catch (e) { toast(e.message, "error"); } finally { btn.disabled = false; }
  }

  async function onKeygenSubmit(ev) {
    ev.preventDefault();
    const form = ev.target;
    const f = new FormData(form);
    if (f.get("pkcs12_password") !== f.get("pkcs12_confirm")) { toast("Passwords do not match", "error"); return; }
    const btn = ev.submitter;
    btn.disabled = true;
    try {
      const res = await api("/api/v1/certificates/keygen", { method: "POST", body: {
        dns_names: lines(f.get("dns_names")),
        ip_addresses: lines(f.get("ip_addresses")),
        profile: f.get("profile"),
        key_algorithm: f.get("key_algorithm"),
        validity_days: Number(f.get("validity_days")) || undefined,
        pkcs12_password: f.get("pkcs12_password"),
      } });
      form.pkcs12_password.value = "";
      form.pkcs12_confirm.value = "";
      renderIssued(res.certificate, res);
      toast("Key and certificate generated", "ok");
    } catch (e) { toast(e.message, "error"); } finally { btn.disabled = false; }
  }

  // Loads a chosen file: PEM text goes into the textarea, binary DER is returned.
  async function readFileInto(input, textarea) {
    const file = input.files && input.files[0];
    if (!file) return null;
    const buf = new Uint8Array(await file.arrayBuffer());
    const text = new TextDecoder().decode(buf);
    if (text.includes("-----BEGIN")) { textarea.value = text; return null; }
    return buf;
  }

  // ---------- certificates ----------
  async function loadCerts(ev) {
    if (ev) ev.preventDefault();
    const f = new FormData($("#cert-filter"));
    const q = new URLSearchParams();
    if (f.get("search")) q.set("search", f.get("search"));
    if (f.get("status")) q.set("status", f.get("status"));
    try {
      const rows = await api(`/api/v1/certificates?${q}`);
      $("#cert-table tbody").replaceChildren(...rows.map((c) => {
        const fmt = el("select", { class: "small", "aria-label": "Format" },
          ...["chain", "pem", "fullchain", "der"].map((x) => el("option", { value: x, text: x })));
        const extra = [...c.dns_names.filter((n) => n !== c.common_name), ...c.ip_addresses];
        return el("tr", {},
          el("td", {}, el("strong", { text: c.common_name }), extra.length ? el("div", { class: "muted small", text: extra.join(", ") }) : null),
          el("td", {}, el("code", { title: c.serial, text: `${c.serial.slice(0, 12)}…` })),
          el("td", { text: c.profile }),
          el("td", {}, statusBadge(c.status)),
          el("td", { title: fmtTime(c.not_after), text: c.status === "active" ? `${daysLeft(c.not_after)} d` : new Date(c.not_after * 1000).toLocaleDateString() }),
          el("td", { text: c.requested_by }),
          el("td", { class: "actions" },
            fmt,
            el("button", { class: "btn btn-small", type: "button", text: "Download", onclick: () => downloadCert(c.serial, fmt.value) }),
            c.status === "active" ? el("button", { class: "btn btn-small btn-danger-ghost", type: "button", text: "Revoke", onclick: () => askRevoke(c.serial) }) : null,
          ),
        );
      }));
      $("#cert-empty").hidden = rows.length > 0;
    } catch (e) { toast(e.message, "error"); }
  }

  function askRevoke(serial) {
    state.revokeSerial = serial;
    $("#revoke-serial").textContent = serial;
    $("#revoke-dialog").showModal();
  }

  async function onRevokeClose() {
    const dlg = $("#revoke-dialog");
    const serial = state.revokeSerial;
    state.revokeSerial = null;
    if (dlg.returnValue !== "confirm" || !serial) return;
    const reason = $("select[name=reason]", dlg).value;
    try {
      await api(`/api/v1/certificates/${encodeURIComponent(serial)}/revoke`, { method: "POST", body: { reason } });
      toast("Certificate revoked; CRL updated", "ok");
      loadCerts();
    } catch (e) { toast(e.message, "error"); }
  }

  // ---------- verify ----------
  async function onVerifySubmit(ev) {
    ev.preventDefault();
    const form = ev.target;
    const der = await readFileInto(form.cert_file, form.certificate_pem);
    const body = { hostname: form.hostname.value.trim() || undefined };
    if (der) body.certificate_der_base64 = bytesToB64(der);
    else if (form.certificate_pem.value.trim()) body.certificate_pem = form.certificate_pem.value;
    else { toast("Paste or choose a certificate first", "error"); return; }
    try {
      const r = await api("/api/v1/verify", { method: "POST", body, auth: false });
      const card = el("div", { class: `card result ${r.valid ? "ok" : "bad"}` },
        el("h2", {}, r.valid ? "✔ Valid" : "✘ Not valid", el("span", { class: "muted small", text: "  checked against this CA" })),
        r.subject ? el("dl", { class: "kv" },
          el("dt", { text: "Subject" }), el("dd", { text: r.subject }),
          el("dt", { text: "Issuer" }), el("dd", { text: r.issuer }),
          el("dt", { text: "Serial" }), el("dd", {}, el("code", { text: r.serial })),
          el("dt", { text: "Names" }), el("dd", { text: r.dns_names.join(", ") || "—" }),
          el("dt", { text: "Validity" }), el("dd", { text: `${r.not_before} → ${r.not_after}` }),
        ) : null,
        el("ul", { class: "checks" }, ...r.checks.map((c) =>
          el("li", { class: c.passed ? "pass" : "fail" }, el("span", { class: "check-name", text: c.name }), el("span", { text: c.detail })))),
      );
      $("#verify-result").replaceChildren(card);
    } catch (e) { toast(e.message, "error"); }
  }

  // ---------- trust ----------
  function snippet(title, code) {
    return el("div", { class: "snippet" },
      el("h3", { text: title }),
      el("div", { class: "code-wrap" }, el("pre", {}, el("code", { text: code })),
        el("button", { class: "btn btn-small copy", type: "button", text: "Copy", onclick: () => copy(code) })),
    );
  }

  function renderTrust() {
    if (!state.ca) return;
    const origin = location.origin;
    $("#ca-facts").replaceChildren(
      el("dt", { text: "Root SHA-256" }), el("dd", {}, el("code", { class: "wrap", text: state.ca.root_sha256 })),
      el("dt", { text: "Intermediate SHA-256" }), el("dd", {}, el("code", { class: "wrap", text: state.ca.intermediate_sha256 })),
      el("dt", { text: "Allowed names" }), el("dd", { text: [...state.ca.allowed_dns_suffixes.map((s) => `*.${s}`), ...state.ca.allowed_ip_networks].join(", ") }),
      el("dt", { text: "Lifetime" }), el("dd", { text: `default ${state.ca.default_validity_days} d, max ${state.ca.max_validity_days} d` }),
    );
    $("#snippets").replaceChildren(
      el("p", { class: "muted", text: "Compare the downloaded root's SHA-256 fingerprint with a value obtained over a trusted channel before installing it." }),
      snippet("Debian / Ubuntu", `sudo curl -fsSo /usr/local/share/ca-certificates/zenv-dmz-root.crt ${origin}/pki/root.crt\nopenssl x509 -in /usr/local/share/ca-certificates/zenv-dmz-root.crt -noout -fingerprint -sha256\nsudo update-ca-certificates`),
      snippet("RHEL / Fedora", `sudo curl -fsSo /etc/pki/ca-trust/source/anchors/zenv-dmz-root.crt ${origin}/pki/root.crt\nsudo update-ca-trust`),
      snippet("Java truststore", `curl -fsSO ${origin}/pki/root.crt\nkeytool -importcert -noprompt -alias zenv-dmz-root -file root.crt \\\n  -keystore truststore.p12 -storetype PKCS12 -storepass changeit`),
      snippet("Check a server certificate with OpenSSL", `curl -fsSO ${origin}/pki/root.crt -O ${origin}/pki/intermediate.crt -O ${origin}/pki/crl.pem\nopenssl verify -CAfile root.crt -untrusted intermediate.crt \\\n  -crl_check -CRLfile crl.pem server.crt`),
    );
  }

  async function copy(text) {
    try { await navigator.clipboard.writeText(text); toast("Copied", "ok"); } catch (_) { toast("Copy failed; select the text manually", "error"); }
  }

  // ---------- audit ----------
  async function loadAudit() {
    try {
      const rows = await api("/api/v1/audit?limit=200");
      $("#audit-table tbody").replaceChildren(...rows.map((r) => el("tr", {},
        el("td", { text: r.id }),
        el("td", { text: fmtTime(r.ts) }),
        el("td", { text: r.actor }),
        el("td", {}, el("code", { text: r.action })),
        el("td", {}, el("code", { class: "wrap", text: r.target })),
        el("td", {}, el("code", { class: "wrap small", text: JSON.stringify(r.details) })),
      )));
    } catch (e) { toast(e.message, "error"); }
  }

  async function verifyAudit() {
    try {
      const v = await api("/api/v1/audit/verify");
      $("#audit-status").replaceChildren(v.intact
        ? el("span", { class: "badge badge-ok", text: `Chain intact: ${v.entries} entries` })
        : el("span", { class: "badge badge-bad", text: `Chain BROKEN at entry #${v.first_broken_id}` }));
    } catch (e) { toast(e.message, "error"); }
  }

  // ---------- boot ----------
  async function boot() {
    for (const t of $$("[data-tab]")) t.addEventListener("click", () => { location.hash = t.dataset.tab; });
    window.addEventListener("hashchange", () => showTab(currentTab()));
    for (const b of $$("[data-mode]")) b.addEventListener("click", () => setMode(b.dataset.mode));
    $("#csr-form").addEventListener("submit", onCsrSubmit);
    $("#csr-form").csr_file.addEventListener("change", (e) => readFileInto(e.target, $("#csr-form").csr_pem));
    $("#keygen-form").addEventListener("submit", onKeygenSubmit);
    $("#helper-names").addEventListener("input", renderHelper);
    $("#cert-filter").addEventListener("submit", loadCerts);
    $("#verify-form").addEventListener("submit", onVerifySubmit);
    $("#revoke-dialog").addEventListener("close", onRevokeClose);
    $("#audit-refresh").addEventListener("click", loadAudit);
    $("#audit-verify").addEventListener("click", verifyAudit);
    for (const b of $$("[data-copy]")) b.addEventListener("click", () => copy($(b.dataset.copy).textContent));

    await loadCaInfo();
    const saved = storage("get");
    if (saved) {
      state.token = saved;
      try { state.me = await api("/api/v1/me"); } catch (_) { state.token = null; storage("del"); }
    }
    renderSession();
    showTab(currentTab());
  }

  document.addEventListener("DOMContentLoaded", boot);
})();
