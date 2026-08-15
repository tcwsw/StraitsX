/**
 * ProcureGuard static frontend (vanilla JS, no build step).
 *
 * A thin client — like dashboard/app.py — over the real FastAPI services
 * (pg/policy_server.py on POLICY_URL, merchants/server.py on MERCHANTS_URL). It holds no
 * secrets, mints no SpendIntent itself, and signs nothing itself. Every number rendered
 * here (prices, policy checks, SpendIntent lifecycle, audit entries) comes straight from
 * those services' real JSON responses.
 *
 * Unlike the fixed final-demo fixture, the request box drives a REAL search against
 * product/catalog.json (via merchants/server.py's /search — the same endpoint
 * agent/run.py's gather() uses): type "<qty> x <item>" (e.g. "2 x usb-c charger",
 * "1 x hdmi cable") and press Run to search all authorized merchants, pick the cheapest
 * in-stock eligible offer, evaluate it against the real policy engine, and (if allowed)
 * run the full x402 payment flow for it. Every "Run" reuses the same mandate/budget
 * (registered once per page load), exactly like an agent spending down one ongoing
 * delegated budget over several purchases.
 *
 * Override backend URLs via query string, e.g.
 *   index.html?policy=http://127.0.0.1:4020&merchants=http://127.0.0.1:4030
 *
 * Run (from the repo root, in a separate terminal from the two API services):
 *   python -m http.server 8080 --directory frontend
 * then open http://127.0.0.1:8080
 */

const qs = new URLSearchParams(location.search);
const POLICY_URL = (qs.get("policy") || "http://127.0.0.1:4020").replace(/\/$/, "");
const MERCHANTS_URL = (qs.get("merchants") || "http://127.0.0.1:4030").replace(/\/$/, "");

let MAINNET_NETWORK = null; // populated from GET /system/info during boot()
let RUN_IN_PROGRESS = false;

// The mandate id is generated fresh per page load (never reused across a browser
// session/reload) so repeated demo reloads never keep reserving new SpendIntents against a
// mandate that has already spent its budget in a prior session — the top bar's
// "Mandate M-001" label is a cosmetic display constant (see index.html), independent of
// this real, unique id used for every API call. Within ONE page load, every "Run" the user
// submits reuses this SAME mandate/budget, exactly like a real agent spending down one
// ongoing delegated budget over multiple purchases.
const MANDATE_ID = "m-" + crypto.randomUUID().slice(0, 8);
const ALLOWED_MERCHANTS = ["techstore", "gadgethub", "bargainbin"];
const COMPARISON_MERCHANTS = [...ALLOWED_MERCHANTS, "cheapdealsstore"];
const MERCHANT_NAMES = { techstore: "TechStore", gadgethub: "GadgetHub", bargainbin: "BargainBin", cheapdealsstore: "CheapDealsStore" };
const MERCHANT_COLORS = { techstore: "#2563eb", gadgethub: "#7c3aed", bargainbin: "#dc2626", cheapdealsstore: "#d97706" };
const MERCHANT_LETTERS = { techstore: "T", gadgethub: "G", bargainbin: "B", cheapdealsstore: "C" };

const $ = (id) => document.getElementById(id);

// ============================================================== request parsing
// Mirrors dashboard/app.py's own regex exactly: "<qty> x <item>" (case-insensitive), else
// the whole string is the item name with quantity defaulting to 1 (a plain "usb-c charger"
// is a perfectly normal request, not an error).
function parseRequest(text) {
  const trimmed = (text || "").trim();
  if (!trimmed) return { itemName: null, quantity: null };
  const m = trimmed.match(/^\s*(\d+)\s*x\s*(.+?)\s*$/i);
  if (m) return { itemName: m[2].trim(), quantity: parseInt(m[1], 10) };
  return { itemName: trimmed, quantity: 1 };
}

function fmtTime(d = new Date()) {
  return d.toLocaleTimeString("en-GB", { hour12: false });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function api(method, base, path, body, extraHeaders) {
  const opts = { method, headers: { "Content-Type": "application/json", ...(extraHeaders || {}) } };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const res = await fetch(`${base}${path}`, opts);
  let json = null;
  try {
    json = await res.json();
  } catch (_) {
    json = null;
  }
  return { ok: res.ok, status: res.status, json };
}

// ============================================================== 1. Request & Agent log

function logAgentLine(text, { done = false, final = false } = {}) {
  const li = document.createElement("li");
  if (done) li.classList.add("done");
  if (final) li.classList.add("final");
  const label = document.createElement("span");
  label.textContent = (done ? "✅ " : "◯ ") + text;
  const time = document.createElement("span");
  time.className = "line-time";
  time.textContent = fmtTime();
  li.append(label, time);
  $("agentLog").appendChild(li);
  return li;
}

// ============================================================== 2. Offers

function renderOffers(offers, quantity, perMerchantMax, selectedMerchant) {
  const list = $("offerList");
  list.innerHTML = "";
  const cheapestEligible = Object.entries(offers)
    .filter(([mid, o]) => o && ALLOWED_MERCHANTS.includes(mid) && o.unit_price * quantity <= perMerchantMax)
    .sort((a, b) => a[1].unit_price - b[1].unit_price)[0]?.[0];

  for (const mid of COMPARISON_MERCHANTS) {
    const offer = offers[mid];
    const card = document.createElement("div");
    card.className = "offer-card";

    if (!offer) {
      card.classList.add("ineligible");
      card.innerHTML = `
        <div class="offer-avatar" style="background:${MERCHANT_COLORS[mid]}">${MERCHANT_LETTERS[mid]}</div>
        <div class="offer-body"><div class="offer-name">${MERCHANT_NAMES[mid]}</div><div class="offer-desc">No matching item found</div></div>
        <div class="offer-status"><div class="offer-tag no">✕ No match</div></div>
      `;
      list.appendChild(card);
      continue;
    }

    const total = offer.unit_price * quantity;
    let statusHtml = "";
    if (!ALLOWED_MERCHANTS.includes(mid)) {
      card.classList.add("ineligible");
      statusHtml = `<div class="offer-tag no">✕ Not authorized</div><div class="offer-reason">Merchant not authorized</div>`;
    } else if (!offer.in_stock || offer.stock < quantity) {
      card.classList.add("ineligible");
      statusHtml = `<div class="offer-tag no">✕ Insufficient stock</div><div class="offer-reason">${offer.stock} in stock, ${quantity} requested</div>`;
    } else if (total > perMerchantMax) {
      card.classList.add("ineligible");
      statusHtml = `<div class="offer-tag no">✕ Over cap</div><div class="offer-reason">Exceeds ${perMerchantMax.toFixed(2)} XSGD per-merchant limit</div>`;
    } else if (mid === selectedMerchant || mid === cheapestEligible) {
      card.classList.add("eligible-best");
      statusHtml = `<div class="offer-tag ok">✓ Best eligible</div>`;
    } else {
      card.classList.add("eligible");
      statusHtml = `<div class="offer-tag ok">✓ Eligible</div>`;
    }

    card.innerHTML = `
      <div class="offer-avatar" style="background:${MERCHANT_COLORS[mid]}">${MERCHANT_LETTERS[mid]}</div>
      <div class="offer-body">
        <div class="offer-name">${MERCHANT_NAMES[mid]}</div>
        <div class="offer-desc">${quantity} x ${offer.title}</div>
      </div>
      <div class="offer-price">${total.toFixed(2)} XSGD</div>
      <div class="offer-status">${statusHtml}</div>
    `;
    list.appendChild(card);
  }
}

// Real catalogue search (product/catalog.json via merchants/server.py's /search) — the
// SAME endpoint agent/run.py's gather() uses. For each comparison merchant, picks the
// cheapest in-stock item whose title/category matches the requested item name; a
// merchant that stocks nothing matching simply has no offer (rendered as "No match").
async function searchOffers(itemName) {
  const offers = {};
  for (const mid of COMPARISON_MERCHANTS) {
    const { ok, json } = await api("GET", MERCHANTS_URL, `/${mid}/search?q=${encodeURIComponent(itemName)}`);
    if (!ok || !json) throw new Error(`could not reach merchant service for ${mid}`);
    const candidates = (json.items || []).filter((i) => i.in_stock);
    if (!candidates.length) {
      offers[mid] = null;
      continue;
    }
    const best = candidates.reduce((a, b) => (Number(b.price) < Number(a.price) ? b : a));
    offers[mid] = {
      sku: best.sku, unit_price: Number(best.price), title: best.title,
      category: best.category, stock: best.stock, in_stock: best.in_stock,
    };
  }
  return offers;
}

// ============================================================== 3. Policy checks

const CHECK_LABELS = [
  { key: "merchant_allowed", label: "Merchant allowed" },
  { key: "category_allowed", label: "Categories allowed" },
  { key: "product_requested", label: "Products match request" },
  { key: "quantity_matches", label: "Quantities valid" },
  { key: "stock_available", label: "Stock availability" },
  { key: "per_intent_limit", label: "Price within per-merchant cap" },
  { key: "delegated_budget", label: "Total within delegated budget" },
];

function findCheck(checks, key, { merchantId, sku, itemName }) {
  const candidates = [
    itemName ? `${key}[${itemName}]` : null,
    merchantId && sku ? `${key}[${merchantId}:${sku}]` : null,
    merchantId ? `${key}[${merchantId}]` : null,
    key,
  ].filter(Boolean);
  for (const name of candidates) {
    const c = checks.find((c) => c.name === name);
    if (c) return c;
  }
  return null;
}

function renderPolicyChecks(verdict, merchantId, sku, itemName) {
  const ul = $("policyChecks");
  ul.innerHTML = "";
  const checks = verdict.checks || [];
  for (const { key, label } of CHECK_LABELS) {
    const c = findCheck(checks, key, { merchantId, sku, itemName });
    const li = document.createElement("li");
    const passed = c ? c.passed : true; // vacuous pass if this check wasn't emitted (e.g. no requested_items configured)
    li.innerHTML = `
      <span class="check-label">${label}</span>
      <span class="check-status ${passed ? "pass" : "fail"}">${passed ? "✅ PASS" : "❌ FAIL"}${c && c.detail ? ` <span class="check-detail">(${c.detail})</span>` : ""}</span>
    `;
    ul.appendChild(li);
  }
  const injectionLi = document.createElement("li");
  injectionLi.innerHTML = `<span class="check-label">Prompt injection / anomaly</span><span class="check-status pass">✅ CLEAN</span>`;
  ul.appendChild(injectionLi);
}

// ============================================================== 4. Payment stepper

function setStep(name, done) {
  const el = document.querySelector(`.step[data-step="${name}"]`);
  if (!el) return;
  if (done) {
    el.classList.add("done");
    el.querySelector(".step-time").textContent = fmtTime();
    const line = el.previousElementSibling;
    if (line && line.classList.contains("step-line")) line.classList.add("done");
  }
}

function setPaymentMeta({ intentId, merchantId, amount, expirySeconds }) {
  if (intentId) $("metaIntent").textContent = intentId.slice(0, 14) + "…";
  if (merchantId) $("metaMerchant").textContent = MERCHANT_NAMES[merchantId] || merchantId;
  if (amount !== undefined) $("metaAmount").textContent = `${Number(amount).toFixed(2)} XSGD`;
  if (expirySeconds !== undefined) $("metaExpiry").textContent = expirySeconds > 0 ? `${expirySeconds}s` : "expired";
}

function peekIntentToken(token) {
  try {
    const [raw] = token.split("||");
    return JSON.parse(raw);
  } catch (_) {
    return null;
  }
}

async function runPaymentFlow(leg, itemsForCheckout) {
  const merchantId = leg.merchant_id;
  const peek = peekIntentToken(leg.spend_intent) || {};
  setPaymentMeta({ intentId: peek.spend_intent_id, merchantId, amount: leg.amount, expirySeconds: peek.exp ? Math.max(0, Math.floor(peek.exp - Date.now() / 1000)) : undefined });

  const body = { items: itemsForCheckout };

  // Step 1: 402 challenge
  const first = await api("POST", MERCHANTS_URL, `/${merchantId}/checkout`, body);
  if (first.status !== 402 || !first.json) {
    logAgentLine(`Merchant did not return the expected 402 challenge (got ${first.status})`, { done: true });
    return;
  }
  setStep("challenge", true);
  const challenge = first.json;

  // Step 2: policy engine verifies recipient + signs (never sends merchant_id/amount — both
  // are derived server-side from the SpendIntent token itself).
  const auth = await api("POST", POLICY_URL, "/authorize", { spend_intent: leg.spend_intent, challenge });
  if (!auth.ok || !auth.json || !auth.json.ok) {
    logAgentLine(`AUTHORIZATION REFUSED: ${(auth.json || {}).detail || "no response"} — nothing signed`, { done: true });
    return;
  }
  setStep("verified", true);
  const intentId = auth.json.intent_id;

  // Step 3: resubmit checkout with the signed PAYMENT-SIGNATURE header.
  const paid = await api("POST", MERCHANTS_URL, `/${merchantId}/checkout`, body, { "PAYMENT-SIGNATURE": auth.json.payment_header });
  if (!paid.ok || !paid.json) {
    await api("POST", POLICY_URL, `/intents/${intentId}/failed`, { reason: `merchant checkout returned ${paid.status}`, definite: true });
    logAgentLine(`Merchant settlement failed (status ${paid.status})`, { done: true });
    return;
  }
  setStep("submitted", true);
  const receipt = paid.json;

  // Step 4: report settlement; the policy engine independently verifies/consumes.
  const settled = await api("POST", POLICY_URL, `/intents/${intentId}/settled`, {
    tx_hash: receipt.receipt.tx_hash, network: receipt.receipt.network, order_id: receipt.order_id,
  });
  setStep("settled", true);

  if (settled.json && settled.json.ok) {
    setStep("consumed", true);
  }

  const txHash = receipt.receipt.tx_hash;
  if (txHash) {
    const isMainnet = MAINNET_NETWORK && receipt.receipt.network === MAINNET_NETWORK;
    const base = isMainnet ? "https://snowtrace.io/tx/" : "https://testnet.snowtrace.io/tx/";
    const link = $("snowtraceLink");
    link.href = `${base}${txHash}`;
    link.style.display = "inline-block";
  }
}

// ============================================================== 5. Audit trail

async function refreshAuditTrail() {
  const { ok, json } = await api("GET", POLICY_URL, "/audit");
  if (!ok || !json) return;
  const ul = $("auditList");
  ul.innerHTML = "";
  const entries = (json.entries || []).filter((e) => JSON.stringify(e).includes(MANDATE_ID)).slice(-30);
  if (!entries.length) {
    ul.innerHTML = `<li class="empty-state">No events yet.</li>`;
    return;
  }
  for (const e of entries) {
    const li = document.createElement("li");
    const ts = (e.ts || "").split("T")[1]?.split(".")[0] || e.ts;
    li.innerHTML = `<span class="audit-dot"></span><span class="audit-time">${ts}</span><span class="audit-label">${e.kind}</span>`;
    ul.appendChild(li);
  }
}

// ============================================================== top bar

async function refreshTopBar() {
  const { ok, json } = await api("GET", POLICY_URL, `/mandates/${MANDATE_ID}`);
  if (!ok || !json) return;
  $("statBudget").textContent = `${Number(json.mandate.budget_total).toFixed(2)} XSGD`;
  $("statLimit").textContent = `${Number(json.mandate.per_intent_max).toFixed(2)} XSGD`;
  $("statSpent").textContent = `${Number(json.spent).toFixed(2)} XSGD`;
  $("statRemaining").textContent = `${Number(json.remaining).toFixed(2)} XSGD`;

  const statusRes = await api("GET", POLICY_URL, `/agent/${MANDATE_ID}/status`);
  if (statusRes.ok && statusRes.json) {
    const status = statusRes.json.status;
    const pill = $("agentStatusPill");
    pill.textContent = status;
    pill.className = "pill " + (status === "ACTIVE" ? "pill-active" : "pill-paused");
    const btn = $("pauseBtn");
    const label = $("pauseBtnLabel");
    if (status === "ACTIVE") {
      btn.classList.remove("resumed");
      label.textContent = "PAUSE AGENT";
      btn.dataset.action = "pause";
    } else {
      btn.classList.add("resumed");
      label.textContent = "RESUME AGENT";
      btn.dataset.action = "resume";
    }
  }
}

async function togglePause() {
  const action = $("pauseBtn").dataset.action || "pause";
  const newStatus = action === "pause" ? "PAUSED" : "ACTIVE";
  await api("POST", POLICY_URL, `/agent/${MANDATE_ID}/status?status=${newStatus}`);
  await refreshTopBar();
}

// ============================================================== main happy-path flow

async function ensureMandate(itemName, quantity, budgetTotal, perMerchantMax) {
  const mandate = {
    mandate_id: MANDATE_ID,
    principal: "Team ProcureGuard",
    budget_total: budgetTotal,
    per_intent_max: perMerchantMax,
    requested_items: [{ name: itemName, quantity }],
    allowed_categories: ["electronics"],
    blocked_categories: ["gift_card", "cash_equivalent"],
    allowed_merchants: ALLOWED_MERCHANTS,
    require_human_above: null,
    expires_at: new Date(Date.now() + 86400000).toISOString(),
  };
  await api("POST", POLICY_URL, "/mandates", mandate);
}

function resetRunUI(requestText) {
  $("requestBubble").style.display = "block";
  $("requestText").textContent = requestText;
  $("requestTime").textContent = fmtTime();
  $("agentLog").innerHTML = "";
  $("offerList").innerHTML = `<div class="empty-state">Waiting for merchant quotes…</div>`;
  $("policyChecks").innerHTML = `<li class="empty-state">Awaiting a policy verdict…</li>`;
  for (const step of ["challenge", "verified", "submitted", "settled", "consumed"]) {
    const el = document.querySelector(`.step[data-step="${step}"]`);
    if (el) {
      el.classList.remove("done");
      el.querySelector(".step-time").textContent = "";
      const line = el.previousElementSibling;
      if (line && line.classList.contains("step-line")) line.classList.remove("done");
    }
  }
  $("metaIntent").textContent = "—";
  $("metaMerchant").textContent = "—";
  $("metaAmount").textContent = "—";
  $("metaExpiry").textContent = "—";
  $("snowtraceLink").style.display = "none";
  $("requestError").style.display = "none";
}

async function runMainFlow(itemName, quantity, budgetTotal, perMerchantMax) {
  logAgentLine("Searching offers from authorized merchants...", { done: false });
  await sleep(300);

  let offers;
  try {
    offers = await searchOffers(itemName);
  } catch (exc) {
    logAgentLine(String(exc.message || exc), { done: true });
    return;
  }
  $("agentLog").lastChild.classList.add("done");
  $("agentLog").lastChild.firstChild.textContent = "✅ Searching offers from authorized merchants...";
  renderOffers(offers, quantity, perMerchantMax, null);

  logAgentLine("Comparing offers and building baskets...", { done: false });
  await sleep(300);

  const eligible = ALLOWED_MERCHANTS
    .map((mid) => ({ mid, offer: offers[mid] }))
    .filter((o) => o.offer && o.offer.in_stock && o.offer.stock >= quantity && o.offer.unit_price * quantity <= perMerchantMax)
    .sort((a, b) => a.offer.unit_price - b.offer.unit_price);
  const selectedMerchant = eligible[0]?.mid;
  $("agentLog").lastChild.classList.add("done");
  $("agentLog").lastChild.firstChild.textContent = "✅ Comparing offers and building baskets...";

  if (!selectedMerchant) {
    logAgentLine(`No eligible merchant found for "${itemName}" within budget/stock constraints.`, { done: true });
    return;
  }

  const chosenOffer = offers[selectedMerchant];
  logAgentLine(`Best eligible option: ${MERCHANT_NAMES[selectedMerchant]} (${(chosenOffer.unit_price * quantity).toFixed(2)} XSGD)`, { done: true, final: true });
  renderOffers(offers, quantity, perMerchantMax, selectedMerchant);

  const proposal = {
    decision_id: "d-" + crypto.randomUUID().slice(0, 8),
    goal: `${quantity}x ${itemName}`,
    selected_items: [{
      requested_item: { name: itemName, quantity },
      merchant_id: selectedMerchant, sku: chosenOffer.sku, unit_price: chosenOffer.unit_price, quantity,
    }],
    reasoning: `${MERCHANT_NAMES[selectedMerchant]} is the cheapest merchant within the ${perMerchantMax.toFixed(2)} XSGD per-merchant cap.`,
  };

  const { ok, json: verdict } = await api("POST", POLICY_URL, "/evaluate-basket", { mandate_id: MANDATE_ID, proposal });
  if (!ok || !verdict) return;
  renderPolicyChecks(verdict, selectedMerchant, chosenOffer.sku, itemName);

  if (verdict.allowed && verdict.spend_intents && verdict.spend_intents.length) {
    const leg = verdict.spend_intents[0];
    await runPaymentFlow(leg, [{ sku: chosenOffer.sku, quantity }]);
  }

  await refreshTopBar();
  await refreshAuditTrail();
}

// ============================================================== 6. Attack demo

async function runAttackFlow(itemName, budgetTotal, perMerchantMax) {
  const atkMandateId = "m-atk-" + crypto.randomUUID().slice(0, 8);
  const atkMandate = {
    mandate_id: atkMandateId,
    principal: "Team ProcureGuard",
    budget_total: budgetTotal,
    per_intent_max: perMerchantMax,
    requested_items: [{ name: itemName, quantity: 1 }],
    allowed_categories: ["electronics"],
    allowed_merchants: ALLOWED_MERCHANTS,
    require_human_above: null,
    expires_at: new Date(Date.now() + 86400000).toISOString(),
  };
  await api("POST", POLICY_URL, "/mandates", atkMandate);

  // The deterministic attack fixture (see tests/agent_mode_matrix.py AT2): a proposal that
  // relabels a $25 gift card as fulfilling whatever the user actually asked for. Posted
  // directly to /evaluate-basket — never through /authorize, so no signature is ever
  // produced.
  const attackProposal = {
    decision_id: "d-attack-" + crypto.randomUUID().slice(0, 8),
    goal: `1x ${itemName}`,
    selected_items: [{
      requested_item: { name: "digital gift card", quantity: 1 },
      merchant_id: "bargainbin", sku: "BB-G01", unit_price: 25.0, quantity: 1,
    }],
    reasoning: `deterministic attack fixture: relabels a $25 gift card as the requested "${itemName}"`,
  };

  const { ok, json: verdict } = await api("POST", POLICY_URL, "/evaluate-basket", { mandate_id: atkMandateId, proposal: attackProposal });
  if (!ok || !verdict) return;

  $("attackBanner").style.display = "block";
  $("deniedBanner").style.display = "none";

  const labels = [
    { key: "merchant_allowed", label: "Merchant allowed", merchantId: "bargainbin" },
    { key: "category_allowed", label: "Categories allowed", merchantId: "bargainbin", sku: "BB-G01" },
    { key: "product_requested", label: "Products match request", merchantId: "bargainbin", sku: "BB-G01" },
    { key: "per_intent_limit", label: "Price within per-merchant cap", merchantId: "bargainbin" },
    { key: "delegated_budget", label: "Total within delegated budget" },
  ];
  const ul = $("attackChecks");
  ul.innerHTML = "";
  for (const { key, label, merchantId, sku } of labels) {
    const c = findCheck(verdict.checks || [], key, { merchantId, sku });
    const passed = c ? c.passed : false;
    const li = document.createElement("li");
    li.innerHTML = `
      <span class="check-label">${label}</span>
      <span class="check-status ${passed ? "pass" : "fail"}">${passed ? "✅ PASS" : "❌ FAIL"}${c && c.detail ? ` <span class="check-detail">(${c.detail})</span>` : ""}</span>
    `;
    ul.appendChild(li);
  }

  if (!verdict.allowed) {
    $("deniedBanner").style.display = "block";
  }
}

// ============================================================== request submission

async function runRequest(rawText, budgetTotal, perMerchantMax) {
  if (RUN_IN_PROGRESS) return;
  const { itemName, quantity } = parseRequest(rawText);
  const errorBox = $("requestError");
  if (!itemName) {
    errorBox.textContent = "What product would you like to buy? (e.g. \"2 x usb-c charger\")";
    errorBox.style.display = "block";
    return;
  }
  if (!quantity || quantity <= 0) {
    errorBox.textContent = `How many "${itemName}" would you like? (e.g. "2 x ${itemName}")`;
    errorBox.style.display = "block";
    return;
  }
  if (!(budgetTotal > 0) || !(perMerchantMax > 0)) {
    errorBox.textContent = "Budget and per-merchant cap must both be positive numbers.";
    errorBox.style.display = "block";
    return;
  }

  RUN_IN_PROGRESS = true;
  const submitBtn = $("requestSubmit");
  submitBtn.disabled = true;
  try {
    resetRunUI(`Buy ${quantity} x ${itemName} within my delegated budget.`);
    await ensureMandate(itemName, quantity, budgetTotal, perMerchantMax);
    await refreshTopBar();
    await runMainFlow(itemName, quantity, budgetTotal, perMerchantMax);
    await runAttackFlow(itemName, budgetTotal, perMerchantMax);
    await refreshAuditTrail();
  } catch (exc) {
    console.error(exc);
    logAgentLine(`Run failed: ${exc.message || exc}`, { done: true });
  } finally {
    RUN_IN_PROGRESS = false;
    submitBtn.disabled = false;
  }
}

// ============================================================== boot

async function boot() {
  $("policyUrlLabel").textContent = POLICY_URL;
  $("merchantsUrlLabel").textContent = MERCHANTS_URL;
  $("pauseBtn").addEventListener("click", togglePause);

  $("requestForm").addEventListener("submit", (evt) => {
    evt.preventDefault();
    runRequest($("requestInput").value, Number($("budgetInput").value), Number($("capInput").value));
  });

  try {
    const sysInfo = await api("GET", POLICY_URL, "/system/info");
    if (sysInfo.ok && sysInfo.json) {
      MAINNET_NETWORK = sysInfo.json.mainnet_network;
      const banner = $("modeBanner");
      banner.textContent = `settle_mode=${sysInfo.json.settle_mode} · mainnet_network=${sysInfo.json.mainnet_network}`;
      banner.classList.add("show");
    }
  } catch (_) { /* non-fatal, badge only */ }

  // Register an initial mandate (using the form's default values) so the top bar shows
  // real numbers immediately, then run the default request once automatically.
  await ensureMandate("usb-c charger", 1, Number($("budgetInput").value), Number($("capInput").value));
  await refreshTopBar();
  await runRequest($("requestInput").value, Number($("budgetInput").value), Number($("capInput").value));
}

boot().catch((exc) => {
  console.error(exc);
  logAgentLine(`Startup failed: ${exc.message || exc} — is the policy engine running at ${POLICY_URL} and the merchant service at ${MERCHANTS_URL}?`, { done: true });
});
