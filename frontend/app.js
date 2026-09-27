const state = {
  emails: [],
  selectedId: null,
  redTeam: null,
};

const el = {
  list: document.getElementById("email-list"),
  detail: document.getElementById("email-detail"),
  log: document.getElementById("log-feed"),
  btnRun: document.getElementById("btn-run"),
  btnReset: document.getElementById("btn-reset"),
  btnAttack: document.getElementById("btn-attack"),
  statTasks: document.getElementById("stat-tasks"),
  statEvents: document.getElementById("stat-events"),
  statPending: document.getElementById("stat-pending"),
  statBlocked: document.getElementById("stat-blocked"),
};

async function fetchJSON(url, opts) {
  const res = await fetch(url, opts);
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `${res.status} ${res.statusText}`);
  }
  return res.json();
}

async function refreshAll() {
  const [emails, tasks, events, log, firewall] = await Promise.all([
    fetchJSON("/api/emails"),
    fetchJSON("/api/tasks"),
    fetchJSON("/api/events"),
    fetchJSON("/api/log"),
    fetchJSON("/api/firewall/metrics"),
  ]);
  state.emails = emails;
  el.statTasks.textContent = tasks.length;
  el.statEvents.textContent = events.length;
  el.statPending.textContent = emails.filter(
    (e) => e.status === "needs_review" || e.status === "draft_ready"
  ).length;
  el.statBlocked.textContent = firewall.blocked;
  renderList();
  renderDetail();
  renderLog(log);
}

function renderList() {
  if (state.emails.length === 0) {
    el.list.innerHTML = '<p class="empty">No emails.</p>';
    return;
  }
  el.list.innerHTML = "";
  for (const entry of state.emails) {
    const { email, analysis, status } = entry;
    const card = document.createElement("button");
    card.type = "button";
    card.className = "email-card" + (state.selectedId === email.id ? " selected" : "");
    card.onclick = () => {
      state.selectedId = email.id;
      state.redTeam = null;
      renderList();
      renderDetail();
    };
    const badges = [`<span class="badge status-${status}">${status.replace(/_/g, " ")}</span>`];
    if (analysis) {
      badges.push(`<span class="badge">${analysis.category.replace(/_/g, " ")}</span>`);
    }
    card.innerHTML = `
      <div class="row1"><span>${escapeHtml(email.from)}</span></div>
      <div class="from">${escapeHtml(email.received_at)}</div>
      <div class="subject">${escapeHtml(email.subject)}</div>
      <div class="badges">${badges.join("")}</div>
    `;
    el.list.appendChild(card);
  }
}

function renderDetail() {
  if (state.redTeam) {
    renderRedTeam();
    return;
  }
  const entry = state.emails.find((e) => e.email.id === state.selectedId);
  if (!entry) {
    el.detail.innerHTML = '<p class="empty">Select an email to see the agent\'s reasoning.</p>';
    return;
  }
  const { email, analysis, policy, status } = entry;

  let reasoningHtml = "";
  let actionHtml = "";
  let policyHtml = "";

  if (analysis) {
    const pct = Math.round(analysis.confidence * 100);
    reasoningHtml = `
      <div class="reasoning-box">
        <h3>Agent reasoning</h3>
        <p>${escapeHtml(analysis.reasoning)}</p>
        <p>Confidence: ${pct}% ${analysis.sensitive ? "&middot; flagged sensitive" : ""}</p>
        <div class="confidence-bar"><div style="width:${pct}%"></div></div>
      </div>
    `;

    if (policy) {
      const checks = policy.checks
        .map(
          (check) => `<li class="${check.passed ? "passed" : "blocked"}">
            <span>${check.passed ? "✓" : "!"}</span>
            <div><strong>${escapeHtml(check.name.replace(/_/g, " "))}</strong><small>${escapeHtml(check.detail)}</small></div>
          </li>`
        )
        .join("");
      policyHtml = `
        <div class="policy-box risk-${escapeHtml(policy.risk_level)}">
          <div class="policy-title"><h3>Autonomy safety gate</h3><span>${escapeHtml(policy.risk_level)} risk</span></div>
          <ul class="policy-checks">${checks}</ul>
          <p>${escapeHtml(policy.rationale)}</p>
        </div>`;
    }

    const action = analysis.proposed_action || {};
    let actionDetail = "";
    if (action.type === "draft_reply") {
      actionDetail = `Draft reply:\n\n${action.reply_text || ""}`;
    } else if (action.type === "create_calendar_event") {
      actionDetail = `Create event: "${action.event_title || ""}" at ${action.event_time || "(unspecified time)"}`;
    } else if (action.type === "create_task") {
      actionDetail = `Create task: "${action.task_title || ""}" due ${action.task_due || "(unspecified)"}`;
    } else {
      actionDetail = "No action needed.";
    }

    let buttons =
      status === "draft_ready" || status === "needs_review"
        ? `<div class="action-buttons">
             <button class="btn approve" onclick="approveEmail('${escapeAttribute(email.id)}')">Approve</button>
             <button class="btn reject" onclick="rejectEmail('${escapeAttribute(email.id)}')">Reject</button>
           </div>`
        : "";
    if (["auto_executed", "auto_archived", "approved"].includes(status) && entry.action_id) {
      buttons = `<div class="action-buttons"><button class="btn undo" onclick="undoEmail('${escapeAttribute(email.id)}')">Undo action</button></div>`;
    }

    actionHtml = `
      <div class="action-box">
        <h3>Proposed action &middot; ${status.replace(/_/g, " ")}</h3>
        <div class="action-detail">${escapeHtml(actionDetail)}</div>
        ${buttons}
      </div>
    `;
  } else {
    reasoningHtml = '<p class="empty">Not yet analyzed. Click "Run Agent".</p>';
  }

  el.detail.innerHTML = `
    <div class="detail-header">
      <div>
        <h2>${escapeHtml(email.subject)}</h2>
        <div class="detail-meta">${escapeHtml(email.from)} &middot; ${escapeHtml(email.received_at)}</div>
      </div>
    </div>
    <div class="body-box">${escapeHtml(email.body)}</div>
    ${reasoningHtml}
    ${policyHtml}
    ${actionHtml}
  `;
}

function renderRedTeam() {
  const { summary, results, audit } = state.redTeam;
  const cards = results
    .map(
      (result) => `<article class="attack-card verdict-${result.verdict.toLowerCase()}">
        <div class="attack-heading">
          <div><strong>${escapeHtml(result.agent)}</strong><small>${escapeHtml(result.tool)}</small></div>
          <span>${escapeHtml(result.verdict)}</span>
        </div>
        <div class="risk-meter"><div style="width:${result.risk_score}%"></div></div>
        <p>Risk score ${result.risk_score}/100 · ${escapeHtml(result.explanation)}</p>
        <div class="rule-pills">${result.rules_triggered
          .map((rule) => `<span title="${escapeHtml(rule.detail)}">${escapeHtml(rule.rule.replace(/_/g, " "))}</span>`)
          .join("") || "<span>NO RISK RULES</span>"}</div>
      </article>`
    )
    .join("");

  el.detail.innerHTML = `
    <div class="lab-hero">
      <div><span class="eyebrow">LIVE ADVERSARIAL EVALUATION</span><h2>Agent Firewall Attack Lab</h2></div>
      <div class="lab-score">${summary.blocked + summary.review}<small>unsafe calls stopped</small></div>
    </div>
    <p class="lab-copy">Four agents attempted real-world tool calls. TrustLayer evaluated the content, tool, reversibility, and confidence before any side effect could occur.</p>
    <div class="lab-summary">
      <div><strong>${summary.blocked}</strong><span>blocked</span></div>
      <div><strong>${summary.review}</strong><span>needs review</span></div>
      <div><strong>${summary.allowed}</strong><span>safely allowed</span></div>
      <div><strong>${audit.valid ? "VALID" : "BROKEN"}</strong><span>audit chain</span></div>
    </div>
    <div class="attack-grid">${cards}</div>
    <div class="chain-proof">Audit proof · ${audit.entries} hash-linked events · head ${escapeHtml(audit.head.slice(0, 16))}…</div>
  `;
}

function renderLog(log) {
  el.log.innerHTML = log.map((line) => `<div>${escapeHtml(line)}</div>`).join("");
  el.log.scrollTop = el.log.scrollHeight;
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str ?? "";
  return div.innerHTML;
}

function escapeAttribute(str) {
  return String(str ?? "").replace(/['\\]/g, "");
}

async function approveEmail(id) {
  await performAction(`/api/emails/${id}/approve`);
}

async function rejectEmail(id) {
  await performAction(`/api/emails/${id}/reject`);
}

async function undoEmail(id) {
  await performAction(`/api/emails/${id}/undo`);
}

async function performAction(url) {
  try {
    await fetchJSON(url, { method: "POST" });
    await refreshAll();
  } catch (err) {
    alert("Action failed: " + err.message);
  }
}

el.btnRun.onclick = async () => {
  el.btnRun.disabled = true;
  el.btnRun.textContent = "Running...";
  try {
    await fetchJSON("/api/run", { method: "POST" });
    await refreshAll();
  } catch (err) {
    alert("Agent run failed: " + err.message);
  } finally {
    el.btnRun.disabled = false;
    el.btnRun.textContent = "Run Agent";
  }
};

el.btnAttack.onclick = async () => {
  el.btnAttack.disabled = true;
  el.btnAttack.textContent = "Attacking...";
  try {
    state.redTeam = await fetchJSON("/api/red-team", { method: "POST" });
    state.selectedId = null;
    await refreshAll();
  } catch (err) {
    alert("Red-team run failed: " + err.message);
  } finally {
    el.btnAttack.disabled = false;
    el.btnAttack.textContent = "Red-Team Demo";
  }
};

el.btnReset.onclick = async () => {
  try {
    await fetchJSON("/api/reset", { method: "POST" });
    state.selectedId = null;
    state.redTeam = null;
    await refreshAll();
  } catch (err) {
    alert("Reset failed: " + err.message);
  }
};

refreshAll().catch((err) => {
  el.detail.innerHTML = `<p class="error">Could not load the application: ${escapeHtml(err.message)}</p>`;
});
