const $ = (id) => document.getElementById(id);
const actionLabels = {"run-full":"running full demo…","reset":"resetting…","run-normal":"running normal traffic…","steal-key":"driving stolen-key attack…","legit-after-containment":"checking legitimate recovery…","direct-raw":"testing direct backend rejection…"};
function esc(value) { return String(value ?? "").replace(/[&<>\"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c])); }
function render(s) {
  $("fingerprint").textContent = s.credential_fingerprint;
  $("baseline-legit").textContent = s.baseline.legitimate_accepted;
  $("baseline-attacker").textContent = s.baseline.attacker_accepted;
  $("protected-legit").textContent = s.protected.legitimate_reached;
  $("protected-attacker").textContent = s.protected.attacker_reached;
  $("protected-blocked").textContent = s.protected.attacker_blocked;
  $("valid-assertions").textContent = s.protected.valid_assertions;
  $("invalid-assertions").textContent = s.protected.invalid_or_forged_assertions;
  $("raw-auth").textContent = s.protected.raw_authorization;
  $("direct-rejected").textContent = s.protected.direct_raw_rejected;
  const proof = s.proof.real_evidence && s.proof.security_transition;
  $("proof").textContent = proof ? "REAL EVIDENCE → LANE TRANSITION → DENIAL" : "Waiting for a real observed transition…";
  $("proof").className = "proof " + (proof ? "pass" : "");
  $("timeline").innerHTML = s.timeline.map(e => `<tr><td>${new Date(e.at).toLocaleTimeString()}</td><td class="mono">${esc(e.request_id)}</td><td>${esc(e.actor)}</td><td class="mono">${esc(e.source_pseudonym)}</td><td class="mono">${esc(e.lane_id)}</td><td>${esc((e.evidence||[]).join(", "))}</td><td>${e.credential_risk}/${e.lane_risk}</td><td>${esc(e.transition)}</td><td>${esc(e.limit_class)}</td><td>${esc(e.decision)}</td><td>${e.backend_reached ? "✓ assertion" : "—"}</td></tr>`).join("");
}
async function refresh() { const r = await fetch("/api/state"); render(await r.json()); }
async function act(name) {
  $("status").textContent = actionLabels[name] || "working…";
  try { const r = await fetch(`/api/${name}`, {method:"POST"}); if (!r.ok) throw new Error(await r.text()); render(await r.json()); $("status").textContent = "complete"; }
  catch (e) { $("status").textContent = "error: " + e.message; }
}
document.querySelectorAll("button[data-action]").forEach(b => b.addEventListener("click", () => act(b.dataset.action)));
refresh();
