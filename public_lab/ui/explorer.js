(() => {
  "use strict";

  const dataNode = document.getElementById("lab-data");
  const panels = {
    overview: document.getElementById("panel-overview"),
    assurance: document.getElementById("panel-assurance"),
    review: document.getElementById("panel-review"),
  };
  const tabs = Array.from(document.querySelectorAll("[role='tab'][data-view]"));
  const main = document.getElementById("main-content");
  const announcer = create("p", { className: "sr-only", "aria-live": "polite", "aria-atomic": "true" });
  document.body.append(announcer);

  let data;
  try {
    data = JSON.parse(dataNode ? dataNode.textContent : "{}");
  } catch (error) {
    renderFatal("The embedded lab data could not be parsed.");
    return;
  }

  const manifest = isPlainObject(data.manifest) ? data.manifest : {};
  const cases = isPlainObject(data.cases) ? data.cases : {};
  const experiments = Array.isArray(manifest.experiments) ? manifest.experiments.filter(isPlainObject) : [];
  if (!experiments.length) {
    renderFatal("This artifact does not contain any public experiment records.");
    return;
  }

  const state = {
    view: "overview",
    experimentId: String(experiments[0].id || ""),
    variant: "genuine",
    artifact: "genuine.json",
  };
  let resizeFrame = 0;
  let toastTimer = 0;

  renderAssurance();
  renderReview();
  renderOverview();
  bindNavigation();
  window.addEventListener("resize", () => {
    if (resizeFrame) return;
    resizeFrame = window.requestAnimationFrame(() => {
      resizeFrame = 0;
      drawFingerprint();
    });
  }, { passive: true });

  function isPlainObject(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
  }

  function create(tag, attributes, ...children) {
    const node = document.createElement(tag);
    if (attributes) {
      Object.entries(attributes).forEach(([key, value]) => {
        if (value === undefined || value === null || value === false) return;
        if (key === "className") node.className = value;
        else if (key === "text") node.textContent = String(value);
        else if (key === "htmlFor") node.htmlFor = value;
        else if (key === "dataset" && isPlainObject(value)) Object.entries(value).forEach(([name, item]) => { node.dataset[name] = String(item); });
        else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2).toLowerCase(), value);
        else node.setAttribute(key, value === true ? "" : String(value));
      });
    }
    children.flat().forEach((child) => {
      if (child === null || child === undefined || child === false) return;
      node.append(child.nodeType ? child : document.createTextNode(String(child)));
    });
    return node;
  }

  function asText(value, fallback = "—") {
    return typeof value === "string" && value.length ? value : fallback;
  }

  function currentExperiment() {
    return experiments.find((item) => String(item.id) === state.experimentId) || experiments[0];
  }

  function currentCase() {
    return isPlainObject(cases[currentExperiment().id]) ? cases[currentExperiment().id] : {};
  }

  function rawArtifact(name = state.artifact) {
    const raw = currentCase().raw;
    return isPlainObject(raw) && typeof raw[name] === "string" ? raw[name] : "";
  }

  function artifactHash(name = state.artifact, experiment = currentExperiment()) {
    const files = isPlainObject(experiment.files) ? experiment.files : {};
    return typeof files[name] === "string" ? files[name].toLowerCase() : "";
  }

  function selectedResult() {
    const results = currentCase().results;
    return isPlainObject(results) && isPlainObject(results[state.variant]) ? results[state.variant] : {};
  }

  function safeResultDetail(result) {
    const items = [];
    ["verified", "reason", "effect", "settlement", "certification", "production", "confinement"].forEach((key) => {
      if (result[key] !== undefined && result[key] !== null) items.push(`${key}: ${String(result[key])}`);
    });
    return items.length ? items.join(" · ") : "The saved verifier output contains no additional summary fields.";
  }

  function outcomeClass(outcome) {
    const value = String(outcome || "").toUpperCase();
    if (value === "VERIFIED" || value === "MATCH" || value === "SETTLEMENT_VERIFIED") return "is-verified";
    if (["REJECTED", "DENIED", "MISMATCH"].includes(value)) return "is-rejected";
    return "is-neutral";
  }

  function shortHash(value) {
    const raw = asText(value, "");
    return raw.length > 22 ? `${raw.slice(0, 12)}…${raw.slice(-8)}` : raw || "not recorded";
  }

  function renderOverview() {
    const experiment = currentExperiment();
    const base = isPlainObject(manifest.base) ? manifest.base : {};
    const hero = create("section", { className: "hero", "aria-labelledby": "hero-title" });
    const heroCopy = create("div", { className: "hero-copy" },
      create("p", { className: "eyebrow", text: "Public Lab 001" }),
      create("h1", { id: "hero-title" }, "Evidence ", create("em", { text: "Explorer" })),
      create("p", { className: "hero-lede", text: "Inspect the signatures behind a fictional student record, a pending payment and an auditor’s disclosure. Compare each with its altered copy to see what the verifier rejects." }),
      create("div", { className: "hero-meta" },
        metaPair("Experiments", String(experiments.length).padStart(2, "0")),
        metaPair("Base commit", shortHash(base.commit)),
        metaPair("Selected case", asText(experiment.category, experiment.id)),
      ),
    );
    const canvas = create("canvas", { id: "fingerprint-canvas", className: "fingerprint-canvas", "aria-hidden": "true" });
    const fingerprint = create("div", { className: "fingerprint" }, canvas,
      create("div", { className: "fingerprint-caption" },
        create("span", { text: "Record fingerprint · SHA-256" }),
        create("code", { id: "hero-digest", text: artifactHash("genuine.json", experiment) || "digest unavailable" }),
      ),
    );
    hero.append(heroCopy, fingerprint);

    const experimentSection = create("section", { "aria-labelledby": "experiments-title" },
      create("div", { className: "section-head" },
        create("h2", { id: "experiments-title", text: "Choose an experiment" }),
        create("p", { text: "Three signed synthetic cases with public evidence and altered comparison records." }),
      ),
    );
    const rail = create("div", { className: "experiment-rail", "aria-label": "Public experiments" });
    experiments.forEach((item, index) => rail.append(experimentCard(item, index)));
    experimentSection.append(rail);

    panels.overview.replaceChildren(hero, experimentSection, detailWorkbench(experiment));
    window.requestAnimationFrame(drawFingerprint);
  }

  function metaPair(label, value) {
    return create("span", null, create("b", { text: `${label}:` }), create("code", { text: value }));
  }

  function experimentCard(experiment, index) {
    const selected = String(experiment.id) === state.experimentId;
    const card = create("button", {
      className: `experiment-card${selected ? " is-selected" : ""}`,
      type: "button",
      "aria-pressed": String(selected),
      "data-experiment-id": String(experiment.id),
      "data-action": "select-experiment",
    },
      create("span", { className: "experiment-card-index", text: reviewedGate(experiment.id, index) }),
      create("span", { className: "experiment-card-title", text: asText(experiment.title, experiment.id) }),
      create("p", { className: "experiment-card-desc", text: asText(experiment.description, "Public synthetic experiment record.") }),
      create("span", { className: "experiment-card-meta", text: asText(experiment.operation, experiment.category) }),
    );
    card.addEventListener("click", () => selectExperiment(experiment.id, card));
    return card;
  }

  function reviewedGate(id, index) {
    const gates = { education: "Reviewed Gate 002", finance: "Reviewed Gate 003", history: "Reviewed Gate 004" };
    return gates[String(id)] || `Reviewed case ${String(index + 1).padStart(2, "0")}`;
  }

  function selectExperiment(id, source) {
    state.experimentId = String(id);
    state.variant = "genuine";
    state.artifact = "genuine.json";
    renderOverview();
    renderReview();
    const next = panels.overview.querySelector(`[data-experiment-id="${cssEscape(state.experimentId)}"]`);
    if (source && next) next.focus();
    announce(`Selected ${asText(currentExperiment().title, currentExperiment().id)}.`);
  }

  function detailWorkbench(experiment) {
    const source = isPlainObject(experiment.source) ? experiment.source : {};
    const detail = create("section", { className: "experiment-detail", "aria-labelledby": "detail-title" });
    const heading = create("div", { className: "detail-header" },
      create("div", null,
        create("p", { className: "detail-kicker", text: `${asText(experiment.category, "experiment")} / ${asText(experiment.operation, "operation")}` }),
        create("h2", { id: "detail-title", className: "detail-title", text: asText(experiment.title, experiment.id) }),
        create("p", { className: "detail-description", text: asText(experiment.description, "") }),
      ),
      create("aside", { className: "claim-block", "aria-label": "Recorded claim scope" },
        create("span", { className: "micro-label", text: "Recorded claim" }),
        create("p", { text: asText(experiment.claim, "No claim text was recorded.") }),
        create("span", { className: "micro-label", text: "Scope" }),
        create("p", { text: asText(experiment.scope, "No scope text was recorded.") }),
      ),
    );
    const sourceStrip = create("div", { className: "source-strip", "aria-label": "Source references" },
      sourceCell("Pull request", source.pr), sourceCell("Commit", source.commit), sourceCell("Tree", source.tree),
    );
    const workbench = create("div", { className: "detail-workbench" }, verificationColumn(experiment), evidenceColumn(experiment));
    detail.append(heading, sourceStrip, workbench);
    return detail;
  }

  function sourceCell(label, value) {
    return create("div", { className: "source-cell" }, create("span", { className: "micro-label", text: label }), create("code", { text: asText(value, "not recorded") }));
  }

  function verificationColumn(experiment) {
    const column = create("div", { className: "verification-column" },
      create("div", { className: "subhead" }, create("h3", { text: "Verification station" }), create("p", { text: "Saved output and optional local checks" })),
      variantControl(),
      recordedVerdict(),
      signedRecordCheck(experiment),
      digestCheck(experiment),
      commandPanel(),
    );
    return column;
  }

  function variantControl() {
    const group = create("div", { className: "variant-control" }, create("span", { className: "micro-label", text: "Select a published record" }));
    const buttons = create("div", { className: "variant-buttons", role: "group", "aria-label": "Published record variant" });
    [
      ["genuine", "Genuine record", "Saved successful path"],
      ["tampered", "Tampered control", "Published altered input"],
    ].forEach(([variant, label, note]) => {
      const active = state.variant === variant;
      const button = create("button", {
        className: `variant-button${active ? " is-active" : ""}`,
        type: "button",
        "aria-pressed": String(active),
        "data-variant": variant,
        "data-action": "select-variant",
      }, create("strong", { text: label }), create("small", { text: note }));
      button.addEventListener("click", () => selectVariant(variant, button));
      buttons.append(button);
    });
    group.append(buttons);
    return group;
  }

  function selectVariant(variant, source) {
    state.variant = variant;
    state.artifact = `${variant}.json`;
    renderOverview();
    renderReview();
    const next = panels.overview.querySelector(`[data-variant="${variant}"]`);
    if (source && next) next.focus();
    announce(`Showing the ${variant} published record.`);
  }

  function recordedVerdict() {
    const result = selectedResult();
    const outcome = asText(result.outcome, "NOT RECORDED");
    return create("section", {
      className: `verdict-panel ${outcomeClass(outcome)}`,
      "data-region": "recorded-result",
      "aria-live": "polite",
      "aria-label": "Recorded canonical verifier result",
    },
      create("p", { className: "verdict-label", text: "Recorded canonical verifier result" }),
      create("p", { className: "verdict-outcome" }, create("b", { text: outcome }), result.reason ? create("code", { text: String(result.reason) }) : null),
      create("p", { className: "verdict-detail", text: safeResultDetail(result) }),
    );
  }

  function signedRecordCheck(experiment) {
    const check = create("section", { className: "check-card", "aria-labelledby": "signed-check-title" },
      create("h4", { id: "signed-check-title", text: "Signed-record check" }),
      create("p", { text: "Runs the bundled browser cryptography check over the selected record, public pins, and challenge. This is narrower than the saved canonical Python verifier result." }),
    );
    const result = create("p", { className: "integrity-result", "data-region": "signed-result", "aria-live": "polite", text: "Not run in this browser." });
    const button = create("button", { className: "button", type: "button", "data-action": "check-signed-record", text: "Check signed record" });
    button.addEventListener("click", async () => {
      button.disabled = true;
      result.className = "integrity-result";
      result.textContent = "Checking the selected signed record locally…";
      try {
        if (typeof window.quorvaneCheckRecord !== "function") {
          setLiveResult(result, { outcome: "UNSUPPORTED", detail: "The bundled WebCrypto verifier is unavailable in this browser build." });
          return;
        }
        const output = await window.quorvaneCheckRecord(
          String(experiment.id), rawArtifact(`${state.variant}.json`), rawArtifact("pins.json"), rawArtifact("challenge.txt"),
        );
        if (!isPlainObject(output)) throw new Error("The bundled checker returned an invalid result.");
        setLiveResult(result, output);
      } catch (error) {
        setLiveResult(result, { outcome: "REJECTED", detail: error instanceof Error ? error.message : "Local signed-record check failed." });
      } finally {
        button.disabled = false;
      }
    });
    check.append(create("div", { className: "check-actions" }, button), result);
    return check;
  }

  function setLiveResult(node, output) {
    const outcome = asText(output.outcome, "UNSUPPORTED");
    const detail = asText(output.detail, "No local-check detail was returned.");
    node.textContent = `${outcome} — ${detail}`;
    node.className = `integrity-result ${outcome === "MATCH" ? "is-match" : outcome === "REJECTED" ? "is-mismatch" : ""}`;
  }

  function digestCheck(experiment) {
    const check = create("section", { className: "check-card", "aria-labelledby": "digest-check-title" },
      create("h4", { id: "digest-check-title", text: "Local file digest" }),
      create("p", { text: "Compares UTF-8 bytes with the manifest SHA-256 for the selected artifact. A match does not verify signatures or the complete authority chain." }),
    );
    const result = create("p", { className: "integrity-result", "data-region": "digest-result", "aria-live": "polite", text: "Not checked." });
    const packaged = create("button", { className: "button-quiet", type: "button", "data-action": "check-digest", text: "Check packaged bytes" });
    packaged.addEventListener("click", async () => {
      const expected = artifactHash();
      if (!expected) return setDigestResult(result, "UNSUPPORTED", "No manifest digest is recorded for this artifact.");
      try {
        const digest = await sha256Hex(new TextEncoder().encode(rawArtifact()));
        setDigestResult(result, digest === expected ? "MATCH" : "MISMATCH", digest === expected ? `Matches published SHA-256 ${shortHash(expected)}.` : `Does not match published SHA-256 ${shortHash(expected)}.`);
      } catch (error) {
        setDigestResult(result, "UNSUPPORTED", "WebCrypto SHA-256 is unavailable in this browser.");
      }
    });
    const input = create("input", { type: "file", accept: ".json,.txt,application/json,text/plain", "aria-label": "Choose a local artifact to compare" });
    input.addEventListener("change", async () => {
      const file = input.files && input.files[0];
      if (!file) return;
      const expected = artifactHash();
      if (!expected) return setDigestResult(result, "UNSUPPORTED", "No manifest digest is recorded for this artifact.");
      try {
        const digest = await sha256Hex(await file.arrayBuffer());
        setDigestResult(result, digest === expected ? "MATCH" : "MISMATCH", digest === expected ? `${file.name} matches the published digest.` : `${file.name} does not match the published digest.`);
      } catch (error) {
        setDigestResult(result, "UNSUPPORTED", "The selected file could not be checked locally.");
      } finally {
        input.value = "";
      }
    });
    const label = create("label", { className: "file-label", text: "Compare a local file" }, input);
    check.append(create("div", { className: "check-actions" }, packaged, label), result);
    return check;
  }

  function setDigestResult(node, outcome, detail) {
    node.textContent = `${outcome} — ${detail}`;
    node.className = `integrity-result ${outcome === "MATCH" ? "is-match" : outcome === "MISMATCH" ? "is-mismatch" : ""}`;
  }

  function commandPanel() {
    const command = asText(currentCase().commands && currentCase().commands[state.variant], "python scripts/public_lab.py verify");
    const copy = create("button", { className: "button-quiet", type: "button", "data-action": "copy-command", "aria-label": "Copy verifier command", text: "Copy" });
    copy.addEventListener("click", () => copyText(command, "Verifier command copied."));
    return create("section", { className: "command-panel", "aria-label": "Published verifier command" },
      create("h4", { text: "Run the complete verifier locally" }),
      create("p", { text: "The recorded result above came from the canonical verifier. Run its exact published command outside the browser for the complete authority-chain check." }),
      create("div", { className: "command-line", "data-region": "command" }, create("code", { text: command }), copy),
    );
  }

  function evidenceColumn(experiment) {
    const column = create("div", { className: "evidence-column" }, create("div", { className: "subhead" }, create("h3", { text: "Public evidence" }), create("p", { text: "Exact embedded bytes" })));
    const artifacts = ["genuine.json", "tampered.json", "pins.json", "challenge.txt"].filter((name) => rawArtifact(name) || artifactHash(name, experiment));
    if (!artifacts.includes(state.artifact)) state.artifact = artifacts[0] || "genuine.json";
    const tabsNode = create("div", { className: "artifact-tabs", role: "tablist", "aria-label": "Evidence artifact" });
    artifacts.forEach((artifact) => {
      const active = artifact === state.artifact;
      const button = create("button", {
        className: `artifact-tab${active ? " is-active" : ""}`,
        type: "button",
        role: "tab",
        "aria-selected": String(active),
        "data-artifact": artifact,
        "data-action": "select-artifact",
        text: artifact,
      });
      button.addEventListener("click", () => {
        state.artifact = artifact;
        renderOverview();
        const next = panels.overview.querySelector(`[data-artifact="${cssEscape(artifact)}"]`);
        if (next) next.focus();
      });
      tabsNode.append(button);
    });
    const raw = rawArtifact();
    const expected = artifactHash();
    const copy = create("button", { className: "button-quiet", type: "button", "data-action": "copy-artifact", text: "Copy exact bytes" });
    copy.addEventListener("click", () => copyText(raw, `${state.artifact} copied.`));
    const download = create("button", { className: "button", type: "button", "data-action": "download-artifact", text: "Download artifact" });
    download.addEventListener("click", () => downloadText(state.artifact, raw, state.artifact.endsWith(".json") ? "application/json;charset=utf-8" : "text/plain;charset=utf-8"));
    const downloadPins = create("button", { className: "button-quiet", type: "button", "data-action": "download-public-keys", text: "Download public keys" });
    downloadPins.addEventListener("click", () => downloadText("pins.json", rawArtifact("pins.json"), "application/json;charset=utf-8"));
    const tools = create("div", { className: "artifact-tools" },
      create("span", { className: "artifact-meta", text: expected ? `Manifest SHA-256: ${expected}` : "No manifest digest recorded for this artifact." }),
      create("div", { className: "artifact-actions" }, copy, download, downloadPins),
    );
    const pre = create("pre", { className: "evidence-pre", tabindex: "0", "aria-label": `Exact content of ${state.artifact}`, text: raw || "Artifact text is unavailable." });
    column.append(tabsNode, tools, pre);
    return column;
  }

  function renderAssurance() {
    const conditions = Array.isArray(manifest.conditions) ? manifest.conditions.filter(isPlainObject) : [];
    const base = isPlainObject(manifest.base) ? manifest.base : {};
    const section = create("div", null,
      create("p", { className: "eyebrow", text: "Assurance boundary" }),
      create("h1", { className: "assurance-title", text: "What this artifact does—and does not—establish" }),
      create("p", { className: "assurance-intro", text: "Conditions are recorded from the qualified research runs. A signed or hashed record authenticates only its declared, bounded statement; it does not upgrade unsupported controls into a production claim." }),
    );
    const table = create("table", { className: "condition-table" });
    const head = create("thead", null, create("tr", null, create("th", { text: "Condition" }), create("th", { text: "Recorded status" }), create("th", { text: "Evidence boundary" })));
    const body = create("tbody");
    conditions.forEach((condition) => {
      const status = asText(condition.status, "NOT_ASSESSED");
      body.append(create("tr", { "data-condition-id": asText(condition.id, "") },
        create("td", { text: asText(condition.title, condition.id) }),
        create("td", null, create("span", { className: `condition-status status-${status}`, text: status.replaceAll("_", " ") })),
        create("td", { text: asText(condition.detail, "No explanatory detail was recorded.") }),
      ));
    });
    if (!conditions.length) body.append(create("tr", null, create("td", { colspan: "3", text: "No assurance conditions were embedded in this artifact." })));
    table.append(head, body);
    section.append(create("div", { className: "assurance-matrix" }, table));
    section.append(create("aside", { className: "assurance-notice" }, create("strong", { text: "Source boundary. " }), `Base commit ${shortHash(base.commit)} / tree ${shortHash(base.tree)} / PR ${asText(base.pr, "not recorded")}. Independent escrow, full confinement, and production certification remain governed by their explicit recorded status.`));
    panels.assurance.replaceChildren(section);
  }

  function renderReview() {
    const experiment = currentExperiment();
    const reviewKey = `${String(experiment.id)}:${state.variant}`;
    if (panels.review.dataset.reviewKey === reviewKey && panels.review.childElementCount) return;
    const result = selectedResult();
    const rawCommand = asText(currentCase().commands && currentCase().commands[state.variant], "python scripts/public_lab.py verify");
    const expectedText = result.reason ? `Recorded ${asText(result.outcome, "outcome")} (${result.reason})` : `Recorded ${asText(result.outcome, "outcome")}`;
    const artifactDigest = artifactHash(`${state.variant}.json`, experiment);
    const layout = create("div", null,
      create("p", { className: "eyebrow", text: "Human review / local handoff" }),
      create("h1", { className: "review-title", text: "Record a browser finding" }),
      create("p", { className: "review-intro", text: "This page cannot submit findings or contact a service. It creates one exact JSON file for manual review; do not include credentials, private material, or real-world records." }),
    );
    const aside = create("aside", { className: "review-aside" },
      create("h3", { text: "Local-only workflow" }),
      create("p", { text: "The form never stores or transmits your text automatically. Download the JSON, review it, then choose whether to submit it through the local review command." }),
      create("ol", null,
        create("li", { text: "Inspect the selected public artifact and recorded result." }),
        create("li", { text: "Describe reproducible observations without sensitive data." }),
        create("li", { text: "Download the local JSON and submit it manually if appropriate." }),
      ),
      create("code", { text: "python scripts/public_lab_finding.py submit finding.json --inbox review-inbox" }),
    );
    const form = create("form", { className: "finding-form", "data-form": "finding", autocomplete: "off", novalidate: "" },
      create("h3", { text: "Finding manifest" }),
      create("p", { text: "Required fields are exported exactly in the local finding schema. No credential fields are present." }),
    );
    const fields = create("div", { className: "finding-grid" });
    fields.append(readoutField("Experiment", experiment.id), readoutField("Variant", state.variant), readoutField("Artifact SHA-256", artifactDigest), readoutField("Manifest SHA-256", asText(data.manifest_sha256, "missing")));
    fields.append(inputField("Environment", "environment", "Local browser review — update with browser and OS", false),
      inputField("Steps", "steps", rawCommand, true),
      inputField("Expected", "expected", expectedText, true),
      inputField("Observed", "observed", "", true, "Describe the observed result without sensitive data."));
    const status = create("p", { className: "form-status", "aria-live": "polite", "data-region": "finding-status" });
    const download = create("button", { className: "button button-rust", type: "submit", "data-action": "download-finding", text: "Download local finding JSON" });
    form.append(fields, create("p", { className: "form-note", text: "No automatic persistence. The downloaded file contains only the declared public-artifact reference and the four review fields." }), download, status);
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const formData = new FormData(form);
      const values = ["environment", "steps", "expected", "observed"].reduce((memo, key) => ({ ...memo, [key]: String(formData.get(key) || "").trim() }), {});
      const invalidField = Object.entries(values).find(([, value]) => !value || value.includes("\0") || new TextEncoder().encode(value).byteLength > 4096);
      if (!data.manifest_sha256 || !artifactDigest || invalidField) {
        status.className = "form-status is-error";
        status.textContent = invalidField
          ? `${invalidField[0]} must be nonempty, contain no NUL, and be at most 4096 UTF-8 bytes.`
          : "A manifest digest and artifact digest are required before download.";
        return;
      }
      const finding = {
        schema: "quorvane.public-lab.finding.v1",
        experiment: String(experiment.id),
        variant: state.variant,
        artifact_sha256: artifactDigest,
        manifest_sha256: String(data.manifest_sha256),
        environment: values.environment,
        steps: values.steps,
        expected: values.expected,
        observed: values.observed,
      };
      downloadText("finding.json", `${JSON.stringify(finding, null, 2)}\n`, "application/json;charset=utf-8");
      status.className = "form-status is-ok";
      status.textContent = "Local finding JSON downloaded. It was not sent or stored by this page.";
    });
    layout.append(create("div", { className: "review-layout" }, aside, form));
    panels.review.replaceChildren(layout);
    panels.review.dataset.reviewKey = reviewKey;
  }

  function readoutField(label, value) {
    return create("div", null, create("span", { className: "field-label", text: label }), create("div", { className: "field-readout", text: asText(value, "not recorded") }));
  }

  function inputField(label, name, value, multiline, placeholder = "") {
    const field = create("div", { className: multiline ? "field-wide" : "" });
    const id = `finding-${name}`;
    const control = multiline
      ? create("textarea", { id, name, required: "", rows: name === "observed" ? "5" : "4", placeholder, text: value })
      : create("input", { id, name, type: "text", required: "", value, placeholder });
    field.append(create("label", { className: "field-label", htmlFor: id, text: label }), control);
    return field;
  }

  function bindNavigation() {
    tabs.forEach((tab, index) => {
      tab.addEventListener("click", () => showView(tab.dataset.view, true));
      tab.addEventListener("keydown", (event) => {
        const keys = ["ArrowLeft", "ArrowRight", "Home", "End"];
        if (!keys.includes(event.key)) return;
        event.preventDefault();
        let next = index;
        if (event.key === "ArrowLeft") next = (index - 1 + tabs.length) % tabs.length;
        if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
        if (event.key === "Home") next = 0;
        if (event.key === "End") next = tabs.length - 1;
        tabs[next].focus();
        showView(tabs[next].dataset.view, false);
      });
    });
  }

  function showView(view, moveFocus) {
    if (!panels[view]) return;
    state.view = view;
    tabs.forEach((tab) => {
      const active = tab.dataset.view === view;
      tab.classList.toggle("is-active", active);
      tab.setAttribute("aria-selected", String(active));
      tab.tabIndex = active ? 0 : -1;
    });
    Object.entries(panels).forEach(([name, panel]) => {
      const active = name === view;
      panel.hidden = !active;
      panel.classList.toggle("is-active", active);
    });
    if (view === "review") renderReview();
    if (moveFocus) main.focus();
  }

  async function sha256Hex(bytes) {
    if (!window.crypto || !window.crypto.subtle) throw new Error("WebCrypto unavailable");
    const digest = await window.crypto.subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
  }

  function drawFingerprint() {
    const canvas = document.getElementById("fingerprint-canvas");
    if (!canvas) return;
    const box = canvas.getBoundingClientRect();
    if (!box.width || !box.height) return;
    const ratio = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = Math.floor(box.width * ratio);
    canvas.height = Math.floor(box.height * ratio);
    const context = canvas.getContext("2d");
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
    const width = box.width;
    const height = box.height;
    const hash = artifactHash("genuine.json") || artifactHash() || "0".repeat(64);
    const bytes = Array.from({ length: 32 }, (_, index) => Number.parseInt(hash.slice(index * 2, index * 2 + 2), 16) || 0);
    const background = context.createLinearGradient(0, 0, width, height);
    background.addColorStop(0, "#163d37");
    background.addColorStop(.55, "#0b302c");
    background.addColorStop(1, "#173d36");
    context.fillStyle = background;
    context.fillRect(0, 0, width, height);
    context.lineCap = "round";
    context.lineJoin = "round";
    for (let grid = 1; grid < 7; grid += 1) {
      context.strokeStyle = "rgba(198,234,209,.075)";
      context.lineWidth = .75;
      context.beginPath();
      context.moveTo((width / 7) * grid, 0);
      context.lineTo((width / 7) * grid, height);
      context.moveTo(0, (height / 5) * (grid - 1));
      context.lineTo(width, (height / 5) * (grid - 1));
      context.stroke();
    }
    const centerX = width * (.43 + (bytes[0] / 255) * .16);
    const centerY = height * (.44 + (bytes[1] / 255) * .12);
    const tilt = ((bytes[2] / 255) - .5) * .42;
    const phase = (bytes[3] / 255) * Math.PI * 2;
    const contourCount = 29;
    context.save();
    context.translate(centerX, centerY);
    context.rotate(tilt);
    for (let layer = 0; layer < contourCount; layer += 1) {
      const step = layer / (contourCount - 1);
      const rx = width * (.53 - step * .43);
      const ry = height * (.66 - step * .52);
      const ridgePhase = phase + (bytes[(layer + 6) % bytes.length] / 255) * .42;
      const skew = (bytes[(layer + 12) % bytes.length] / 255 - .5) * 18;
      context.strokeStyle = layer % 6 === 0
        ? "rgba(231,151,83,.92)"
        : `rgba(184,232,204,${.38 + (layer % 5) * .075})`;
      context.lineWidth = layer % 6 === 0 ? 1.42 : .94;
      context.beginPath();
      // A nested, tilted contour is distorted by several digest-derived waves;
      // it reads as a single physical ridge rather than unrelated trace lines.
      for (let degrees = 0; degrees <= 360; degrees += 2) {
        const theta = (degrees / 180) * Math.PI;
        const shoulder = Math.sin(theta * 2 + ridgePhase) * (7 + (bytes[(layer + 19) % bytes.length] / 255) * 8) * (1 - step * .45);
        const grain = Math.sin(theta * (3 + (bytes[(layer + 23) % bytes.length] % 3)) - ridgePhase) * (3 + (bytes[(layer + 27) % bytes.length] / 255) * 4);
        const radial = 1 + Math.sin(theta * 3 + ridgePhase) * (.035 + (bytes[(layer + 9) % bytes.length] / 255) * .03);
        const asymmetric = Math.max(0, Math.sin(theta - .35)) * (1 - step) * (10 + (bytes[(layer + 15) % bytes.length] / 255) * 10);
        const x = Math.cos(theta) * rx * radial + shoulder + skew * Math.sin(theta);
        const y = Math.sin(theta) * ry * radial + grain - asymmetric;
        if (degrees === 0) context.moveTo(x, y); else context.lineTo(x, y);
      }
      context.closePath();
      context.stroke();
    }
    // A restrained internal bifurcation makes the contour nest visibly
    // asymmetric while retaining a stable fingerprint/topographic silhouette.
    for (let branch = 0; branch < 5; branch += 1) {
      const offset = (branch - 2) * 8;
      context.strokeStyle = branch === 2 ? "rgba(231,151,83,.82)" : "rgba(184,232,204,.42)";
      context.lineWidth = branch === 2 ? 1.2 : .8;
      context.beginPath();
      for (let t = -1.05; t <= 1.05; t += .025) {
        const x = t * width * .31 + Math.sin(t * 6 + phase) * (6 + branch);
        const y = offset + Math.sin(t * Math.PI + phase) * height * .13 + t * t * height * .105;
        if (t <= -1.04) context.moveTo(x, y); else context.lineTo(x, y);
      }
      context.stroke();
    }
    context.restore();
  }

  async function copyText(value, message) {
    try {
      if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(value);
      else {
        const area = create("textarea", { text: value, "aria-hidden": "true" });
        area.style.cssText = "position:fixed;left:-9999px;top:0";
        document.body.append(area);
        area.select();
        const copied = document.execCommand("copy");
        area.remove();
        if (!copied) throw new Error("Copy command was unavailable");
      }
      showToast(message);
    } catch (error) {
      showToast("Copy was unavailable. Select the displayed text instead.");
    }
  }

  function downloadText(name, value, mime) {
    const blob = new Blob([value], { type: mime });
    const url = URL.createObjectURL(blob);
    const anchor = create("a", { href: url, download: name });
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 500);
    showToast(`${name} downloaded locally.`);
  }

  function showToast(message) {
    let toast = document.querySelector(".toast");
    if (!toast) {
      toast = create("div", { className: "toast", role: "status", "aria-live": "polite" });
      document.body.append(toast);
    }
    toast.textContent = message;
    toast.classList.add("is-visible");
    window.clearTimeout(toastTimer);
    toastTimer = window.setTimeout(() => toast.classList.remove("is-visible"), 2600);
  }

  function announce(message) {
    announcer.textContent = "";
    window.setTimeout(() => { announcer.textContent = message; }, 20);
  }

  function cssEscape(value) {
    if (window.CSS && typeof window.CSS.escape === "function") return window.CSS.escape(value);
    return String(value).replace(/[^a-zA-Z0-9_-]/g, "\\$&");
  }

  function renderFatal(message) {
    const target = panels.overview || document.body;
    target.replaceChildren(create("section", { className: "assurance-notice" }, create("strong", { text: "Evidence explorer unavailable. " }), message));
  }
})();
