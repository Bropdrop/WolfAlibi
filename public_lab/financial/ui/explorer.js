"use strict";
(() => {
  const el = id => document.getElementById(id);
  const {cases, artifacts, report} = JSON.parse(el("payload").textContent);
  const recorded = new Map(report.cases.map(row => [row.id, row]));
  const families = {
    A: "Authorization substitution", B: "Replay and duplicate effects",
    C: "Historical authority confusion", D: "Settlement confusion",
    E: "Evidence substitution", F: "Rollback and incomplete evidence", P: "Positive controls"
  };
  const states = ["REJECTED", "VERIFIED", "UNSUPPORTED", "NOT_ASSESSED", "INPUT_REFUSED", "ERROR", "BLOCKED"];
  const boundaries = ["assurance", "cross_uid_custody", "confinement", "production", "certification"];
  let current, group, submitted, reportVersion = 0;
  const notes = new Map();
  async function sha256(raw) {
    if (!window.crypto?.subtle) return null;
    try {
      const result = new Uint8Array(await crypto.subtle.digest("SHA-256", raw));
      return Array.from(result, n => n.toString(16).padStart(2, "0")).join("");
    } catch { return null; }
  }
  const byteArray = path => Uint8Array.from(atob(artifacts[path].base64), c => c.charCodeAt(0));
  const put = (id, text) => { el(id).textContent = text; };
  const make = (tag, text, cls) => {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    node.textContent = text;
    return node;
  };
  const familyOf = item => item.id[0];
  const matchesExpected = (actual, expected) => actual.outcome === expected.outcome && actual.reason === expected.reason;

  // Unknown keys may contain private text. Export only public field names.
  function differences(actual, known, path = "$", result = []) {
    if (actual === known || result.length >= 12) return result;
    if (!actual || !known || typeof actual !== "object" || typeof known !== "object" ||
        Array.isArray(actual) !== Array.isArray(known)) {
      result.push(path);
      return result;
    }
    for (const key of Object.keys(known)) {
      if (result.length >= 12) break;
      const next = path + "." + key;
      if (!Object.hasOwn(actual, key)) result.push(next);
      else differences(actual[key], known[key], next, result);
    }
    if (result.length < 12 && Object.keys(actual).some(key => !Object.hasOwn(known, key))) result.push(path + ".[extra field]");
    return result;
  }

  function showGroup(family, selectedId) {
    group = cases.filter(item => familyOf(item) === family);
    el("family").value = family;
    el("case").replaceChildren(...group.map(row => new Option(row.id + " · " + row.title, row.id)));
    el("case").value = selectedId || group[0].id;
    showCase();
  }

  function bytesPane(label, path, raw, offset) {
    const panel = make("div", "", "bytes");
    const details = make("details", "");
    const text = new TextDecoder().decode(raw);
    details.append(make("summary", "View complete text"), make("pre", text));
    const from = Math.max(0, offset - 48);
    const excerpt = new TextDecoder().decode(raw.slice(from, Math.min(raw.length, offset + 90)));
    panel.append(make("p", label, "small-title"), make("code", path, "path"),
      make("pre", excerpt || "(empty)"), make("code", artifacts[path].sha256, "digest"), details);
    return panel;
  }

  function showBytes() {
    const original = byteArray(current.reference);
    const specimen = byteArray(current.fixture);
    let offset = 0;
    while (offset < original.length && offset < specimen.length && original[offset] === specimen[offset]) offset++;
    const same = offset === original.length && offset === specimen.length;
    put("difference", (same ? "This case uses the published reference bytes."
      : "First differing byte at offset " + offset + " (counting from zero).") +
      " Excerpts show nearby UTF-8 text. SHA-256 covers the complete original bytes, including malformed encodings.");
    el("byte-panes").replaceChildren(bytesPane("Published reference", current.reference, original, same ? 0 : offset),
      bytesPane("Challenge fixture", current.fixture, specimen, same ? 0 : offset));
  }

  function showCase() {
    if (current) notes.set(current.id, el("note").value);
    current = group.find(item => item.id === el("case").value);
    const result = recorded.get(current.id);
    const index = group.indexOf(current);
    put("case-code", current.id + " / " + families[familyOf(current)]);
    put("case-title", current.title);
    for (const id of ["hypothesis", "inputs", "assumptions"]) put(id, current[id]);
    put("limit", current.limitation);
    el("target-note").hidden = familyOf(current) !== "B";
    put("index-note", "Case " + (index + 1) + " of " + group.length + " in this family · " + cases.length + " across the matrix");
    el("prev").disabled = index === 0;
    el("next").disabled = index === group.length - 1;
    put("expected", current.expected.outcome);
    put("expected-reason", current.expected.reason);
    put("recorded", result.observed.outcome);
    put("recorded-reason", result.observed.reason);
    put("recorded-scope", "Recorded comparison: " + result.result + ". Verification phase: " + result.observed.phase +
      ". The supplied observation applies to this fixture and its pinned expectations.");
    put("recorded-details", JSON.stringify(result.observed, null, 2));
    put("command", current.command + " > local-report.json");
    put("custom-command", "python -I scripts/financial_receipt_check.py " + current.profile + " my-evidence.json");
    showBytes();
    for (const id of ["hash-result", "copy-result", "export-state"]) put(id, "");
    el("note").value = notes.get(current.id) || "";
    refreshCompared();
  }

  async function checkHash() {
    const row = current;
    const value = await sha256(byteArray(row.fixture));
    if (row !== current) return;
    if (!value) put("hash-result", "UNSUPPORTED · Browser SHA-256 is unavailable. Use the Python command.");
    else put("hash-result", (value === row.sha256 ? "MATCH" : "MISMATCH") +
      " · Compared fixture bytes with the packaged digest. No signature or authority check was performed.");
  }

  function parseReport(text) {
    const parsed = JSON.parse(text);
    // JSON.parse accepts repeated fields. Inspect string tokens before comparing a report.
    const objects = [];
    let previous;
    for (const [token] of text.matchAll(/"(?:\\.|[^"\\])*"|[{}\[\]:]/g)) {
      if (token === "{" || token === "[") objects.push(new Set());
      else if (token === "}" || token === "]") objects.pop();
      else if (token === ":") {
        const keys = objects[objects.length - 1];
        const key = JSON.parse(previous);
        if (keys.has(key)) throw Error("Repeated field in the submitted JSON.");
        keys.add(key);
      }
      previous = token;
    }
    return parsed;
  }

  function checkSubmitted(doc) {
    if (doc?.schema !== report.schema || doc.matrix_sha256 !== report.matrix_sha256 ||
        doc.baseline?.commit !== report.baseline.commit || doc.baseline?.tree !== report.baseline.tree ||
        !boundaries.every(key => doc[key] === report[key]) || !Array.isArray(doc.cases)) {
      throw Error("Profile, baseline, matrix digest, or assurance labels differ from the package.");
    }
    if (doc.selected_case !== "all" && !recorded.has(doc.selected_case)) throw Error("Unknown selected case.");
    const scheduled = cases.filter(row => doc.selected_case === "all" || familyOf(row) === "P" || row.id === doc.selected_case);
    const rows = new Map();
    if (doc.cases.length !== scheduled.length) throw Error("The submitted case set is incomplete.");
    for (const item of doc.cases) {
      const known = scheduled.find(row => row.id === item?.id);
      if (!known || rows.has(item.id) || item.sha256 !== known.sha256 || item.fixture !== known.fixture ||
          !item.expected || !matchesExpected(item.expected, known.expected) || item.expected_phase !== known.expected_phase) {
        throw Error("Repeated case or inconsistent case, path, digest, or expectation.");
      }
      if (!item.observed || typeof item.observed.outcome !== "string" || typeof item.observed.reason !== "string"
          || typeof item.observed.phase !== "string" || item.observed.reason.length > 2048) {
        throw Error("Missing or malformed observation.");
      }
      rows.set(item.id, item.observed);
    }
    if (!["PASS", "SELECTED", "BLOCKED"].includes(doc.outcome)) throw Error("Unknown runner status.");
    const source = doc.provenance;
    const provenance = {mode: ["EXACT_GIT", "PORTABLE", "UNVERIFIED"].includes(source?.mode) ? source.mode : "UNRECOGNIZED"};
    for (const key of ["commit", "tree", "parent"]) {
      if (typeof source?.[key] === "string" && /^[0-9a-f]{40}$/.test(source[key])) provenance[key] = source[key];
    }
    return {rows, runner: doc.outcome, provenance};
  }

  function refreshCompared() {
    const local = submitted?.rows?.get(current.id);
    el("import-state").classList.toggle("attention", Boolean(submitted?.error || (local && differences(local, recorded.get(current.id).observed).length)));
    if (submitted?.error) put("import-state", "Comparison unavailable · " + submitted.error + " · File SHA-256: " + (submitted.sha256 || "UNAVAILABLE"));
    else if (!submitted) put("import-state", "No local report selected.");
    else if (!local) put("import-state", "This report covers a different case.");
    else {
      const match = matchesExpected(local, current.expected);
      const delta = differences(local, recorded.get(current.id).observed);
      put("import-state", "Author-reported " + local.outcome + " · " + local.reason +
        " · Phase: " + local.phase + ". " + (match ? "Outcome and reason match the expectation." : "Outcome or reason differs from the expectation.") +
        " Complete observation " + (delta.length ? "differs at " + delta.join(", ") : "matches the packaged observation") +
        ". Submitted runner status: " + submitted.runner + ". Submitted file SHA-256: " + (submitted.sha256 || "UNAVAILABLE") + ".");
    }
  }

  async function importFile() {
    const version = ++reportVersion;
    submitted = undefined;
    refreshCompared();
    const file = el("import-report").files[0];
    if (!file) return;
    let digest = null;
    try {
      if (file.size > 1048576) throw Error("Select a report smaller than 1 MiB.");
      const bytes = await file.arrayBuffer();
      digest = await sha256(bytes);
      const doc = parseReport(new TextDecoder("utf-8", {fatal: true}).decode(bytes));
      const data = checkSubmitted(doc);
      data.sha256 = digest;
      if (version === reportVersion) submitted = data;
    } catch (error) {
      if (version === reportVersion) submitted = {sha256: digest, error: error instanceof SyntaxError ? "Invalid report JSON." : error.message};
    }
    refreshCompared();
  }

  function exportFinding() {
    const published = recorded.get(current.id);
    const local = submitted?.rows?.get(current.id);
    const finding = {
      schema: "QUORVANE_FINANCIAL_FINDING_V1", source: "local_review_export",
      baseline: report.baseline, matrix_sha256: report.matrix_sha256, challenge_id: current.id,
      fixture: {path: current.fixture, sha256: current.sha256},
      reference: {path: current.reference, sha256: artifacts[current.reference].sha256},
      command: current.command, expected: current.expected,
      packaged_observation: published.observed,
      submitted_report: submitted ? {
        sha256: submitted.sha256, status: submitted.error ? "COMPARISON_UNAVAILABLE" : local ? "CASE_PRESENT" : "CASE_ABSENT"
      } : null,
      submitted_comparison: local ? {
        source: "UNAUTHENTICATED_REPORT", outcome: states.includes(local.outcome) ? local.outcome : "UNRECOGNIZED",
        reason_matches_expectation: local.reason === current.expected.reason,
        report_sha256: submitted.sha256, self_reported_provenance: submitted.provenance,
        observed_phase: report.cases.some(row => row.observed.phase === local.phase) ? local.phase : "UNRECOGNIZED",
        complete_observation_matches_package: differences(local, published.observed).length === 0,
        difference_paths: differences(local, published.observed),
        submitted_runner_status: submitted.runner,
        outcome_and_reason_match_expected: matchesExpected(local, current.expected)
      } : null,
      reviewer_note: el("note").value.trim(),
      ...Object.fromEntries(boundaries.map(key => [key, report[key]]))
    };
    const url = URL.createObjectURL(new Blob([JSON.stringify(finding, null, 2) + "\n"], {type: "application/json"}));
    const link = document.createElement("a");
    link.href = url;
    link.download = "quorvane-financial-finding-" + current.id + ".json";
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
    put("export-state", "Local JSON download requested.");
  }

  el("family").replaceChildren(...Object.keys(families).filter(k => cases.some(row => familyOf(row) === k))
    .map(k => new Option(k + " · " + families[k], k)));
  el("family").addEventListener("change", () => showGroup(el("family").value));
  el("case").addEventListener("change", showCase);
  for (const [id, step] of [["prev", -1], ["next", 1]]) {
    el(id).addEventListener("click", () => {
      el("case").value = group[group.indexOf(current) + step].id;
      showCase();
    });
  }
  el("hash").addEventListener("click", checkHash);
  el("copy-command").addEventListener("click", async () => {
    const row = current;
    try {
      await navigator.clipboard.writeText(el("command").textContent);
      if (row === current) put("copy-result", "Command copied.");
    } catch {
      if (row === current) put("copy-result", "Clipboard unavailable. Select and copy the command above.");
    }
  });
  el("import-report").addEventListener("change", importFile);
  el("export").addEventListener("click", exportFinding);
  const requested = cases.find(row => "#" + row.id === location.hash);
  showGroup(requested ? familyOf(requested) : "A", requested?.id);
})();
