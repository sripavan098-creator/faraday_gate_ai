/*
 * Faraday Gate proof-report viewer.
 *
 * Renders the JSON emitted by `faraday prove latest --format json`.
 *
 * Everything is built with DOM nodes and textContent. No proof-report field is
 * ever written with innerHTML: the report is produced from repository content,
 * so a file path or a limitation string could contain markup, and injecting it
 * would turn a documentation page into an XSS vector.
 */
(function () {
  "use strict";

  var input = document.getElementById("report-input");
  var output = document.getElementById("report-output");
  var status = document.getElementById("report-status");

  var SAMPLE = {
    session_id: "session_demo00000000",
    started_at: "2026-09-27T13:56:09.957213+00:00",
    tool: "wrap",
    mode: "strict-local",
    policy_version: "default-v1",
    status: "blocked",
    files_scanned: 0,
    prompt_tokens_scanned: 12,
    findings_total: 2,
    secrets_blocked: 1,
    injections_blocked: 1,
    command_guard_blocks: 0,
    path_blocks: 0,
    redactions_total: 0,
    sensitive_redactions: 0,
    model_backends: ["none recorded"],
    egress_method: "not-recorded",
    egress_observed_connections: [],
    egress_label: "Egress status not recorded",
    egress_details: "No egress observation was recorded for this session.",
    audit_chain_valid: true,
    audit_message: "9 audit events verified",
    audit_head: "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0",
    output_hash: null,
    limitations: [
      "Detection is defense-in-depth and not a guarantee of perfect secret or injection detection.",
      "The audit chain is local-only and is not remotely anchored.",
    ],
  };

  var COUNT_FIELDS = [
    ["findings_total", "Findings"],
    ["secrets_blocked", "Secrets blocked"],
    ["injections_blocked", "Injections blocked"],
    ["command_guard_blocks", "Command guard blocks"],
    ["path_blocks", "Path blocks"],
    ["redactions_total", "Redactions"],
    ["sensitive_redactions", "Sensitive redactions"],
    ["files_scanned", "Files scanned"],
    ["prompt_tokens_scanned", "Prompt tokens scanned"],
  ];

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function section(title) {
    var wrap = el("section", "report-section");
    wrap.appendChild(el("h3", null, title));
    return wrap;
  }

  function fieldList(pairs) {
    var dl = el("dl", "report-fields");
    pairs.forEach(function (pair) {
      var label = pair[0];
      var value = pair[1];
      if (value === undefined || value === null || value === "") return;
      dl.appendChild(el("dt", null, label));
      dl.appendChild(el("dd", null, value));
    });
    return dl;
  }

  function verdict(report) {
    var box = el("div", "verdict");
    var valid = report.audit_chain_valid === true;
    box.classList.add(valid ? "verdict-good" : "verdict-bad");
    box.appendChild(el("span", "verdict-label", valid ? "AUDIT VALID" : "AUDIT INVALID"));
    box.appendChild(
      el("span", "verdict-detail", report.audit_message || "no audit message provided")
    );
    return box;
  }

  function render(report) {
    output.textContent = "";

    if (typeof report !== "object" || report === null || Array.isArray(report)) {
      status.textContent = "Expected a JSON object. Paste the output of `faraday prove latest --format json`.";
      return;
    }

    output.appendChild(verdict(report));

    var summary = section("Session");
    summary.appendChild(
      fieldList([
        ["Session ID", report.session_id],
        ["Started", report.started_at],
        ["Tool", report.tool],
        ["Mode", report.mode],
        ["Policy version", report.policy_version],
        ["Status", report.status],
      ])
    );
    output.appendChild(summary);

    var counts = section("Findings and actions");
    var grid = el("div", "count-grid");
    COUNT_FIELDS.forEach(function (pair) {
      var key = pair[0];
      var label = pair[1];
      var value = report[key];
      if (value === undefined || value === null) return;
      var cell = el("div", "count-cell");
      cell.appendChild(el("span", "count-value", value));
      cell.appendChild(el("span", "count-label", label));
      grid.appendChild(cell);
    });
    counts.appendChild(grid);
    output.appendChild(counts);

    var egress = section("Egress");
    egress.appendChild(
      fieldList([
        ["Label", report.egress_label],
        ["Method", report.egress_method],
        ["Details", report.egress_details],
      ])
    );
    var conns = report.egress_observed_connections;
    if (Array.isArray(conns) && conns.length > 0) {
      var list = el("ul", "report-list");
      conns.forEach(function (conn) {
        list.appendChild(el("li", null, typeof conn === "string" ? conn : JSON.stringify(conn)));
      });
      egress.appendChild(list);
    } else {
      egress.appendChild(
        el("p", "note", "No remote endpoints were observed. This never means none occurred.")
      );
    }
    output.appendChild(egress);

    var integrity = section("Integrity");
    integrity.appendChild(
      fieldList([
        ["Audit head", report.audit_head],
        ["Output hash", report.output_hash || "not recorded"],
        ["Model backends", Array.isArray(report.model_backends) ? report.model_backends.join(", ") : report.model_backends],
      ])
    );
    output.appendChild(integrity);

    var limits = report.limitations;
    if (Array.isArray(limits) && limits.length > 0) {
      var limitSection = section("Limitations");
      var ul = el("ul", "report-list limits");
      limits.forEach(function (item) {
        ul.appendChild(el("li", null, item));
      });
      limitSection.appendChild(ul);
      output.appendChild(limitSection);
    }

    status.textContent = "Report rendered locally. Nothing was uploaded.";
  }

  function parseAndRender(text) {
    if (!text.trim()) {
      status.textContent = "Paste a proof report first.";
      output.textContent = "";
      return;
    }
    var parsed;
    try {
      parsed = JSON.parse(text);
    } catch (err) {
      status.textContent = "Invalid JSON: " + err.message;
      output.textContent = "";
      return;
    }
    render(parsed);
  }

  document.getElementById("render-report").addEventListener("click", function () {
    parseAndRender(input.value);
  });

  document.getElementById("load-sample").addEventListener("click", function () {
    input.value = JSON.stringify(SAMPLE, null, 2);
    render(SAMPLE);
  });

  document.getElementById("clear-report").addEventListener("click", function () {
    input.value = "";
    output.textContent = "";
    status.textContent = "";
  });
})();
