(() => {
  "use strict";

  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || "";
  const api = async (url, options = {}) => {
    const headers = { "Content-Type": "application/json", "X-CSRFToken": csrfToken, ...(options.headers || {}) };
    const response = await fetch(url, { ...options, headers, credentials: "same-origin" });
    let payload = {};
    try { payload = await response.json(); } catch (_) { payload = {}; }
    if (!response.ok) throw new Error(payload.error || `Request failed (${response.status}).`);
    return payload;
  };
  const feedback = (element, message, kind = "success") => {
    if (!element) return;
    element.hidden = false;
    element.className = `feedback-box${kind === "error" ? " feedback-error" : kind === "info" ? " feedback-info" : ""}`;
    element.textContent = message;
  };
  const setBusy = (button, busy, label) => {
    if (!button) return;
    if (busy) {
      button.dataset.originalText = button.textContent;
      button.disabled = true;
      button.textContent = label;
    } else {
      button.disabled = false;
      if (button.dataset.originalText) button.textContent = button.dataset.originalText;
    }
  };
  const textElement = (tag, text, className) => {
    const element = document.createElement(tag);
    if (text !== undefined) element.textContent = text;
    if (className) element.className = className;
    return element;
  };

  const menuToggle = document.getElementById("menuToggle");
  const sidebar = document.getElementById("sidebar");
  const sidebarBackdrop = document.getElementById("sidebarBackdrop");
  const setSidebarOpen = open => {
    if (!sidebar || !menuToggle || !sidebarBackdrop) return;
    sidebar.classList.toggle("open", open);
    sidebarBackdrop.hidden = !open;
    document.body.classList.toggle("navigation-open", open);
    menuToggle.setAttribute("aria-expanded", String(open));
  };
  menuToggle?.addEventListener("click", () => {
    setSidebarOpen(!sidebar?.classList.contains("open"));
  });
  sidebarBackdrop?.addEventListener("click", () => setSidebarOpen(false));
  sidebar?.querySelectorAll("a").forEach(link => {
    link.addEventListener("click", () => setSidebarOpen(false));
  });
  document.addEventListener("keydown", event => {
    if (event.key === "Escape" && sidebar?.classList.contains("open")) {
      setSidebarOpen(false);
      menuToggle?.focus();
    }
  });

  const threatRoot = document.querySelector("[data-threat-model]");
  if (threatRoot) {
    const nodes = [...threatRoot.querySelectorAll("[data-component]")];
    const threatSelect = document.getElementById("threatSelect");
    const controlSelect = document.getElementById("controlSelect");
    const description = document.getElementById("componentDescription");
    const output = document.getElementById("threatFeedback");
    let catalog = [];
    let selectedComponent = "browser";
    const populateThreats = () => {
      const component = catalog.find(item => item.id === selectedComponent);
      if (!component) return;
      description.textContent = component.description;
      threatSelect.replaceChildren();
      component.threats.forEach(threat => {
        const option = document.createElement("option");
        option.value = threat.id;
        option.textContent = threat.label;
        threatSelect.append(option);
      });
      const threat = component.threats[0];
      controlSelect.replaceChildren();
      (threat?.controls || []).forEach(control => {
        const option = document.createElement("option");
        option.value = control.id;
        option.textContent = control.label;
        controlSelect.append(option);
      });
      if (output) output.hidden = true;
    };
    const refreshControls = () => {
      const component = catalog.find(item => item.id === selectedComponent);
      const threat = component?.threats.find(item => item.id === threatSelect.value);
      controlSelect.replaceChildren();
      (threat?.controls || []).forEach(control => {
        const option = document.createElement("option");
        option.value = control.id;
        option.textContent = control.label;
        controlSelect.append(option);
      });
    };
    api("/api/threat-model/data").then(data => {
      catalog = data.components;
      populateThreats();
    }).catch(error => feedback(output, error.message, "error"));
    nodes.forEach(node => node.addEventListener("click", () => {
      nodes.forEach(item => item.classList.toggle("selected", item === node));
      selectedComponent = node.dataset.component;
      populateThreats();
    }));
    threatSelect.addEventListener("change", refreshControls);
    document.getElementById("threatForm")?.addEventListener("submit", async event => {
      event.preventDefault();
      const button = event.currentTarget.querySelector("button[type=submit]");
      setBusy(button, true, "Evaluating…");
      try {
        const result = await api("/api/threat-model/evaluate", {
          method: "POST",
          body: JSON.stringify({ component: selectedComponent, threat: threatSelect.value, control: controlSelect.value }),
        });
        feedback(output, result.explanation, result.passed ? "success" : "error");
      } catch (error) {
        feedback(output, error.message, "error");
      } finally { setBusy(button, false); }
    });
  }

  document.querySelectorAll("[data-challenge]").forEach(card => {
    const output = card.querySelector(".challenge-feedback");
    card.querySelectorAll("[data-answer]").forEach(button => button.addEventListener("click", async () => {
      card.querySelectorAll("[data-answer]").forEach(choice => { choice.disabled = true; });
      try {
        const result = await api(`/api/challenges/${encodeURIComponent(card.dataset.challenge)}/attempt`, {
          method: "POST", body: JSON.stringify({ answer: button.dataset.answer }),
        });
        feedback(output, `${result.passed ? "Correct. " : "Not quite. "}${result.explanation}`, result.passed ? "success" : "error");
        card.querySelectorAll("[data-answer]").forEach(choice => {
          choice.disabled = false;
          choice.classList.toggle("selected-choice", choice === button);
        });
      } catch (error) {
        feedback(output, error.message, "error");
        card.querySelectorAll("[data-answer]").forEach(choice => { choice.disabled = false; });
      }
    }));
  });

  const aiButton = document.getElementById("analyzeCode");
  if (aiButton) {
    const textarea = document.getElementById("aiCode");
    const count = document.getElementById("charCount");
    const errorPanel = document.getElementById("aiError");
    const resultRoot = document.getElementById("aiResult");
    const configStatus = document.getElementById("aiConfigStatus");
    let editor = null;
    const currentCode = () => editor ? editor.getValue() : textarea.value;
    const updateCount = () => { count.textContent = `${currentCode().length.toLocaleString()} / 12,000`; };
    textarea.addEventListener("input", updateCount);
    api("/api/ai/status").then(status => {
      const providerName = status.provider === "gemini" ? "Gemini" : "OpenAI";
      const keyName = status.provider === "gemini" ? "GEMINI_API_KEY" : "OPENAI_API_KEY";
      configStatus.textContent = status.configured
        ? `${providerName} API key loaded by this server · Model: ${status.model}`
        : `${providerName} key not loaded. Configure ${keyName} in .env and restart the server.`;
      configStatus.classList.toggle("configured", status.configured);
    }).catch(error => {
      configStatus.textContent = error.message;
    });
    if (window.require && document.getElementById("monacoHost")) {
      try {
        window.require.config({ paths: { vs: "https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.52.2/min/vs" } });
        window.require(["vs/editor/editor.main"], () => {
          try {
            editor = window.monaco.editor.create(document.getElementById("monacoHost"), {
              value: textarea.value,
              language: "python",
              theme: "vs",
              minimap: { enabled: false },
              automaticLayout: true,
              fontSize: 12,
              scrollBeyondLastLine: false,
              wordWrap: "on",
              ariaLabel: "Code for AI security analysis",
            });
            editor.onDidChangeModelContent(updateCount);
            textarea.classList.add("monaco-ready");
            updateCount();
          } catch (_) { editor = null; }
        }, () => {});
      } catch (_) { /* The accessible textarea remains available when Monaco is offline. */ }
    }
    aiButton.addEventListener("click", async () => {
      const code = currentCode();
      errorPanel.hidden = true;
      if (!code.trim()) {
        feedback(errorPanel, "Paste code to analyze first.", "error");
        textarea.focus();
        return;
      }
      setBusy(aiButton, true, "Analyzing…");
      try {
        const response = await api("/api/ai/analyze", { method: "POST", body: JSON.stringify({ code }) });
        renderAIResult(resultRoot, response.result);
      } catch (error) {
        feedback(errorPanel, error.message, "error");
      } finally { setBusy(aiButton, false); }
    });
  }

  function renderAIResult(root, result) {
    root.replaceChildren();
    const summary = document.createElement("div");
    summary.className = "risk-summary";
    const heading = document.createElement("div");
    heading.className = "risk-summary-head";
    heading.append(textElement("span", "OVERALL RISK"));
    heading.append(textElement("span", result.risk.toUpperCase(), `risk-tag risk-${result.risk}`));
    summary.append(heading, textElement("p", result.summary));
    root.append(summary);
    root.append(textElement("h3", "Findings", "result-section-title"));
    if (result.findings.length) {
      result.findings.forEach(item => {
        const card = document.createElement("article");
        card.className = "finding-card";
        const title = document.createElement("h4");
        title.append(textElement("span", item.title), textElement("span", item.severity.toUpperCase(), `risk-tag risk-${item.severity}`));
        card.append(title, textElement("p", item.explanation), textElement("p", `Remediation: ${item.remediation}`));
        root.append(card);
      });
    } else {
      root.append(textElement("p", "No specific findings were returned. This does not guarantee the code is secure.", "muted"));
    }
    if (result.secure_example) {
      root.append(textElement("h3", "Secure example", "result-section-title"));
      const example = document.createElement("pre");
      example.textContent = result.secure_example;
      root.append(example);
    }
    root.append(textElement("h3", "Recommended tests", "result-section-title"));
    const list = document.createElement("ul");
    list.className = "recommendation-list";
    result.test_recommendations.forEach(item => list.append(textElement("li", item)));
    root.append(list, textElement("p", result.disclaimer, "ai-disclaimer"));
  }

  const arena = document.querySelector("[data-arena]");
  if (arena) {
    const scenarioButtons = [...arena.querySelectorAll("[data-scenario]")];
    const description = document.getElementById("scenarioDescription");
    const compare = document.getElementById("simulationCompare");
    const vulnerableButton = document.getElementById("runVulnerable");
    const defendedButton = document.getElementById("runDefended");
    let catalog = [];
    let currentScenario = "sql-injection";
    let vulnerableResult = null;
    defendedButton.disabled = true;
    api("/api/simulations/catalog").then(data => { catalog = data.scenarios; updateDescription(); })
      .catch(error => { compare.textContent = error.message; });
    function updateDescription() {
      const item = catalog.find(scenario => scenario.id === currentScenario);
      if (item) description.textContent = item.description;
    }
    function renderSimulations(defendedResult = null) {
      compare.replaceChildren();
      if (!vulnerableResult && !defendedResult) {
        compare.append(textElement("div", "Your simulation results will appear here. Run both versions to compare.", "simulation-empty"));
        return;
      }
      if (vulnerableResult) compare.append(simulationCard(vulnerableResult, "VULNERABLE VERSION", false));
      if (defendedResult) compare.append(simulationCard(defendedResult, "DEFENDED VERSION", true));
    }
    scenarioButtons.forEach(button => button.addEventListener("click", () => {
      scenarioButtons.forEach(item => item.classList.toggle("selected", item === button));
      currentScenario = button.dataset.scenario;
      vulnerableResult = null;
      defendedButton.disabled = true;
      renderSimulations();
      updateDescription();
    }));
    vulnerableButton.addEventListener("click", () => run(false));
    defendedButton.addEventListener("click", () => run(true));
    async function run(defended) {
      const button = defended ? defendedButton : vulnerableButton;
      setBusy(button, true, "Running simulation…");
      try {
        const result = await api("/api/simulations/run", {
          method: "POST", body: JSON.stringify({ scenario: currentScenario, defended }),
        });
        if (defended) renderSimulations(result);
        else {
          vulnerableResult = result;
          defendedButton.disabled = false;
          renderSimulations();
        }
      } catch (error) {
        compare.replaceChildren(textElement("div", error.message, "simulation-empty"));
      } finally { setBusy(button, false); }
    }
    function simulationCard(result, label, defended) {
      const card = document.createElement("div");
      card.className = `simulation-result ${defended ? "result-defended" : "result-exposed"}`;
      card.append(textElement("span", label));
      card.append(textElement("h3", defended ? (result.blocked ? "Defense held" : "Review defense") : "Vulnerable behavior simulated"));
      card.append(textElement("p", result.result));
      card.append(textElement("small", `Evidence: ${result.evidence}`));
      return card;
    }
  }

  const testButton = document.getElementById("runSecurityTests");
  if (testButton) {
    const resultRoot = document.getElementById("testResults");
    const output = document.getElementById("testFeedback");
    testButton.addEventListener("click", async () => {
      output.hidden = true;
      setBusy(testButton, true, "Executing checks…");
      resultRoot.replaceChildren(textElement("div", "Executing security checks…", "simulation-empty"));
      try {
        const data = await api("/api/tests/run", { method: "POST", body: "{}" });
        renderTestResults(resultRoot, data.results);
        feedback(output, `${data.results.filter(item => item.status === "PASS").length} of ${data.results.length} checks passed. Deployment status: ${data.deployment.status}.`, data.results.every(item => item.status === "PASS") ? "success" : "info");
      } catch (error) {
        resultRoot.replaceChildren();
        feedback(output, error.message, "error");
      } finally { setBusy(testButton, false); }
    });
    api("/api/tests/latest").then(data => {
      if (data.results.length) renderTestResults(resultRoot, data.results);
    }).catch(error => feedback(output, error.message, "error"));
  }

  function renderTestResults(root, results) {
    root.replaceChildren();
    results.forEach(item => {
      const row = document.createElement("div");
      row.className = `test-row status-${item.status.toLowerCase()}`;
      row.append(textElement("span", item.status === "PASS" ? "✓" : item.status === "FAIL" ? "!" : "—", "test-status"));
      const content = document.createElement("span");
      content.append(textElement("b", item.test_name.replaceAll("_", " ").replace(/\b\w/g, char => char.toUpperCase())));
      content.append(textElement("small", item.details));
      row.append(content, textElement("span", item.status, `result-tag ${item.status.toLowerCase()}`));
      root.append(row);
    });
  }

  const gateStatus = document.getElementById("gateStatus");
  if (gateStatus) {
    const refreshButton = document.getElementById("refreshGate");
    const gateTests = document.getElementById("gateTests");
    const reviewItems = document.getElementById("reviewItems");
    const gateReason = document.getElementById("gateReason");
    const reviewForm = document.getElementById("reviewItemForm");
    const reviewFeedback = document.getElementById("reviewFeedback");
    const loadGate = async () => {
      const data = await api("/api/deployment");
      const decision = data.deployment;
      gateStatus.className = `gate-status status-${decision.status === "READY" ? "ready" : decision.status === "BLOCKED" ? "blocked" : "review"}`;
      gateStatus.querySelector(".gate-indicator").textContent = decision.status === "READY" ? "✓" : decision.status === "BLOCKED" ? "!" : "…";
      gateStatus.querySelector("h2").textContent = decision.status;
      gateReason.textContent = decision.reason;
      gateTests.replaceChildren();
      decision.required_tests.forEach(item => {
        const row = document.createElement("div");
        row.className = "gate-test-row";
        row.append(textElement("b", item.label));
        if (item.critical) row.append(textElement("small", "CRITICAL", "critical-label"));
        row.append(textElement("span", item.status, `result-tag ${item.status === "PASS" ? "pass" : item.status === "FAIL" ? "fail" : "not-run"}`));
        gateTests.append(row);
      });
      renderReviewItems(decision.open_review_items);
    };
    const renderReviewItems = items => {
      reviewItems.replaceChildren();
      if (!items.length) {
        reviewItems.append(textElement("div", "No open review items.", "empty-inline"));
        return;
      }
      items.forEach(item => {
        const row = document.createElement("div");
        row.className = "review-item";
        row.append(textElement("span", item.title), textElement("span", item.severity.toUpperCase(), `risk-tag severity-${item.severity}`));
        const button = textElement("button", "Resolve", "button button-outline");
        button.type = "button";
        button.addEventListener("click", async () => {
          button.disabled = true;
          try {
            await api(`/api/review-items/${item.id}/resolve`, { method: "POST", body: "{}" });
            await loadGate();
            feedback(reviewFeedback, "Review item marked resolved.", "success");
          } catch (error) { feedback(reviewFeedback, error.message, "error"); button.disabled = false; }
        });
        row.append(button);
        reviewItems.append(row);
      });
    };
    refreshButton.addEventListener("click", async () => {
      setBusy(refreshButton, true, "Refreshing…");
      try { await loadGate(); }
      catch (error) { feedback(reviewFeedback, error.message, "error"); }
      finally { setBusy(refreshButton, false); }
    });
    reviewForm.addEventListener("submit", async event => {
      event.preventDefault();
      const title = document.getElementById("reviewTitle");
      const severity = document.getElementById("reviewSeverity");
      const button = reviewForm.querySelector("button");
      setBusy(button, true, "Adding…");
      try {
        await api("/api/review-items", { method: "POST", body: JSON.stringify({ title: title.value, severity: severity.value }) });
        title.value = "";
        await loadGate();
        feedback(reviewFeedback, "Review item added. Resolve it before requesting a READY decision.", "info");
      } catch (error) { feedback(reviewFeedback, error.message, "error"); }
      finally { setBusy(button, false); }
    });
    loadGate().catch(error => {
      gateStatus.querySelector("h2").textContent = "Unavailable";
      feedback(reviewFeedback, error.message, "error");
    });
  }
})();
