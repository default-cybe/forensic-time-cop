const mftInput = document.getElementById("mft-input");
const evtxInput = document.getElementById("evtx-input");
const linuxcsvInput = document.getElementById("linuxcsv-input");
const logInput = document.getElementById("log-input");
const mftBox = document.getElementById("mft-box");
const evtxBox = document.getElementById("evtx-box");
const linuxcsvBox = document.getElementById("linuxcsv-box");
const logBox = document.getElementById("log-box");
const analyzeBtn = document.getElementById("analyze-btn");
const loading = document.getElementById("loading");
const results = document.getElementById("results");
const cleanBanner = document.getElementById("clean-banner");

let analysisData = null;
let chart = null;
let currentOS = "windows";

// OS toggle
document.querySelectorAll(".os-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".os-btn").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    currentOS = btn.dataset.os;

    document.getElementById("panel-windows").style.display =
      currentOS === "windows" ? "" : "none";
    document.getElementById("panel-linux").style.display =
      currentOS === "linux" ? "" : "none";
  });
});

// File selection display, Windows
mftInput.addEventListener("change", () => {
  const name = mftInput.files[0]?.name;
  if (name) {
    mftBox.querySelector(".file-name").textContent = name;
    mftBox.classList.add("has-file");
  }
});

evtxInput.addEventListener("change", () => {
  const count = evtxInput.files.length;
  if (count) {
    evtxBox.querySelector(".file-name").textContent = `${count} file(s) selected`;
    evtxBox.classList.add("has-file");
  }
});

// File selection display, Linux
linuxcsvInput.addEventListener("change", () => {
  const name = linuxcsvInput.files[0]?.name;
  if (name) {
    linuxcsvBox.querySelector(".file-name").textContent = name;
    linuxcsvBox.classList.add("has-file");
  }
});

logInput.addEventListener("change", () => {
  const count = logInput.files.length;
  if (count) {
    logBox.querySelector(".file-name").textContent = `${count} file(s) selected`;
    logBox.classList.add("has-file");
  }
});

// Drag and drop
[mftBox, evtxBox, linuxcsvBox, logBox].forEach((box) => {
  box.addEventListener("dragover", (e) => {
    e.preventDefault();
    box.classList.add("dragover");
  });
  box.addEventListener("dragleave", () => box.classList.remove("dragover"));
  box.addEventListener("drop", (e) => {
    e.preventDefault();
    box.classList.remove("dragover");
    const input = box.querySelector("input[type=file]");
    input.files = e.dataTransfer.files;
    input.dispatchEvent(new Event("change"));
  });
});

// Tab switching
document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach((c) => c.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById(`tab-${tab.dataset.tab}`).classList.add("active");
  });
});

// Run analysis
analyzeBtn.addEventListener("click", async () => {
  const formData = new FormData();
  formData.append("os_mode", currentOS);

  if (currentOS === "windows") {
    if (!mftInput.files.length) {
      alert("Upload MFT CSV first");
      return;
    }
    formData.append("mft_csv", mftInput.files[0]);
    for (const f of evtxInput.files) {
      formData.append("evtx_files", f);
    }
  } else {
    if (!linuxcsvInput.files.length) {
      alert("Upload Linux filesystem CSV first");
      return;
    }
    formData.append("linux_csv", linuxcsvInput.files[0]);
    for (const f of logInput.files) {
      formData.append("log_files", f);
    }
  }

  const fullscan = document.getElementById("fullscan").checked;
  formData.append("fullscan", fullscan);

  analyzeBtn.disabled = true;
  loading.classList.add("active");
  results.classList.remove("active");
  cleanBanner.classList.remove("active");

  try {
    const res = await fetch("/analyze", { method: "POST", body: formData });
    const data = await res.json();

    if (data.error) {
      alert("Error: " + data.error);
      return;
    }

    analysisData = data;

    if (data.status === "clean") {
      cleanBanner.classList.add("active");
    } else {
      renderResults(data);
      results.classList.add("active");
    }
  } catch (err) {
    alert("Request failed: " + err.message);
  } finally {
    analyzeBtn.disabled = false;
    loading.classList.remove("active");
  }
});

function renderResults(data) {
  const osMode = data.os_mode || currentOS;

  document.getElementById("count-high").textContent = data.summary.high;
  document.getElementById("count-medium").textContent = data.summary.medium;
  document.getElementById("count-low").textContent = data.summary.low;
  document.getElementById("count-total").textContent = data.summary.total;

  // Update column headers based on OS
  if (osMode === "linux") {
    document.getElementById("ts-col1").textContent = "Modify Time";
    document.getElementById("ts-col2").textContent = "Change Time";
  } else {
    document.getElementById("ts-col1").textContent = "SI Timestamp";
    document.getElementById("ts-col2").textContent = "FN Timestamp";
  }

  renderChart(data.findings);
  renderSimplifiedTable(data.findings, osMode);
  renderDetailedTable(data.findings);
  renderVisualizations(data.findings, osMode);
}

function renderChart(findings) {
  const ctx = document.getElementById("score-chart").getContext("2d");
  const top20 = findings.slice(0, 20);
  const labels = top20.map((f) => {
    const name = f.file.replace(/\\/g, "/").split("/").pop();
    return name.length > 20 ? name.slice(0, 18) + "..." : name;
  });
  const scores = top20.map((f) => f.total_score);
  const colors = top20.map((f) => {
    if (f.severity === "HIGH") return "#f85149";
    if (f.severity === "MEDIUM") return "#d29922";
    return "#e3b341";
  });

  if (chart) chart.destroy();

  chart = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [{
        label: "Suspicion Score",
        data: scores,
        backgroundColor: colors,
        borderRadius: 4,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: "#484f58", font: { size: 10, family: "Inter" } }, grid: { display: false } },
        y: { ticks: { color: "#484f58", font: { family: "Inter" } }, grid: { color: "#161b22" } },
      },
    },
  });
}

// Parse timestamps from reason strings
function parseTimestamps(reasons, osMode) {
  let ts1 = "-";
  let ts2 = "-";

  for (const r of reasons) {
    if (osMode === "linux") {
      // Modify time (...) is ... earlier than change time (...)
      const mtimeMatch = r.match(/Modify time \(([^)]+)\)/);
      const ctimeMatch = r.match(/change time \(([^)]+)\)/);
      if (mtimeMatch && ts1 === "-") ts1 = formatTs(mtimeMatch[1]);
      if (ctimeMatch && ts2 === "-") ts2 = formatTs(ctimeMatch[1]);

      // Birth time (...) differs from change time (...)
      const birthMatch = r.match(/Birth time \(([^)]+)\)/);
      const ctime2Match = r.match(/change time \(([^)]+)\)/);
      if (birthMatch && ts1 === "-") ts1 = formatTs(birthMatch[1]);
      if (ctime2Match && ts2 === "-") ts2 = formatTs(ctime2Match[1]);
    } else {
      // SI timestamp (...) is earlier than FN timestamp (...)
      const siMatch = r.match(/SI timestamp \(([^)]+)\)/);
      const fnMatch = r.match(/FN timestamp \(([^)]+)\)/);
      if (siMatch) ts1 = formatTs(siMatch[1]);
      if (fnMatch) ts2 = formatTs(fnMatch[1]);

      // Modified time (...) is earlier than birth time (...)
      const modMatch = r.match(/Modified time \(([^)]+)\)/);
      const birthMatch = r.match(/birth time \(([^)]+)\)/);
      if (modMatch && ts1 === "-") ts1 = formatTs(modMatch[1]);
      if (birthMatch && ts2 === "-") ts2 = formatTs(birthMatch[1]);

      // Log clearing / clock events
      const logMatch = r.match(/cleared at ([^\s]+)/);
      if (logMatch && ts1 === "-") ts1 = formatTs(logMatch[1]);

      // File created during clock manipulation
      const clockMatch = r.match(/File created at ([^\s]+)/);
      if (clockMatch && ts1 === "-") ts1 = formatTs(clockMatch[1]);
    }
  }

  return { ts1, ts2 };
}

function formatTs(ts) {
  if (!ts) return "-";
  return ts.replace(/\.\d+/, "").replace(/\+00:00$/, "").trim();
}

function splitPath(fullPath) {
  const normalized = fullPath.replace(/\\/g, "/");
  const lastSlash = normalized.lastIndexOf("/");
  if (lastSlash === -1) return { name: fullPath, dir: "" };
  return {
    name: normalized.slice(lastSlash + 1),
    dir: normalized.slice(0, lastSlash),
  };
}

function shortenRule(ruleName, osMode) {
  if (osMode === "linux") {
    return ruleName
      .replace("Modify Time < Change Time (Linux)", "mtime\u00a0<\u00a0ctime")
      .replace("Zeroed Nanoseconds (Linux)", "Zero\u00a0ns")
      .replace("Birthtime Anomaly (Linux)", "Birth\u00a0Gap")
      .replace("Touch Command Detected (Linux)", "Touch\u00a0Cmd")
      .replace("Timestamp Syscall Detected (Linux)", "utime\u00a0Syscall")
      .replace("Clock Change Detected (Linux)", "Clock\u00a0Change")
      .replace("Log File Tampering (Linux)", "Log\u00a0Tamper")
      .replace("Clock Jump in Logs (Linux)", "Clock\u00a0Jump");
  }
  return ruleName
    .replace("SI < FN Timestamp Mismatch", "SI\u2009<\u2009FN")
    .replace("Zeroed Nanoseconds", "Zero\u00a0ns")
    .replace("Birthtime vs Mtime Gap", "Birth\u00a0Gap")
    .replace("Log Clearing Detected", "Log\u00a0Clear")
    .replace("System Clock Jump Detected", "Clock\u00a0Jump")
    .replace("Event Log Record Sequence Gap", "Record\u00a0Gap")
    .replace("System Time Change (Event ID 4616)", "Time\u00a0Change")
    .replace("File Created During Clock Manipulation", "Clock\u00a0File");
}

function renderSimplifiedTable(findings, osMode) {
  const tbody = document.getElementById("simplified-body");
  tbody.innerHTML = "";

  findings.forEach((f) => {
    const { name, dir } = splitPath(f.file);
    const { ts1, ts2 } = parseTimestamps(f.reasons, osMode);
    const badgeClass = f.severity === "HIGH" ? "badge-high"
      : f.severity === "MEDIUM" ? "badge-medium" : "badge-low";

    const rules = [...new Set(f.rules_triggered)];
    const tagClass = f.severity === "HIGH" ? "tag-high"
      : f.severity === "MEDIUM" ? "tag-medium" : "";

    const rulesHtml = rules.map((r) => {
      const short = shortenRule(r, osMode);
      return `<span class="rule-tag ${tagClass}">${short}</span>`;
    }).join("");

    const ts1Class = ts1 !== "-" && ts2 !== "-" ? "mismatch" : "";

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="name-cell">${escapeHtml(name)}</td>
      <td class="path-cell" title="${escapeHtml(f.file)}">${escapeHtml(dir || "-")}</td>
      <td><span class="badge ${badgeClass}">${f.severity}</span></td>
      <td>${f.total_score}</td>
      <td class="ts-cell ${ts1Class}">${ts1}</td>
      <td class="ts-cell">${ts2}</td>
      <td>${rulesHtml}</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderDetailedTable(findings) {
  const tbody = document.getElementById("findings-body");
  tbody.innerHTML = "";

  findings.forEach((f, i) => {
    const badgeClass = f.severity === "HIGH" ? "badge-high"
      : f.severity === "MEDIUM" ? "badge-medium" : "badge-low";

    const fileName = f.file.replace(/\\/g, "/").split("/").pop();
    const rules = [...new Set(f.rules_triggered)].join(", ");

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><button class="expand-btn" data-idx="${i}">&#9654;</button></td>
      <td title="${escapeHtml(f.file)}">${escapeHtml(fileName)}</td>
      <td><span class="badge ${badgeClass}">${f.severity}</span></td>
      <td>${f.total_score}</td>
      <td class="rules-list">${escapeHtml(rules)}</td>
    `;
    tbody.appendChild(tr);

    const detail = document.createElement("tr");
    detail.className = "detail-row";
    detail.id = `detail-${i}`;
    const reasonsHtml = f.reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join("");
    detail.innerHTML = `<td colspan="5"><ul>${reasonsHtml}</ul></td>`;
    tbody.appendChild(detail);
  });

  tbody.querySelectorAll(".expand-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const idx = btn.dataset.idx;
      const detail = document.getElementById(`detail-${idx}`);
      detail.classList.toggle("open");
      btn.innerHTML = detail.classList.contains("open") ? "&#9660;" : "&#9654;";
    });
  });
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

const plotlyBase = {
  paper_bgcolor: "rgba(0,0,0,0)",
  plot_bgcolor: "rgba(0,0,0,0)",
  font: { family: "Inter, system-ui, sans-serif", color: "#7d8590", size: 11 },
  margin: { t: 8, r: 16, b: 44, l: 48 },
};

const plotlyConfig = { displayModeBar: false, responsive: true };

function renderVisualizations(findings, osMode) {
  const scores = findings.map((f) => f.total_score);

  // 1. Score distribution histogram
  Plotly.newPlot("viz-histogram", [{
    x: scores,
    type: "histogram",
    marker: { color: "rgba(79,195,247,0.6)", line: { color: "rgba(79,195,247,0.9)", width: 1 } },
    xbins: { size: 15 },
    hovertemplate: "Score %{x}: %{y} files<extra></extra>",
  }], {
    ...plotlyBase,
    height: 280,
    xaxis: { title: { text: "Suspicion Score", font: { size: 11 } }, color: "#484f58", gridcolor: "#161b22", zeroline: false },
    yaxis: { title: { text: "File Count", font: { size: 11 } }, color: "#484f58", gridcolor: "#161b22", zeroline: false, dtick: 1 },
    bargap: 0.08,
  }, plotlyConfig);

  // 2. Severity donut, filter out zero-count slices
  const sevMap = { HIGH: "#f85149", MEDIUM: "#d29922", LOW: "#e3b341" };
  const sevLabels = [];
  const sevValues = [];
  const sevColors = [];
  const sevCounts = { HIGH: 0, MEDIUM: 0, LOW: 0 };
  findings.forEach((f) => { sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1; });
  for (const [k, v] of Object.entries(sevCounts)) {
    if (v > 0) {
      sevLabels.push(k);
      sevValues.push(v);
      sevColors.push(sevMap[k]);
    }
  }
  Plotly.newPlot("viz-donut", [{
    labels: sevLabels,
    values: sevValues,
    type: "pie",
    hole: 0.6,
    marker: { colors: sevColors, line: { color: "#0a0e14", width: 3 } },
    textinfo: "label+value",
    textfont: { color: "#f0f6fc", size: 13, family: "Inter" },
    textposition: "inside",
    hovertemplate: "%{label}: %{value} files (%{percent})<extra></extra>",
    sort: false,
    direction: "clockwise",
  }], {
    ...plotlyBase,
    height: 240,
    width: 240,
    margin: { t: 4, r: 4, b: 4, l: 4 },
    showlegend: false,
  }, { ...plotlyConfig, responsive: false });

  // 3. Rule breakdown horizontal bar
  const ruleCounts = {};
  findings.forEach((f) => {
    [...new Set(f.rules_triggered)].forEach((r) => {
      const short = shortenRule(r, osMode);
      ruleCounts[short] = (ruleCounts[short] || 0) + 1;
    });
  });
  const sorted = Object.entries(ruleCounts).sort((a, b) => a[1] - b[1]);
  const barColors = ["#f85149", "#d29922", "#e3b341", "#4fc3f7", "#58a6ff", "#3fb950", "#bc8cff", "#7d8590"];
  Plotly.newPlot("viz-rules", [{
    x: sorted.map((s) => s[1]),
    y: sorted.map((s) => s[0]),
    type: "bar",
    orientation: "h",
    marker: {
      color: sorted.map((_, i) => barColors[i % barColors.length]),
      line: { width: 0 },
    },
    hovertemplate: "%{y}: %{x} files<extra></extra>",
  }], {
    ...plotlyBase,
    height: Math.max(180, sorted.length * 38 + 50),
    margin: { t: 8, r: 16, b: 44, l: 160 },
    xaxis: { title: { text: "Files Affected", font: { size: 11 } }, color: "#484f58", gridcolor: "#161b22", zeroline: false, dtick: 1 },
    yaxis: { color: "#c9d1d9", tickfont: { size: 12 }, automargin: true },
    bargap: 0.2,
  }, plotlyConfig);
}

// Export
document.getElementById("export-btn").addEventListener("click", () => {
  if (!analysisData) return;
  const report = {
    tool: "Forensic Time Cop",
    generated: new Date().toISOString(),
    ...analysisData,
  };
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "timecop_report.json";
  a.click();
  URL.revokeObjectURL(url);
});
