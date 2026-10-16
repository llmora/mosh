const shownToasts = new Set();
const settingsReturnKey = "mosh-settings-return";

if (!window.location.pathname.startsWith("/settings")) {
  try { window.sessionStorage.removeItem(settingsReturnKey); } catch { /* Storage may be disabled. */ }
}

const toolWarning = document.querySelector("[data-tool-warning]");
if (toolWarning) {
  async function pollToolStatus() {
    let interval = 30000;
    try {
      const response = await fetch("/settings/tools/status", { cache: "no-store" });
      if (response.ok) {
        const status = await response.json();
        if (typeof status.warning === "boolean" && typeof status.html === "string") {
          toolWarning.hidden = !status.warning;
          toolWarning.setAttribute("aria-label", status.label);
          toolWarning.setAttribute("title", status.label);
          const settingsLink = toolWarning.closest("a");
          if (settingsLink) settingsLink.href = status.warning ? "/settings#local-tools" : "/settings";
          const section = document.querySelector("[data-tool-status]");
          if (section) section.outerHTML = status.html;
          interval = Math.max(1000, Number(status.interval_ms) || 30000);
        }
      }
    } catch { /* Retry on the next check. */ }
    window.setTimeout(pollToolStatus, interval);
  }
  pollToolStatus();
}

function showToasts(root = document) {
  const alerts = root.querySelectorAll('.error[role="alert"]');
  if (!alerts.length) return;
  let region = document.getElementById("toast-region");
  if (!region) {
    region = document.createElement("div");
    region.id = "toast-region";
    region.className = "toast-region";
    document.body.append(region);
  }
  for (const alert of alerts) {
    const message = alert.textContent.trim();
    alert.remove();
    if (shownToasts.has(message)) continue;
    shownToasts.add(message);
    const dismiss = document.createElement("button");
    dismiss.type = "button";
    dismiss.className = "toast-dismiss";
    dismiss.setAttribute("aria-label", "Dismiss error");
    dismiss.textContent = "×";
    dismiss.addEventListener("click", () => alert.remove());
    alert.append(dismiss);
    region.append(alert);
  }
}

// Refresh live stage sections while keeping the log panel and its scroll position.
async function refreshSection(section) {
  if (!section.isConnected) return;
  if (section.querySelector("dialog[data-stop-confirm][open]")) return;
  const logs = section.querySelector("[data-live-logs]");
  const logsOpen = Boolean(logs?.open);
  const scrollArea = logs?.querySelector("[data-preserve-scroll]");
  const scrollPosition = scrollArea?.scrollTop;
  const followEnd = !scrollArea || scrollArea.scrollHeight - scrollArea.clientHeight - scrollArea.scrollTop < 30;
  const url = new URL(section.dataset.statusUrl, window.location.href);
  if (logsOpen) url.searchParams.set("view", "logs");

  try {
    const response = await fetch(url, { cache: "no-store" });
    if (!response.ok || !section.isConnected) return;
    const update = await response.json();
    if (typeof update.html !== "string" || typeof update.poll !== "boolean") return;
    if (section.querySelector("dialog[data-stop-confirm][open]")) return;

    const stillOpen = Boolean(logs?.open);
    const id = section.id;
    section.outerHTML = update.html;
    const next = document.getElementById(id);
    if (!next) return;
    showToasts(next);
    const nextLogs = next.querySelector("[data-live-logs]");
    if (nextLogs) {
      if (stillOpen && !logsOpen) nextLogs.dataset.logsLoaded = "loading";
      nextLogs.open = stillOpen;
    }
    bindLogPanel(next);
    const nextScrollArea = nextLogs?.querySelector("[data-preserve-scroll]");
    if (nextScrollArea) {
      nextScrollArea.scrollTop = followEnd ? nextScrollArea.scrollHeight : scrollPosition;
    }
    if (stillOpen && !logsOpen) refreshSection(next);
  } catch {
    // Keep the current section visible. The next poll or toggle can retry.
  }
}

function bindLogPanel(section) {
  const logs = section.querySelector("[data-live-logs]");
  if (!logs) return;
  logs.addEventListener("toggle", () => {
    if (!section.isConnected) return;
    if (!logs.open) {
      logs.dataset.logsLoaded = "false";
    } else if (logs.dataset.logsLoaded === "false") {
      logs.dataset.logsLoaded = "loading";
      refreshSection(section);
    }
  });
}

function pollSection(section) {
  const id = section.id;
  const interval = Number(section.dataset.pollMs) || 2000;
  window.setTimeout(async () => {
    const current = document.getElementById(id);
    if (!current?.dataset.pollUrl) return;
    await refreshSection(current);
    const next = document.getElementById(id);
    if (next?.dataset.pollUrl) pollSection(next);
  }, interval);
}

document.querySelectorAll("[data-status-url]").forEach(bindLogPanel);
document.querySelectorAll("[data-poll-url]").forEach(pollSection);
showToasts();

document.addEventListener("click", (event) => {
  const settingsOpen = event.target?.closest?.("[data-settings-link]");
  if (settingsOpen && !window.location.pathname.startsWith("/settings")) {
    try {
      window.sessionStorage.setItem(settingsReturnKey, window.location.pathname + window.location.search + window.location.hash);
    } catch { /* Closing Settings falls back to Assessments. */ }
  }
  const settingsClose = event.target?.closest?.("[data-close-settings]");
  if (settingsClose) {
    let destination = "/";
    try {
      const saved = window.sessionStorage.getItem(settingsReturnKey);
      window.sessionStorage.removeItem(settingsReturnKey);
      if (saved) {
        const url = new URL(saved, window.location.origin);
        if (url.origin === window.location.origin && !url.pathname.startsWith("/settings")) {
          destination = url.pathname + url.search + url.hash;
        }
      }
    } catch { /* The link still closes Settings to Assessments. */ }
    if (destination !== "/") {
      event.preventDefault();
      window.location.assign(destination);
    }
    return;
  }
  for (const menu of document.querySelectorAll(".markdown-download-menu[open]")) {
    if (!menu.contains(event.target)) menu.open = false;
  }
  const opener = event.target?.closest?.("[data-open-requirements]");
  if (opener) document.getElementById(opener.dataset.openRequirements)?.showModal();
  const closer = event.target?.closest?.("[data-close-requirements]");
  if (closer) closer.closest("dialog")?.close();
  const stopOpener = event.target?.closest?.("[data-open-stop]");
  if (stopOpener) document.getElementById(stopOpener.dataset.openStop)?.showModal();
  const stopCloser = event.target?.closest?.("[data-close-stop]");
  if (stopCloser) stopCloser.closest("dialog")?.close();
});
document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") return;
  for (const menu of document.querySelectorAll(".markdown-download-menu[open]")) {
    menu.open = false;
    menu.querySelector("summary")?.focus();
  }
});
document.querySelectorAll("dialog[data-auto-open]").forEach((dialog) => dialog.showModal());
