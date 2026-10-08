const shownToasts = new Set();

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
  const opener = event.target?.closest?.("[data-open-requirements]");
  if (opener) document.getElementById(opener.dataset.openRequirements)?.showModal();
  const closer = event.target?.closest?.("[data-close-requirements]");
  if (closer) closer.closest("dialog")?.close();
});
document.querySelectorAll("dialog[data-auto-open]").forEach((dialog) => dialog.showModal());
