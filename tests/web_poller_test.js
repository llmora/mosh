const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const script = fs.readFileSync(process.argv[2], "utf8");
const timers = [];
const requests = [];
let current;
let toastRegion;
let clickHandler;
const requirementsDialog = { showModal() { this.open = true; }, close() { this.open = false; } };
const alert = {
  textContent: "Wait for the current stage to finish before changing test setup.",
  remove() { this.removed = true; },
  append(element) { this.dismiss = element; },
};

function section() {
  const logs = {
    open: true,
    dataset: { logsLoaded: "true" },
    addEventListener() {},
    querySelector() { return null; },
  };
  const element = {
    id: "testing-status",
    isConnected: true,
    dataset: { statusUrl: "/testing/status", pollUrl: "/testing/status", pollMs: "2000" },
    querySelector(selector) { return selector === "[data-live-logs]" ? logs : null; },
    set outerHTML(_) {
      this.isConnected = false;
      current = section();
    },
  };
  return element;
}

current = section();
const original = current;
const context = {
  URL,
  document: {
    addEventListener(name, callback) { if (name === "click") clickHandler = callback; },
    body: { append(element) { toastRegion = element; } },
    createElement(tag) {
      return {
        tag,
        append(element) { (this.children ||= []).push(element); },
        setAttribute() {},
        addEventListener(_, callback) { this.onClick = callback; },
      };
    },
    getElementById(id) { return id === "testing-status" ? current : id === "toast-region" ? toastRegion : id === "test-requirements-0" ? requirementsDialog : null; },
    querySelectorAll(selector) {
      return selector === "[data-poll-url]" ? [original] : selector === '.error[role="alert"]' ? [alert] : [];
    },
  },
  window: {
    location: { href: "http://127.0.0.1:8765/" },
    setTimeout(callback) { timers.push(callback); },
  },
  async fetch(url) {
    requests.push(String(url));
    return { ok: true, async json() { return { html: "<section></section>", poll: true }; } };
  },
};

(async () => {
  vm.runInNewContext(script, context);
  assert.equal(toastRegion.id, "toast-region");
  assert.equal(toastRegion.children[0], alert);
  assert.equal(alert.dismiss.textContent, "×");
  assert.equal(timers.length, 1);
  await context.refreshSection(original); // Opening logs replaces the section before its scheduled poll.
  assert.equal(original.isConnected, false);
  await timers.shift()();
  assert.equal(requests.length, 2);
  assert.ok(requests.every((url) => url.includes("view=logs")));
  assert.equal(timers.length, 1); // Polling continues on the replacement section.

  context.showToasts({ querySelectorAll() { return [alert]; } });
  assert.equal(toastRegion.children.length, 1); // Repeated polling does not duplicate the alert.
  alert.dismiss.onClick();
  assert.equal(alert.removed, true);

  clickHandler({ target: { closest(selector) {
    return selector === "[data-open-requirements]" ? { dataset: { openRequirements: "test-requirements-0" } } : null;
  } } });
  assert.equal(requirementsDialog.open, true);
  clickHandler({ target: { closest(selector) {
    return selector === "[data-close-requirements]" ? { closest() { return requirementsDialog; } } : null;
  } } });
  assert.equal(requirementsDialog.open, false);
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
