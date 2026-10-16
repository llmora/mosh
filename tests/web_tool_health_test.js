const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const script = fs.readFileSync(process.argv[2], "utf8");
const timers = [];
const storage = new Map();
const requests = [];
const link = { href: "/settings", closest(selector) { return selector === "a" ? this : null; } };
const warning = {
  hidden: true,
  closest(selector) { return link.closest(selector); },
  setAttribute(name, value) { this[name] = value; },
};
const section = { outerHTML: "" };
let clickHandler;
let currentStatus = { warning: true, label: "Local tools need attention", html: "<section>Missing</section>", interval_ms: 2000 };
const context = {
  URL,
  document: {
    querySelector(selector) {
      if (selector === "[data-tool-warning]") return warning;
      if (selector === "[data-tool-status]") return section;
      return null;
    },
    querySelectorAll() { return []; },
    getElementById() { return null; },
    addEventListener(name, callback) { if (name === "click") clickHandler = callback; },
  },
  window: {
    location: {
      href: "http://127.0.0.1:8765/assessments/eng_1/discovery",
      origin: "http://127.0.0.1:8765",
      pathname: "/assessments/eng_1/discovery",
      search: "", hash: "",
    },
    sessionStorage: {
      getItem(key) { return storage.get(key) ?? null; },
      setItem(key, value) { storage.set(key, value); },
      removeItem(key) { storage.delete(key); },
    },
    setTimeout(callback, delay) { timers.push({ callback, delay }); },
  },
  async fetch(url) {
    requests.push(url);
    return { ok: true, async json() { return currentStatus; } };
  },
};

(async () => {
  vm.runInNewContext(script, context);
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(requests, ["/settings/tools/status"]);
  assert.equal(warning.hidden, false);
  assert.equal(link.href, "/settings#local-tools");
  assert.equal(section.outerHTML, "<section>Missing</section>");
  assert.equal(timers[0].delay, 2000);

  clickHandler({ target: { closest(selector) { return selector === "[data-settings-link]" ? link : null; } } });
  assert.equal(storage.get("mosh-settings-return"), "/assessments/eng_1/discovery");

  currentStatus = { warning: false, label: "Local tools ready", html: "<section>Ready</section>", interval_ms: 30000 };
  await timers.shift().callback();
  assert.equal(warning.hidden, true);
  assert.equal(link.href, "/settings");
  assert.equal(section.outerHTML, "<section>Ready</section>");
  assert.equal(timers[0].delay, 30000);
})().catch((error) => { console.error(error); process.exitCode = 1; });
