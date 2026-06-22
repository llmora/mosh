#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const args = parseArgs(process.argv.slice(2));
const input = await readStdin();
const sources = parseInput(input, args.baseUrl);
const results = [];

for (const source of sources) {
  results.push(await inspectJavaScriptSource(source));
}

if (args.json) {
  process.stdout.write(`${JSON.stringify(results)}\n`);
} else {
  for (const result of results) {
    const mapCount = result.source_maps.length;
    process.stdout.write(`${result.source}: ${mapCount} source map${mapCount === 1 ? "" : "s"}\n`);
  }
}

function parseArgs(argv) {
  const parsed = { baseUrl: "", json: false };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--base-url") {
      parsed.baseUrl = argv[index + 1] || "";
      index += 1;
    } else if (arg === "--json") {
      parsed.json = true;
    } else if (arg === "--help" || arg === "-h") {
      process.stdout.write("Usage: source-map-discovery [--base-url URL] [--json]\n");
      process.exit(0);
    }
  }
  return parsed;
}

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      data += chunk;
    });
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", reject);
  });
}

function parseInput(input, baseUrl) {
  const trimmed = input.trim();
  if (!trimmed) {
    return [];
  }
  let candidates;
  if (trimmed.startsWith("[")) {
    const parsed = JSON.parse(trimmed);
    candidates = parsed
      .map((item) => {
        if (typeof item === "string") {
          return item;
        }
        if (item && typeof item.source === "string") {
          return item.source;
        }
        return "";
      })
      .filter(Boolean);
  } else {
    candidates = trimmed.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  }

  return [...new Set(candidates.map((candidate) => normalizeSource(candidate, baseUrl)))];
}

function normalizeSource(source, baseUrl) {
  if (/^https?:\/\//i.test(source) || source.startsWith("file://")) {
    return source;
  }
  if (baseUrl && (/^\//.test(source) || !path.isAbsolute(source))) {
    try {
      return new URL(source, baseUrl).toString();
    } catch {
      return source;
    }
  }
  return source;
}

async function inspectJavaScriptSource(source) {
  const result = {
    source,
    checked: [],
    source_maps: [],
  };

  let body;
  try {
    body = await readText(source);
  } catch (error) {
    result.error = error.message;
    return result;
  }

  const references = sourceMapReferences(source, body);
  for (const candidate of references) {
    const checked = { url: candidate.url, reason: candidate.reason, found: false };
    result.checked.push(checked);

    try {
      const sourceMap = await readSourceMap(candidate.url);
      checked.found = true;
      result.source_maps.push(sourceMapSummary(candidate.url, sourceMap));
    } catch (error) {
      checked.error = error.message;
    }
  }

  return result;
}

function sourceMapReferences(source, body) {
  const references = [];
  const seen = new Set();
  const regex = /(?:\/\/[#@]\s*sourceMappingURL=([^\s]+)|\/\*[#@]\s*sourceMappingURL=([^*]+?)\s*\*\/)/g;
  let match;
  while ((match = regex.exec(body)) !== null) {
    const raw = (match[1] || match[2] || "").trim();
    if (!raw) {
      continue;
    }
    const resolved = resolveReference(raw, source);
    if (resolved && !seen.has(resolved)) {
      seen.add(resolved);
      references.push({ url: resolved, reason: "sourceMappingURL" });
    }
  }

  const sibling = siblingSourceMapReference(source);
  if (!seen.has(sibling)) {
    references.push({ url: sibling, reason: "sibling" });
  }
  return references;
}

function siblingSourceMapReference(source) {
  try {
    if (/^https?:\/\//i.test(source) || source.startsWith("file://")) {
      const sourceUrl = new URL(source);
      sourceUrl.pathname = `${sourceUrl.pathname}.map`;
      sourceUrl.search = "";
      sourceUrl.hash = "";
      return sourceUrl.toString();
    }
  } catch {
    return `${source}.map`;
  }
  return `${source}.map`;
}

function resolveReference(reference, source) {
  if (reference.startsWith("data:")) {
    return reference;
  }
  try {
    if (/^https?:\/\//i.test(source) || source.startsWith("file://")) {
      return new URL(reference, source).toString();
    }
    return fileURLToPath(new URL(reference, pathToFileURL(source)));
  } catch {
    return "";
  }
}

async function readSourceMap(source) {
  if (source.startsWith("data:")) {
    return parseDataSourceMap(source);
  }
  const text = await readText(source);
  const parsed = JSON.parse(text);
  if (!parsed || typeof parsed !== "object" || parsed.version === undefined) {
    throw new Error("not a source map JSON object");
  }
  if (!Array.isArray(parsed.sources) && !Array.isArray(parsed.sourcesContent)) {
    throw new Error("source map has no sources");
  }
  return parsed;
}

function parseDataSourceMap(dataUrl) {
  const match = /^data:([^,]*),(.*)$/s.exec(dataUrl);
  if (!match) {
    throw new Error("invalid data source map URL");
  }
  const metadata = match[1] || "";
  const payload = match[2] || "";
  const decoded = metadata.includes(";base64")
    ? Buffer.from(payload, "base64").toString("utf8")
    : decodeURIComponent(payload);
  return JSON.parse(decoded);
}

function sourceMapSummary(url, sourceMap) {
  const sources = Array.isArray(sourceMap.sources) ? sourceMap.sources.filter((item) => typeof item === "string") : [];
  const sourcesContent = Array.isArray(sourceMap.sourcesContent) ? sourceMap.sourcesContent : [];
  return {
    url: url.startsWith("data:") ? "inline-source-map" : url,
    valid: true,
    source_root: typeof sourceMap.sourceRoot === "string" ? sourceMap.sourceRoot : "",
    sources,
    sources_count: sources.length,
    sources_with_content: sourcesContent.filter((item) => typeof item === "string" && item.length > 0).length,
  };
}

async function readText(source) {
  if (/^https?:\/\//i.test(source)) {
    const response = await fetch(source, { redirect: "follow" });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    return await response.text();
  }
  if (source.startsWith("file://")) {
    return await readFile(fileURLToPath(source), "utf8");
  }
  return await readFile(source, "utf8");
}
