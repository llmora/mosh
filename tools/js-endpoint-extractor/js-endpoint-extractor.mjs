#!/usr/bin/env node
import * as acorn from 'acorn';
import fs from 'node:fs/promises';

const args = process.argv.slice(2);
const baseUrl = optionValue('--base-url') || '';
const jsonOutput = args.includes('--json');

function optionValue(name) {
  const index = args.indexOf(name);
  if (index === -1 || index + 1 >= args.length) return '';
  return args[index + 1];
}

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => {
      data += chunk;
    });
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
}

async function readSource(source) {
  if (source.startsWith('http://') || source.startsWith('https://')) {
    const response = await fetch(source);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status} ${response.statusText}`);
    }
    return response.text();
  }
  if (source.startsWith('file://')) {
    return fs.readFile(new URL(source), 'utf8');
  }
  return fs.readFile(source, 'utf8');
}

function parseJavaScript(source, sourceType = 'module') {
  return acorn.parse(source, {
    ecmaVersion: 'latest',
    sourceType,
    allowHashBang: true,
    allowReturnOutsideFunction: true,
  });
}

function walk(node, visitor, parent = null) {
  if (!node || typeof node !== 'object') return;
  if (typeof node.type === 'string') {
    visitor(node, parent);
  }
  for (const [key, value] of Object.entries(node)) {
    if (key === 'parent') continue;
    if (Array.isArray(value)) {
      for (const item of value) {
        if (item && typeof item.type === 'string') walk(item, visitor, node);
      }
    } else if (value && typeof value.type === 'string') {
      walk(value, visitor, node);
    }
  }
}

function memberName(node) {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'Literal' && typeof node.value === 'string') return node.value;
  if (node.type === 'MemberExpression') {
    const object = memberName(node.object);
    const property = memberName(node.property);
    if (object && property) return `${object}.${property}`;
  }
  return null;
}

function expressionText(node) {
  if (!node) return 'unknown';
  if (node.type === 'Identifier') return node.name;
  const member = memberName(node);
  if (member) return member;
  if (node.type === 'CallExpression') return `${expressionText(node.callee)}()`;
  if (node.type === 'MemberExpression') return memberName(node) || 'member';
  return node.type;
}

function makeValue(value, confidence = 'resolved') {
  return { value, confidence };
}

function mergeConfidence(left, right) {
  return left === 'resolved' && right === 'resolved' ? 'resolved' : 'partial';
}

function evaluate(node, env) {
  if (!node) return null;
  if (node.type === 'Literal') {
    if (typeof node.value === 'string') return makeValue(node.value);
    if (node.value instanceof RegExp) return makeValue(String(node.value));
    return null;
  }
  if (node.type === 'Identifier') {
    return env.get(node.name) || null;
  }
  if (node.type === 'MemberExpression') {
    const name = memberName(node);
    return name ? env.get(name) || null : null;
  }
  if (node.type === 'LogicalExpression' && node.operator === '||') {
    return evaluate(node.left, env) || evaluate(node.right, env);
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const left = evaluate(node.left, env);
    const right = evaluate(node.right, env);
    if (!left || !right) return null;
    return makeValue(`${left.value}${right.value}`, mergeConfidence(left.confidence, right.confidence));
  }
  if (node.type === 'TemplateLiteral') {
    let value = '';
    let confidence = 'resolved';
    for (let index = 0; index < node.quasis.length; index += 1) {
      value += node.quasis[index].value.cooked || '';
      if (index < node.expressions.length) {
        const evaluated = evaluate(node.expressions[index], env);
        if (evaluated) {
          value += evaluated.value;
          confidence = mergeConfidence(confidence, evaluated.confidence);
        } else {
          value += `{${expressionText(node.expressions[index])}}`;
          confidence = 'partial';
        }
      }
    }
    return makeValue(value, confidence);
  }
  if (node.type === 'CallExpression') {
    const calleeName = memberName(node.callee);
    const calleeProperty = node.callee?.type === 'MemberExpression' ? memberName(node.callee.property) : null;
    if (calleeName === 'encodeURIComponent' && node.arguments.length) {
      const evaluated = evaluate(node.arguments[0], env);
      if (evaluated) return evaluated;
      return makeValue(`{${expressionText(node.arguments[0])}}`, 'partial');
    }
    if (calleeProperty === 'replace' && node.arguments.length >= 2) {
      const base = evaluate(node.callee.object, env);
      const replacement = evaluate(node.arguments[1], env);
      if (!base || !replacement) return base;
      const pattern = node.arguments[0];
      if (pattern.type === 'Literal' && pattern.regex?.pattern === '\\/$') {
        return makeValue(base.value.replace(/\/$/, replacement.value), mergeConfidence(base.confidence, replacement.confidence));
      }
      return base;
    }
  }
  return null;
}

function assignValue(name, node, env) {
  const value = evaluate(node, env);
  if (name && value) env.set(name, value);
}

function collectEnvironment(ast, env) {
  let changed = true;
  let iterations = 0;
  while (changed && iterations < 5) {
    changed = false;
    iterations += 1;
    walk(ast, (node) => {
      if (node.type === 'VariableDeclarator' && node.id?.type === 'Identifier' && node.init) {
        const before = env.get(node.id.name)?.value;
        assignValue(node.id.name, node.init, env);
        if (env.get(node.id.name)?.value !== before) changed = true;
      }
      if (node.type === 'AssignmentExpression') {
        const name = memberName(node.left);
        const before = name ? env.get(name)?.value : undefined;
        assignValue(name, node.right, env);
        if (name && env.get(name)?.value !== before) changed = true;
      }
    });
  }
}

function endpointKind(node) {
  const calleeName = memberName(node.callee);
  if (calleeName === 'fetch') return { kind: 'fetch', argument: node.arguments[0] };
  if (calleeName?.startsWith('axios.')) return { kind: 'axios', argument: node.arguments[0] };
  if (calleeName?.endsWith('.open') && node.arguments.length >= 2) {
    return { kind: 'xhr', argument: node.arguments[1] };
  }
  return null;
}

function findEndpoints(ast, env, source) {
  const endpoints = [];
  walk(ast, (node) => {
    if (node.type === 'CallExpression') {
      const target = endpointKind(node);
      if (!target?.argument) return;
      const evaluated = evaluate(target.argument, env);
      if (!evaluated) return;
      endpoints.push({
        source,
        endpoint: evaluated.value,
        kind: target.kind,
        confidence: evaluated.confidence,
        evidence: expressionText(target.argument),
      });
    }
    if (node.type === 'NewExpression' && memberName(node.callee) === 'URL' && node.arguments.length) {
      const evaluated = evaluate(node.arguments[0], env);
      if (!evaluated) return;
      endpoints.push({
        source,
        endpoint: evaluated.value,
        kind: 'new_url',
        confidence: evaluated.confidence,
        evidence: expressionText(node.arguments[0]),
      });
    }
  });
  return endpoints;
}

async function collectBaseEnvironment(base) {
  const env = new Map();
  if (!base) return env;
  try {
    const source = await readSource(base);
    const inlineScripts = [...source.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)].map((match) => match[1]);
    for (const script of inlineScripts) {
      if (!script.trim()) continue;
      const ast = parseJavaScript(script, 'script');
      collectEnvironment(ast, env);
    }
  } catch {
    return env;
  }
  return env;
}

function groupBySource(findings) {
  const grouped = new Map();
  for (const finding of findings) {
    const existing = grouped.get(finding.source) || [];
    existing.push(finding);
    grouped.set(finding.source, existing);
  }
  return [...grouped.entries()].map(([source, sourceFindings]) => ({
    source,
    endpoints: [...new Set(sourceFindings.map((finding) => finding.endpoint))],
    findings: sourceFindings,
  }));
}

const input = await readStdin();
const sources = input.split(/\s+/).map((value) => value.trim()).filter(Boolean);
const baseEnv = await collectBaseEnvironment(baseUrl);
const allFindings = [];

for (const source of sources) {
  try {
    const text = await readSource(source);
    const ast = parseJavaScript(text);
    const env = new Map(baseEnv);
    collectEnvironment(ast, env);
    allFindings.push(...findEndpoints(ast, env, source));
  } catch (error) {
    allFindings.push({
      source,
      endpoint: '',
      kind: 'error',
      confidence: 'error',
      evidence: error.message || String(error),
    });
  }
}

const output = groupBySource(allFindings.filter((finding) => finding.endpoint));
if (jsonOutput) {
  process.stdout.write(`${JSON.stringify(output)}\n`);
} else {
  for (const item of output) {
    process.stdout.write(`${item.source}\n`);
    for (const endpoint of item.endpoints) {
      process.stdout.write(`  ${endpoint}\n`);
    }
  }
}
