import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { dirname, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { loadPolicy } from "@open-policy-agent/opa-wasm";

export const OPA_VERSION = "1.21.0";
export const ENTRYPOINT = "iam/guard/deny";
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DEFAULT_OUTPUT_DIR = resolve(ROOT, "build/wasm");
const POLICY_PATH = resolve(ROOT, "policy/iam_guard.rego");
const VECTORS_PATH = resolve(ROOT, "tests/parity-vectors.json");

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function invalidResult(code, message) {
  return { allowed: false, error: code, violations: [message] };
}

function canonicalMessages(value) {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    return null;
  }
  if (new Set(value).size !== value.length) {
    return null;
  }
  return [...value].sort();
}

export function decodeWasmResult(raw) {
  // The SDK's success shape is exactly [{ result: string[] }].  Undefined,
  // empty, missing, or differently-shaped results are not an allow signal.
  if (!Array.isArray(raw) || raw.length !== 1 || !isRecord(raw[0])) {
    return invalidResult("wasm-result-malformed", "Wasm evaluation returned no decision result");
  }
  const keys = Object.keys(raw[0]);
  if (keys.length !== 1 || keys[0] !== "result") {
    return invalidResult("wasm-result-malformed", "Wasm evaluation returned an invalid result object");
  }
  const messages = canonicalMessages(raw[0].result);
  if (messages === null) {
    return invalidResult("wasm-result-malformed", "Wasm result was not a unique string array");
  }
  return { allowed: messages.length === 0, violations: messages };
}

export function evaluateWasm(policy, input) {
  try {
    return decodeWasmResult(policy.evaluate(input, ENTRYPOINT));
  } catch {
    return invalidResult("wasm-evaluation-error", "Wasm evaluation failed");
  }
}

function decodeNativeOutput(output) {
  if (typeof output !== "string" || output.trim() === "") {
    return invalidResult("native-result-malformed", "OPA returned no decision result");
  }
  let parsed;
  try {
    parsed = JSON.parse(output);
  } catch {
    return invalidResult("native-result-malformed", "OPA result was not valid JSON");
  }
  const messages = canonicalMessages(parsed);
  if (messages === null) {
    return invalidResult("native-result-malformed", "OPA result was not a unique string array");
  }
  return { allowed: messages.length === 0, violations: messages };
}

function commandOutput(command, args, input = undefined) {
  const result = spawnSync(command, args, {
    input,
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
  if (result.error) {
    throw new Error(`${command} could not be executed: ${result.error.message}`);
  }
  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout || "").trim();
    throw new Error(`${command} exited ${result.status}${detail ? `: ${detail}` : ""}`);
  }
  return result.stdout;
}

export function resolveOpa() {
  const command = process.env.OPA_BIN || "opa";
  const output = commandOutput(command, ["version"]);
  const match = output.match(/^Version:\s*(\S+)/m);
  const version = match?.[1];
  if (version !== OPA_VERSION) {
    throw new Error(`OPA ${OPA_VERSION} is required; '${command}' reports '${version || "unknown"}'`);
  }
  return command;
}

function evaluateNative(opa, input) {
  const output = commandOutput(
    opa,
    [
      "eval",
      "--format",
      "raw",
      "--data",
      POLICY_PATH,
      "--stdin-input",
      "data.iam.guard.deny",
    ],
    JSON.stringify(input),
  );
  return decodeNativeOutput(output);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function safeFixturePath(root, relativePath) {
  const candidate = resolve(root, relativePath);
  if (candidate !== root && !candidate.startsWith(`${root}${sep}`)) {
    throw new Error(`fixture path escapes repository: ${relativePath}`);
  }
  return candidate;
}

async function verifyManifest(outputDir) {
  const manifestPath = resolve(outputDir, "manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  if (manifest.opa_version !== OPA_VERSION) {
    throw new Error(`manifest OPA version is ${manifest.opa_version}, expected ${OPA_VERSION}`);
  }
  if (manifest.entrypoint !== ENTRYPOINT) {
    throw new Error(`manifest entrypoint is ${manifest.entrypoint}, expected ${ENTRYPOINT}`);
  }
  if (manifest.source !== "policy/iam_guard.rego") {
    throw new Error(`manifest source is ${manifest.source}, expected policy/iam_guard.rego`);
  }

  const source = await readFile(POLICY_PATH);
  if (sha256(source) !== manifest.source_sha256) {
    throw new Error("production Rego source does not match the Wasm manifest");
  }

  const expected = new Map();
  for (const artifact of Object.values(manifest.artifacts || {})) {
    if (!isRecord(artifact) || typeof artifact.file !== "string" || typeof artifact.sha256 !== "string") {
      throw new Error("manifest contains an invalid artifact entry");
    }
    const path = safeFixturePath(outputDir, artifact.file);
    const digest = sha256(await readFile(path));
    if (digest !== artifact.sha256) {
      throw new Error(`hash mismatch for ${artifact.file}`);
    }
    expected.set(artifact.file, artifact.sha256);
  }
  if (!expected.has("policy.wasm") || !expected.has("policy-bundle.tar.gz")) {
    throw new Error("manifest must include both policy.wasm and policy-bundle.tar.gz");
  }

  const checksums = await readFile(resolve(outputDir, "checksums.txt"), "utf8");
  for (const [file, digest] of expected) {
    if (!checksums.includes(`${digest}  ${file}\n`)) {
      throw new Error(`checksums.txt does not cover ${file}`);
    }
  }
}

async function loadVectors() {
  const document = JSON.parse(await readFile(VECTORS_PATH, "utf8"));
  if (!Array.isArray(document.vectors) || document.vectors.length === 0) {
    throw new Error("parity vector file contains no vectors");
  }
  const ids = new Set();
  for (const vector of document.vectors) {
    if (!isRecord(vector) || typeof vector.id !== "string" || ids.has(vector.id)) {
      throw new Error("parity vectors must have unique string ids");
    }
    ids.add(vector.id);
  }
  return document.vectors;
}

function assertExpected(expected, actual, id) {
  const canonicalExpected = canonicalMessages(expected);
  if (canonicalExpected === null) {
    throw new Error(`${id}: expected is not a unique string array`);
  }
  if (JSON.stringify(actual.violations) !== JSON.stringify(canonicalExpected)) {
    throw new Error(
      `${id}: expected ${JSON.stringify(canonicalExpected)}, got ${JSON.stringify(actual.violations)}`,
    );
  }
  if (actual.allowed !== (canonicalExpected.length === 0)) {
    throw new Error(`${id}: allow flag does not match the result set`);
  }
}

function assertFailClosedHelpers() {
  const malformed = [
    undefined,
    null,
    {},
    [],
    [{}],
    [{ result: null }],
    [{ result: {} }],
    [{ result: [1] }],
    [{ result: ["duplicate", "duplicate"] }],
    [{ result: [] }, { result: [] }],
  ];
  for (const value of malformed) {
    const decision = decodeWasmResult(value);
    if (decision.allowed !== false || typeof decision.error !== "string") {
      throw new Error("malformed or undefined Wasm result did not fail closed");
    }
  }
  const thrown = evaluateWasm({ evaluate() { throw new Error("simulated SDK failure"); } }, {});
  if (thrown.allowed !== false || thrown.error !== "wasm-evaluation-error") {
    throw new Error("Wasm evaluation exception did not fail closed");
  }
}

export async function main() {
  const outputDir = resolve(ROOT, process.env.WASM_OUTPUT_DIR || DEFAULT_OUTPUT_DIR);
  await verifyManifest(outputDir);
  const opa = resolveOpa();
  const policy = await loadPolicy(await readFile(resolve(outputDir, "policy.wasm")));

  if (!policy || typeof policy.evaluate !== "function") {
    throw new Error("opa-wasm did not return an evaluable policy");
  }
  if (!isRecord(policy.entrypoints) || !Object.prototype.hasOwnProperty.call(policy.entrypoints, ENTRYPOINT)) {
    throw new Error(`Wasm module does not expose ${ENTRYPOINT}`);
  }

  assertFailClosedHelpers();
  const vectors = await loadVectors();
  for (const vector of vectors) {
    const input = vector.fixture
      ? JSON.parse(await readFile(safeFixturePath(ROOT, vector.fixture), "utf8"))
      : vector.input;
    if (input === undefined) {
      throw new Error(`${vector.id}: vector has neither fixture nor input`);
    }

    // The production Rego messages are produced by its sprintf builtin; do
    // not reimplement them in JavaScript before comparing the two runtimes.
    const wasm = evaluateWasm(policy, input);
    if (wasm.error) {
      throw new Error(`${vector.id}: ${wasm.error}`);
    }
    assertExpected(vector.expected, wasm, vector.id);

    const native = evaluateNative(opa, input);
    if (native.error) {
      throw new Error(`${vector.id}: ${native.error}`);
    }
    if (native.allowed !== wasm.allowed ||
        JSON.stringify(native.violations) !== JSON.stringify(wasm.violations)) {
      throw new Error(
        `${vector.id}: native/Wasm mismatch: ${JSON.stringify(native)} vs ${JSON.stringify(wasm)}`,
      );
    }
  }

  const relativeOutput = relative(ROOT, outputDir) || ".";
  console.log(
    `Wasm parity: ${vectors.length} vectors matched OPA ${OPA_VERSION} at ${ENTRYPOINT} (${relativeOutput})`,
  );
}

const invokedAsScript = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedAsScript) {
  main().catch((error) => {
    console.error(`verify-wasm: ${error.message}`);
    process.exitCode = 1;
  });
}
