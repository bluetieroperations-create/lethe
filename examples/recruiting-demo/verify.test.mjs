/* Tests for verify.html.
 *
 *     node verify.test.mjs                 # offline, against the page's own fixture
 *     node verify.test.mjs cert-and-key.json   # also against a freshly minted certificate
 *
 * The load-bearing test is the first one. verify.html re-implements Lethe's
 * canonical JSON — Python's json.dumps(sort_keys=True, separators=(",", ":"))
 * under the default ensure_ascii=True — because JSON.stringify does not escape
 * non-ASCII, and the claim text contains an em dash. Get that wrong and the
 * page reports INVALID for every genuine certificate. Nothing else in this
 * repository compares the two implementations, and they cannot be compared by
 * inspection: the fixture's payload_hash was computed by Python, so a JS
 * canonicalisation that hashes to it agrees byte for byte.
 *
 * No dependencies, deliberately: the page has none either.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createHash } from "node:crypto";

const here = dirname(fileURLToPath(import.meta.url));

function loadPage() {
  const html = readFileSync(join(here, "verify.html"), "utf8");
  const m = html.match(/<script>\n([\s\S]*?)\n<\/script>/);
  if (!m) throw new Error("no <script> block found in verify.html");
  const els = {};
  const stub = () => ({ value: "", className: "", textContent: "", innerHTML: "",
                        hidden: false, addEventListener() {} });
  const document = { getElementById: id => (els[id] ||= stub()) };
  const fn = new Function("document", m[1] + "\n;return { verify, canonical, render, EXAMPLE };");
  return { ...fn(document), els };
}

const page = loadPage();
let failed = 0;
function check(name, ok, detail = "") {
  if (!ok) failed++;
  console.log(`${ok ? "ok  " : "FAIL"}  ${name}${detail ? "  — " + detail : ""}`);
}

const sha256 = bytes => createHash("sha256").update(bytes).digest("hex");
const clone = o => JSON.parse(JSON.stringify(o));
const allPassed = r => !r.fatal &&
  ["pinning", "key_id", "hash", "signature"].every(k => r.results[k] && r.results[k].ok);

/* ---- the cross-language contract ---------------------------------------- */

async function agreesWithPython(label, cert, publicKey) {
  const bytes = Buffer.from(page.canonical(cert.payload), "utf8");
  check(`${label}: canonical bytes hash to Python's payload_hash`,
        sha256(bytes) === cert.payload_hash,
        `js=${sha256(bytes).slice(0, 12)}… recorded=${String(cert.payload_hash).slice(0, 12)}…`);
  check(`${label}: non-ASCII is escaped rather than emitted literally`,
        bytes.includes("\\u"), "ensure_ascii=True behaviour");
  check(`${label}: certificate verifies`,
        allPassed(await page.verify(JSON.stringify(cert), publicKey)));
}

await agreesWithPython("fixture", page.EXAMPLE.cert, page.EXAMPLE.public_key);

const extra = process.argv[2];
if (extra) {
  const f = JSON.parse(readFileSync(extra, "utf8"));
  await agreesWithPython("freshly minted", f.cert, f.public_key);
}

/* ---- rejection paths ----------------------------------------------------- */

const { cert, public_key: PUB } = page.EXAMPLE;

{
  const c = clone(cert); c.payload.records_deleted = 9999;
  const r = await page.verify(JSON.stringify(c), PUB);
  check("an altered payload fails at the hash check", r.results.hash?.ok === false);
}
{
  const r = await page.verify(JSON.stringify(cert), Buffer.alloc(32, 7).toString("base64"));
  check("a different pinned key fails at the pinning check", r.results.pinning?.ok === false);
}
{
  const c = clone(cert); c.payload.key_id = "ed25519:" + "0".repeat(32);
  const r = await page.verify(JSON.stringify(c), PUB);
  check("a key_id that disagrees with the key is rejected", r.results.key_id?.ok === false);
}
{
  const c = clone(cert);
  const sig = Buffer.from(c.signature, "base64"); sig[0] ^= 0xff;
  c.signature = sig.toString("base64");
  const r = await page.verify(JSON.stringify(c), PUB);
  check("a corrupt signature is rejected", r.results.signature?.ok === false);
}
{
  const r = await page.verify(JSON.stringify(cert), "   ");
  check("an empty pinned key is refused, not waved through", !!r.fatal);
}

/* ---- malformed input must be reported, never thrown ---------------------- */

for (const [label, mutate] of [
  ["payload_hash is not a string", c => { c.payload_hash = { a: 1 }; }],
  ["signature is not a string",    c => { c.signature = 12345; }],
  ["public_key is not a string",   c => { c.public_key = null; }],
  ["payload is not an object",     c => { c.payload = "nope"; }],
  ["public_key is the wrong size", c => { c.public_key = Buffer.alloc(16, 3).toString("base64"); }],
]) {
  const c = clone(cert); mutate(c);
  let threw = false, out = null;
  try { out = await page.verify(JSON.stringify(c), PUB); } catch { threw = true; }
  check(`${label}: reported, not thrown`, !threw && !allPassed(out), out?.fatal || "");
}

/* ---- a certificate is untrusted input, and is rendered as such ------------ */

// On the failure path the note text is rendered, so tampering is enough.
{
  const c = clone(cert);
  c.payload.key_id = '<img src=x onerror="boom()">';
  page.render(await page.verify(JSON.stringify(c), PUB));
  check("payload.key_id cannot inject markup",
        !page.els.checks.innerHTML.includes("<img src=x"));
}

// The facts panel renders only for a certificate that fully verifies, so
// tampering can never reach it — the hash check fires first. Reaching it
// requires a *validly signed* certificate carrying markup, which is the real
// threat: an operator whose key you pinned is still not someone whose payload
// should be able to run script in your browser. So sign one and try.
{
  const { generateKeyPairSync, sign: edSign } = await import("node:crypto");
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  const pub = raw.toString("base64");
  const keyId = "ed25519:" + sha256(raw).slice(0, 32);

  for (const field of ["audit_head", "schema", "issued_at"]) {
    const payload = { ...clone(cert.payload), key_id: keyId };
    payload[field] = '<img src=x onerror="boom()">';
    const bytes = Buffer.from(page.canonical(payload), "utf8");
    const signed = {
      payload,
      payload_hash: sha256(bytes),
      signature: edSign(null, bytes, privateKey).toString("base64"),
      public_key: pub,
    };
    const out = await page.verify(JSON.stringify(signed), pub);
    check(`a signed payload.${field} still verifies`, allPassed(out), out.fatal || "");
    page.render(out);
    check(`signed payload.${field} cannot inject markup`,
          !(page.els.checks.innerHTML + page.els.facts.innerHTML).includes("<img src=x"));
  }
}

console.log(failed ? `\n${failed} failing` : "\nall good");
process.exit(failed ? 1 : 0);
