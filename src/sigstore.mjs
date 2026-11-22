import crypto from 'node:crypto';
import { CT_LOGS, FULCIO_CHAINS, REKOR_LOGS } from './sigstore-trust-root.mjs';

// Offline verification of the Sigstore bundle npm serves with build provenance.
// Checked: the DSSE signature against the signing certificate; that certificate's chain
// to a pinned Fulcio root; the certificate's OIDC issuer and source repository; the
// Rekor entry's signed timestamp against the pinned log key; the Merkle inclusion proof
// of the entry up to a checkpoint signed by that log key; that the entry is for this
// envelope and certificate; and that the logged time is inside the certificate's
// validity; and an embedded signed certificate timestamp (SCT) from a pinned
// certificate-transparency log. Not checked: RFC 3161 timestamps,
// consistency between checkpoints (a split view of the log is not detected), and
// trust-root freshness (the root is pinned, not fetched).

const GITHUB_ACTIONS_ISSUER = 'https://token.actions.githubusercontent.com';
const OID_ISSUER_V2 = '1.3.6.1.4.1.57264.1.8';
const OID_SOURCE_REPOSITORY = '1.3.6.1.4.1.57264.1.12';
const OID_SCT_LIST = '1.3.6.1.4.1.11129.2.4.2';
const OID_CT_POISON = '1.3.6.1.4.1.11129.2.4.3';
const MAX_DER_DEPTH = 16;
// npm provenance from 2023 uses bundle format 0.1, which may carry only the log's
// promise. The cutoff is checked against the log-signed time, so relabelling a newer
// bundle as 0.1 and dropping its proof does not pass.
const LEGACY_BUNDLE_WITHOUT_PROOF = 'application/vnd.dev.sigstore.bundle+json;version=0.1';
const LEGACY_BUNDLE_CUTOFF = Date.parse('2024-01-01T00:00:00Z');

function fail(reason) {
  return { verified: false, reason };
}

function readTlv(buffer, offset) {
  if (offset + 2 > buffer.length) throw new Error('der');
  const tag = buffer[offset];
  if ((tag & 0x1f) === 0x1f) throw new Error('der');
  let length = buffer[offset + 1];
  let start = offset + 2;
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count < 1 || count > 4 || start + count > buffer.length) throw new Error('der');
    length = buffer.readUIntBE(start, count);
    start += count;
  }
  if (start + length > buffer.length) throw new Error('der');
  return { tag, start, end: start + length };
}

function children(buffer, node) {
  const out = [];
  for (let offset = node.start; offset < node.end;) {
    const child = readTlv(buffer, offset);
    if (child.end > node.end) throw new Error('der');
    out.push(child);
    offset = child.end;
  }
  return out;
}

function oidText(bytes) {
  const parts = [Math.floor(bytes[0] / 40), bytes[0] % 40];
  let value = 0n;
  for (const byte of bytes.subarray(1)) {
    value = (value << 7n) | BigInt(byte & 0x7f);
    if (!(byte & 0x80)) {
      parts.push(value);
      value = 0n;
    }
  }
  return parts.join('.');
}

// Collects X.509 extensions as OID -> value bytes. Only constructed values are walked,
// so data inside an extension value cannot pose as another extension.
function certificateExtensions(der) {
  const found = new Map();
  const visit = (node, depth) => {
    if (depth > MAX_DER_DEPTH) throw new Error('der');
    if (!(node.tag & 0x20)) return;
    const items = children(der, node);
    const last = items.at(-1);
    if (node.tag === 0x30 && items.length >= 2 && items.length <= 3 && items[0].tag === 0x06 && last.tag === 0x04) {
      const oid = oidText(der.subarray(items[0].start, items[0].end));
      if (found.has(oid)) throw new Error('duplicate extension');
      found.set(oid, der.subarray(last.start, last.end));
      return;
    }
    for (const item of items) visit(item, depth + 1);
  };
  visit(readTlv(der, 0), 0);
  return found;
}

function utf8Extension(extensions, oid) {
  const value = extensions.get(oid);
  if (!value) return null;
  const node = readTlv(value, 0);
  if (node.tag !== 0x0c || node.end !== value.length) return null;
  return value.subarray(node.start, node.end).toString('utf8');
}

function within(validFor, time) {
  const start = Date.parse(validFor?.start);
  const end = validFor?.end ? Date.parse(validFor.end) : Infinity;
  return Number.isFinite(start) && time >= start && time <= end;
}

function certificateValidAt(certificate, time) {
  return time >= Date.parse(certificate.validFrom) && time <= Date.parse(certificate.validTo);
}

// Returns the certificate that issued the leaf when the leaf chains to a pinned root.
function pinnedIssuer(leaf, time, chains) {
  for (const { validFor, certificates } of chains) {
    if (!within(validFor, time) || certificates.length === 0) continue;
    try {
      const chain = [leaf, ...certificates.map((raw) => new crypto.X509Certificate(Buffer.from(raw, 'base64')))];
      const root = chain.at(-1);
      if (chain.every((certificate, index) => {
        const issuer = chain[index + 1] || root;
        return certificateValidAt(certificate, time) && (index === 0 || certificate.ca) &&
          certificate.checkIssued(issuer) && certificate.verify(issuer.publicKey);
      })) return chain[1];
    } catch {
      // Try the next pinned chain.
    }
  }
  return null;
}

function derLength(length) {
  if (length < 0x80) return Buffer.from([length]);
  const bytes = [];
  for (let rest = length; rest > 0; rest = Math.floor(rest / 256)) bytes.unshift(rest % 256);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

const derWrap = (tag, content) => Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);

// Children of a constructed node together with their full encoding.
function rawChildren(buffer, node) {
  const out = [];
  for (let offset = node.start; offset < node.end;) {
    const child = readTlv(buffer, offset);
    if (child.end > node.end) throw new Error('der');
    out.push({ ...child, raw: buffer.subarray(offset, child.end) });
    offset = child.end;
  }
  return out;
}

// The CT log signed the certificate as it was before the SCT list was added (RFC 6962
// section 3.2), so the to-be-signed part is rebuilt without that one extension.
function precertificateTbs(der) {
  const certificate = readTlv(der, 0);
  if (certificate.tag !== 0x30 || certificate.end !== der.length) throw new Error('der');
  const [tbs] = rawChildren(der, certificate);
  if (!tbs || tbs.tag !== 0x30) throw new Error('der');
  const fields = rawChildren(der, tbs);
  const wrapper = fields.at(-1);
  if (!wrapper || wrapper.tag !== 0xa3) throw new Error('der');
  const [list, ...rest] = rawChildren(der, wrapper);
  if (!list || list.tag !== 0x30 || rest.length) throw new Error('der');
  let sctList = null;
  const kept = [];
  for (const extension of rawChildren(der, list)) {
    const parts = rawChildren(der, extension);
    if (extension.tag !== 0x30 || parts.length < 2 || parts[0].tag !== 0x06 || parts.at(-1).tag !== 0x04) throw new Error('der');
    const oid = oidText(der.subarray(parts[0].start, parts[0].end));
    if (oid === OID_CT_POISON) throw new Error('poison');
    if (oid !== OID_SCT_LIST) {
      kept.push(extension.raw);
      continue;
    }
    if (sctList) throw new Error('duplicate extension');
    const value = parts.at(-1);
    const inner = readTlv(der, value.start);
    if (inner.tag !== 0x04 || inner.end !== value.end) throw new Error('der');
    sctList = der.subarray(inner.start, inner.end);
  }
  if (!sctList) return null;
  const extensions = derWrap(0xa3, derWrap(0x30, Buffer.concat(kept)));
  return { sctList, tbs: derWrap(0x30, Buffer.concat([...fields.slice(0, -1).map((field) => field.raw), extensions])) };
}

// At least one embedded SCT must be signed by a pinned CT log over this certificate as
// issued by the pinned issuer. SCTs from logs that are not pinned are ignored.
function sctFromPinnedLog(leafDer, issuer, ctLogs) {
  const precertificate = precertificateTbs(leafDer);
  if (!precertificate || precertificate.tbs.length >= 2 ** 24) return false;
  const { sctList, tbs } = precertificate;
  if (sctList.length < 2 || sctList.readUInt16BE(0) !== sctList.length - 2) return false;
  const issuerKeyHash = crypto.createHash('sha256').update(issuer.publicKey.export({ type: 'spki', format: 'der' })).digest();
  const tbsLength = Buffer.alloc(3);
  tbsLength.writeUIntBE(tbs.length, 0, 3);
  let verified = false;
  for (let offset = 2; offset < sctList.length;) {
    if (offset + 2 > sctList.length) return false;
    const end = offset + 2 + sctList.readUInt16BE(offset);
    if (end > sctList.length) return false;
    const sct = sctList.subarray(offset + 2, end);
    offset = end;
    // version(1) log id(32) timestamp(8) extensions(2+n) hash(1) signature(1) length(2) signature
    if (sct.length < 47 || sct[0] !== 0) continue;
    const extensionsEnd = 43 + sct.readUInt16BE(41);
    if (extensionsEnd + 4 > sct.length || sct[extensionsEnd] !== 4 || sct[extensionsEnd + 1] !== 3 ||
        extensionsEnd + 4 + sct.readUInt16BE(extensionsEnd + 2) !== sct.length) continue;
    const log = ctLogs.find((item) => item.logId === sct.subarray(1, 33).toString('base64'));
    const timestamp = Number(sct.readBigUInt64BE(33));
    if (!log || !within(log.validFor, timestamp)) continue;
    const signed = Buffer.concat([
      Buffer.from([0, 0]), sct.subarray(33, 41), Buffer.from([0, 1]), issuerKeyHash,
      tbsLength, tbs, sct.subarray(41, extensionsEnd)
    ]);
    const key = crypto.createPublicKey({ key: Buffer.from(log.publicKey, 'base64'), format: 'der', type: 'spki' });
    if (crypto.verify('sha256', signed, key, sct.subarray(extensionsEnd + 4))) verified = true;
  }
  return verified;
}

function decodeBase64(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) throw new Error('base64');
  return Buffer.from(value, 'base64');
}

const sha256 = (...parts) => crypto.createHash('sha256').update(Buffer.concat(parts)).digest();
const LEAF_PREFIX = Buffer.from([0]);
const NODE_PREFIX = Buffer.from([1]);

function decimal(value) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,18})$/.test(value)) throw new Error('number');
  return BigInt(value);
}

// RFC 9162 section 2.1.3.2: recompute the tree root from a leaf and its audit path.
function merkleRoot(leafHash, index, size, path) {
  if (index >= size) throw new Error('proof');
  let node = index;
  let last = size - 1n;
  let hash = leafHash;
  for (const sibling of path) {
    if (last === 0n) throw new Error('proof');
    if (node % 2n === 1n || node === last) {
      hash = sha256(NODE_PREFIX, sibling, hash);
      while (node % 2n === 0n && node !== 0n) {
        node >>= 1n;
        last >>= 1n;
      }
    } else {
      hash = sha256(NODE_PREFIX, hash, sibling);
    }
    node >>= 1n;
    last >>= 1n;
  }
  if (last !== 0n) throw new Error('proof');
  return hash;
}

// The checkpoint is a signed note: `<origin>\n<tree size>\n<root hash>\n`, optional
// extension lines, a blank line, then signature lines `\u2014 <name> <base64>` whose
// bytes are a 4-byte key hint followed by the signature over the note text.
function checkpointSignedBy(envelope, logKey, logId, size, root) {
  if (typeof envelope !== 'string') return false;
  const split = envelope.indexOf('\n\n');
  if (split < 0) return false;
  const text = envelope.slice(0, split + 1);
  const lines = text.split('\n');
  if (lines.length < 4 || !lines[0] || lines[1] !== size.toString() ||
      !decodeBase64(lines[2]).equals(root)) return false;
  const hint = decodeBase64(logId).subarray(0, 4);
  return envelope.slice(split + 2).split('\n').some((line) => {
    const match = /^\u2014 \S+ ([A-Za-z0-9+/]+={0,2})$/.exec(line);
    if (!match) return false;
    const bytes = Buffer.from(match[1], 'base64');
    return bytes.length > 4 && bytes.subarray(0, 4).equals(hint) &&
      crypto.verify('sha256', Buffer.from(text), logKey, bytes.subarray(4));
  });
}

function inclusionProven(proof, body, logKey, logId) {
  if (!proof || !Array.isArray(proof.hashes) || proof.hashes.length > 64) return false;
  const size = decimal(proof.treeSize);
  const path = proof.hashes.map((hash) => {
    const bytes = decodeBase64(hash);
    if (bytes.length !== 32) throw new Error('proof');
    return bytes;
  });
  const root = merkleRoot(sha256(LEAF_PREFIX, body), decimal(proof.logIndex), size, path);
  return root.equals(decodeBase64(proof.rootHash)) &&
    checkpointSignedBy(proof.checkpoint?.envelope, logKey, logId, size, root);
}

export function verifyNpmProvenanceBundle(bundle, expected, trust = {}) {
  const chains = trust.fulcioChains || FULCIO_CHAINS;
  const logs = trust.rekorLogs || REKOR_LOGS;
  const ctLogs = trust.ctLogs || CT_LOGS;
  try {
    const envelope = bundle?.dsseEnvelope;
    const material = bundle?.verificationMaterial;
    const rawCertificate = material?.certificate?.rawBytes ?? material?.x509CertificateChain?.certificates?.[0]?.rawBytes;
    if (!envelope || !rawCertificate) return fail('missing-material');
    if (!Array.isArray(envelope.signatures) || envelope.signatures.length !== 1) return fail('unsupported-signatures');
    if (!Array.isArray(material.tlogEntries) || material.tlogEntries.length !== 1) return fail('unsupported-log-entries');

    const leafDer = decodeBase64(rawCertificate);
    const leaf = new crypto.X509Certificate(leafDer);
    const payload = decodeBase64(envelope.payload);
    const signature = decodeBase64(envelope.signatures[0].sig);
    const payloadType = String(envelope.payloadType);
    const pae = Buffer.concat([
      Buffer.from(`DSSEv1 ${Buffer.byteLength(payloadType)} ${payloadType} ${payload.length} `),
      payload
    ]);
    if (!crypto.verify('sha256', pae, leaf.publicKey, signature)) return fail('envelope-signature');

    const entry = material.tlogEntries[0];
    const log = logs.find((item) => item.logId === entry?.logId?.keyId);
    if (!log) return fail('unknown-log');
    const integratedTime = Number(entry.integratedTime);
    const logIndex = Number(entry.logIndex);
    if (!Number.isSafeInteger(integratedTime) || !Number.isSafeInteger(logIndex) || integratedTime <= 0 || logIndex < 0) {
      return fail('log-entry');
    }
    const time = integratedTime * 1000;
    if (!within(log.validFor, time)) return fail('log-key-validity');
    const body = decodeBase64(entry.canonicalizedBody);
    const signedEntry = Buffer.from(JSON.stringify({
      body: entry.canonicalizedBody,
      integratedTime,
      logID: decodeBase64(entry.logId.keyId).toString('hex'),
      logIndex
    }));
    const logKey = crypto.createPublicKey({ key: Buffer.from(log.publicKey, 'base64'), format: 'der', type: 'spki' });
    if (!crypto.verify('sha256', signedEntry, logKey, decodeBase64(entry.inclusionPromise?.signedEntryTimestamp))) {
      return fail('log-signature');
    }
    // The signed timestamp is a promise to log the entry; the inclusion proof shows it
    // is in the log, under a tree head the log key signed.
    // Only a 2023 bundle in format 0.1 may lack the proof; a proof that is present must
    // verify whatever the format says.
    const proof = entry.inclusionProof ?? null;
    let included = proof === null && bundle.mediaType === LEGACY_BUNDLE_WITHOUT_PROOF && time < LEGACY_BUNDLE_CUTOFF;
    if (proof !== null) {
      try { included = inclusionProven(proof, body, logKey, entry.logId.keyId); } catch { included = false; }
    }
    if (!included) return fail('log-inclusion');

    // The logged entry must be for this payload, signature, and certificate.
    const logged = JSON.parse(body.toString('utf8'));
    const entryKind = `${logged?.kind} ${logged?.apiVersion}`;
    // Rekor has logged npm provenance as `dsse` 0.0.1 and, for older releases, `intoto` 0.0.2,
    // which base64-encodes the signature once more and nests the fields under `content`.
    const spec = { 'dsse 0.0.1': logged?.spec, 'intoto 0.0.2': logged?.spec?.content }[entryKind];
    const loggedSignature = entryKind === 'dsse 0.0.1' ? spec?.signatures : spec?.envelope?.signatures;
    if (!spec || spec.payloadHash?.algorithm !== 'sha256' ||
        spec.payloadHash.value !== crypto.createHash('sha256').update(payload).digest('hex') ||
        !Array.isArray(loggedSignature) || loggedSignature.length !== 1) {
      return fail('log-entry-mismatch');
    }
    const [loggedSig, loggedVerifier] = entryKind === 'dsse 0.0.1'
      ? [decodeBase64(loggedSignature[0].signature), loggedSignature[0].verifier]
      : [decodeBase64(decodeBase64(loggedSignature[0].sig).toString('latin1')), loggedSignature[0].publicKey];
    if (!loggedSig.equals(signature) || (entryKind === 'intoto 0.0.2' && spec.envelope.payloadType !== payloadType)) {
      return fail('log-entry-mismatch');
    }
    const loggedCertificate = new crypto.X509Certificate(decodeBase64(loggedVerifier));
    if (!loggedCertificate.raw.equals(leaf.raw)) return fail('log-entry-mismatch');

    const issuer = pinnedIssuer(leaf, time, chains);
    if (!issuer) return fail('certificate-chain');
    // The certificate must have been submitted to a pinned certificate-transparency log.
    let transparent = false;
    try { transparent = sctFromPinnedLog(leafDer, issuer, ctLogs); } catch { transparent = false; }
    if (!transparent) return fail('certificate-transparency');

    const extensions = certificateExtensions(leafDer);
    if (utf8Extension(extensions, OID_ISSUER_V2) !== GITHUB_ACTIONS_ISSUER) return fail('certificate-issuer');
    const repository = utf8Extension(extensions, OID_SOURCE_REPOSITORY);
    if (!expected?.repository ||
        String(repository).toLowerCase() !== `https://github.com/${String(expected.repository).toLowerCase()}`) {
      return fail('certificate-repository');
    }
    return { verified: true };
  } catch {
    return fail('malformed-bundle');
  }
}
