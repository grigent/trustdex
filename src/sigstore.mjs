import crypto from 'node:crypto';
import { FULCIO_CHAINS, REKOR_LOGS } from './sigstore-trust-root.mjs';

// Offline verification of the Sigstore bundle npm serves with build provenance.
// Checked: the DSSE signature against the signing certificate; that certificate's chain
// to a pinned Fulcio root; the certificate's OIDC issuer and source repository; the
// Rekor entry's signed timestamp against the pinned log key; that the entry is for this
// envelope and certificate; and that the logged time is inside the certificate's
// validity. Not checked: the certificate-transparency SCT, the Merkle inclusion proof,
// RFC 3161 timestamps, and trust-root freshness (the root is pinned, not fetched).

const GITHUB_ACTIONS_ISSUER = 'https://token.actions.githubusercontent.com';
const OID_ISSUER_V2 = '1.3.6.1.4.1.57264.1.8';
const OID_SOURCE_REPOSITORY = '1.3.6.1.4.1.57264.1.12';
const MAX_DER_DEPTH = 16;

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

function chainsToPinnedRoot(leaf, time, chains) {
  return chains.some(({ validFor, certificates }) => {
    if (!within(validFor, time) || certificates.length === 0) return false;
    try {
      const chain = [leaf, ...certificates.map((raw) => new crypto.X509Certificate(Buffer.from(raw, 'base64')))];
      const root = chain.at(-1);
      return chain.every((certificate, index) => {
        const issuer = chain[index + 1] || root;
        return certificateValidAt(certificate, time) && (index === 0 || certificate.ca) &&
          certificate.checkIssued(issuer) && certificate.verify(issuer.publicKey);
      });
    } catch {
      return false;
    }
  });
}

function decodeBase64(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) throw new Error('base64');
  return Buffer.from(value, 'base64');
}

export function verifyNpmProvenanceBundle(bundle, expected, trust = {}) {
  const chains = trust.fulcioChains || FULCIO_CHAINS;
  const logs = trust.rekorLogs || REKOR_LOGS;
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

    // The logged entry must be for this payload, signature, and certificate.
    const logged = JSON.parse(body.toString('utf8'));
    const loggedSignature = logged?.spec?.signatures;
    if (logged?.kind !== 'dsse' || logged.apiVersion !== '0.0.1' ||
        logged.spec?.payloadHash?.algorithm !== 'sha256' ||
        logged.spec.payloadHash.value !== crypto.createHash('sha256').update(payload).digest('hex') ||
        !Array.isArray(loggedSignature) || loggedSignature.length !== 1 ||
        !decodeBase64(loggedSignature[0].signature).equals(signature)) {
      return fail('log-entry-mismatch');
    }
    const loggedCertificate = new crypto.X509Certificate(decodeBase64(loggedSignature[0].verifier));
    if (!loggedCertificate.raw.equals(leaf.raw)) return fail('log-entry-mismatch');

    if (!chainsToPinnedRoot(leaf, time, chains)) return fail('certificate-chain');

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
