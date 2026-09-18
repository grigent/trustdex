import { diffSnapshots } from './snapshot.mjs';
import { verifyTrustRecord } from './trust-record.mjs';

export function assessReview({ record, publicKey, baseline, current, policy = null }) {
  const signature = verifyTrustRecord(record, publicKey, {
    snapshot: baseline,
    policy
  });

  if (!signature.valid) {
    return {
      status: 'invalid',
      reason: signature.reason,
      changes: []
    };
  }

  if (!current?.digest) {
    return {
      status: 'invalid',
      reason: 'current snapshot is missing a digest',
      changes: []
    };
  }

  if (current.digest === baseline.digest) {
    return {
      status: 'approved',
      reason: 'current state matches the signed review',
      changes: []
    };
  }

  return {
    status: 'needs-review',
    reason: 'current state differs from the signed review',
    changes: diffSnapshots(baseline, current)
  };
}
