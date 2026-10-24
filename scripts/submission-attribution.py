"""Resolve honest source attribution; no model or service calls.

An assisted/handwritten candidate uses --model or candidate.cpp.provenance.json
containing model and source_sha256. Directory names never identify AI models.
"""
import argparse
import hashlib
import json
from pathlib import Path


def resolve(candidate, worker='', model=''):
    candidate = Path(candidate)
    digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
    if model.strip():
        label, basis = model.strip(), 'explicit_coordinator_attribution'
    else:
        sidecar = candidate.with_suffix(candidate.suffix + '.provenance.json')
        if sidecar.exists():
            data = json.loads(sidecar.read_text(encoding='utf-8-sig'))
            if data.get('source_sha256', '').lower() != digest:
                raise ValueError('Provenance source hash differs from candidate')
            label, basis = data.get('model', '').strip(), 'hash_bound_candidate_provenance'
        else:
            raise ValueError('Unknown source author; supply --model or hash-bound provenance')
    if not label or len(label) > 200 or any(ord(c) < 32 for c in label):
        raise ValueError('Model/details must be 1-200 printable characters')
    return dict(model=label, basis=basis, source_sha256=digest)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', required=True, type=Path)
    parser.add_argument('--worker', default='')
    parser.add_argument('--model', default='')
    args = parser.parse_args()
    try:
        print(json.dumps(resolve(args.candidate, args.worker, args.model)))
    except (ValueError, OSError) as error:
        parser.exit(2, str(error) + '\n')
