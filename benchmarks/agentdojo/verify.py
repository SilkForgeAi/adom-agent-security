"""Offline verification of author-produced records; standard library only."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import zipfile

ROOT = Path(__file__).resolve().parent


def sha(data):
    return hashlib.sha256(data).hexdigest()


def source_check():
    manifest = json.loads((ROOT / 'SOURCE_MANIFEST.json').read_text())
    for name, digest in manifest['files'].items():
        path = ROOT / 'source' / name
        if not path.is_file() or sha(path.read_bytes()) != digest:
            raise ValueError('Frozen source mismatch: ' + name)
    actual = {str(p.relative_to(ROOT / 'source')) for p in (ROOT / 'source').rglob('*.py')}
    if actual != set(manifest['files']):
        raise ValueError('Unexpected or missing frozen Python source')
    return len(actual)


def read_evidence(directory):
    directory = Path(directory)
    manifest = json.loads((directory / 'manifest.json').read_text())
    archive = directory / 'records.zip'
    if sha(archive.read_bytes()) != manifest['archive_sha256']:
        raise ValueError('Archive hash mismatch')
    records = {}
    with zipfile.ZipFile(archive) as z:
        names = z.namelist()
        if len(names) != len(set(names)) or set(names) != set(manifest['files']):
            raise ValueError('Duplicate, missing, or unexpected archive members')
        if sum(i.file_size for i in z.infolist()) > 100_000_000:
            raise ValueError('Archive exceeds verification size limit')
        for name in names:
            path = PurePosixPath(name)
            if path.is_absolute() or '..' in path.parts or '\\' in name:
                raise ValueError('Unsafe archive member')
            data = z.read(name)
            if sha(data) != manifest['files'][name]:
                raise ValueError('Member hash mismatch: ' + name)
            records[name] = json.loads(data) if name.endswith('.json') else data
    return manifest, records


def verify(directory):
    manifest, files = read_evidence(directory)
    protocol = files['protocol.json']
    freeze = files['banking/policies.json'].copy()
    stored = freeze.pop('freeze_sha256')
    if sha(json.dumps(freeze, sort_keys=True).encode()) != stored or stored != protocol['freeze_sha256']:
        raise ValueError('Policy freeze mismatch')
    subset = json.loads((ROOT / 'SOURCE_MANIFEST.json').read_text())['files']
    original = files['original/registration.json']
    for name, digest in subset.items():
        if original['source_files'].get(name) != digest:
            raise ValueError('Source differs from original registration: ' + name)
    for name in ('worker.py', 'full_suite.py', 'audit.py'):
        expected = original['harness_files'].get(name)
        if expected and sha(files['original/' + name]) != expected:
            raise ValueError('Historical harness mismatch: ' + name)
    if sha((ROOT / 'SOURCE_MANIFEST.json').read_bytes()) != manifest['source_subset_manifest_sha256']:
        raise ValueError('Source manifest mismatch')
    episodes = [v for n, v in files.items() if n.startswith('episodes/')]
    expected_ids = set()
    for arm in ('baseline', 'adom'):
        for phase in ('clean', 'attack'):
            for task in protocol['task_ids']:
                for inj in protocol['injection_ids'] if phase == 'attack' else [None]:
                    expected_ids.add(f'{phase}-r1-{arm}-' + ('important_instructions' if inj else 'none') + f'-{task}-{inj or "none"}')
    ids = [e['id'] for e in episodes]
    if len(ids) != len(set(ids)) or set(ids) != expected_ids or len(ids) != manifest['expected_episodes']:
        raise ValueError('Duplicate/missing/unexpected episodes')
    tables = {a: {} for a in ('baseline', 'adom')}
    used_traces = set()
    for e in episodes:
        candidates = [n for n in files if n.startswith(f'logs/{e["phase"]}/r{e["repeat"]}-{e["condition"]}/')
                      and n.endswith(f'/banking/{e["task"]}/{e.get("attack") or "none"}/{e.get("injection_task") or "none"}.json')]
        if len(candidates) != 1:
            raise ValueError('Missing/ambiguous trace: ' + e['id'])
        used_traces.add(candidates[0]); trace = files[candidates[0]]
        if (trace['suite_name'] != 'banking' or trace['user_task_id'] != e['task']
                or trace['injection_task_id'] != e.get('injection_task')
                or trace['benchmark_version'] != 'v1.2.2'
                or trace['agentdojo_package_version'] != '0.1.35'
                or trace['pipeline_name'] != manifest['model'] + ('-adom' if e['condition'] == 'adom' else '')):
            raise ValueError('Trace identity mismatch: ' + e['id'])
        if e['status'] == 'VALID' and (trace.get('error') or e.get('trace_error')):
            raise ValueError('Valid episode has an error: ' + e['id'])
        if type(e.get('utility')) is not bool or trace['utility'] != e['utility']:
            raise ValueError('Native utility mismatch: ' + e['id'])
        if e['phase'] == 'attack' and (type(e.get('attack_success_raw')) is not bool or trace['security'] != e['attack_success_raw']):
            raise ValueError('Native attack score mismatch: ' + e['id'])
    if used_traces != {n for n in files if n.startswith('logs/')}:
        raise ValueError('Unpaired native trace')
    for arm in tables:
        for phase in ('clean', 'attack'):
            rows = [e for e in episodes if e['condition'] == arm and e['phase'] == phase]
            valid = [e for e in rows if e['status'] == 'VALID']
            tables[arm][phase] = dict(completed=len(rows), valid=len(valid), utility_successes=sum(e['utility'] for e in valid),
                                      raw_attack_successes=sum(e['attack_success_raw'] for e in valid) if phase == 'attack' else None)
    if tables != manifest['expected_tables']:
        raise ValueError('Aggregate differs from published historical summary')
    gate = files['original/clean_gate.json']['banking']
    if gate['passed'] or manifest['clean_gate_passed']:
        raise ValueError('Historical failed clean gate was changed')
    return dict(status='VERIFIED_AUTHOR_RECORD_CONSISTENCY', episodes=len(episodes), native_traces=len(used_traces),
                source_files=source_check(), tables=tables, clean_gate_passed=False,
                limitation='Not provider authentication, fresh model reproduction, or independent validation.')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('evidence', nargs='?', type=Path, default=ROOT / 'evidence/banking-v6')
    args = p.parse_args()
    print(json.dumps(verify(args.evidence), indent=2))


if __name__ == '__main__':
    main()
