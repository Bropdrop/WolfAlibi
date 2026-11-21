"""Rebuild or check the standalone offline explorer, recorded results and review ZIP."""

import argparse
from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from zipfile import ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / 'public_lab'
PAGE = 'public_lab/index.html'
REPORT = 'public_lab/reports/verification.json'
ARCHIVE = 'public_lab/quorvane-public-lab-001.zip'
BASENAMES = ('pins.json', 'challenge.txt', 'genuine.json', 'tampered.json')
# Vendored verbatim from this checkout. Only the canonical verifier import
# closure and the two review commands/tests are distributed in the ZIP.
MODULES = (
    '__init__', 'agent_probe', 'agent_solitary', 'agent_solitary_observation',
    'agent_solitary_worker', 'clearance_records', 'education_records', 'education_verify',
    'finance_records', 'finance_verify', 'history_records', 'history_verify', 'receipts',
    'solitary', 'solitary_cli', 'solitary_evidence', 'solitary_preflight', 'solitary_worker',
    'stage3', 'stage35', 'stage35_measure', 'stage35_verifier', 'stage3_evidence', 'stage3_worker',
)


def render():
    completed = subprocess.run([sys.executable, str(ROOT / 'scripts/public_lab.py'), 'verify'],
                               cwd=ROOT, capture_output=True, check=False)
    report = json.loads(completed.stdout)
    if completed.returncode or report.get('outcome') != 'PASS':
        raise ValueError('canonical verification failed; run python scripts/public_lab.py verify for details')
    manifest_bytes = (LAB / 'manifest.json').read_bytes()
    if sha256(manifest_bytes).hexdigest() != report['manifest_sha256']:
        raise ValueError('manifest changed during verification')
    manifest = json.loads(manifest_bytes)
    provenance = json.loads((LAB / 'reports/provenance.json').read_bytes())
    for experiment in manifest['experiments']:
        audited = provenance['cases'][experiment['id']]
        source = audited['pull_request']
        if experiment['source'] != {'pr': source['number'], 'commit': source['head_commit'], 'tree': source['tree']}:
            raise ValueError('experiment source differs from the reviewed PR revision')
        if experiment['files'] != {name: info['sha256'] for name, info in audited['vectors'].items()}:
            raise ValueError('experiment files differ from the published-source review')
    data = {'manifest': manifest, 'manifest_sha256': report['manifest_sha256'], 'cases': {}}
    source_paths = []
    for result in report['cases']:
        name = result['id']
        prefix = f'public_lab/vectors/{name}'
        raw = {}
        for filename in BASENAMES:
            path = f'{prefix}/{filename}'
            content = (ROOT / path).read_bytes()
            if sha256(content).hexdigest() != result['files'][filename]:
                raise ValueError(f'artifact changed during build: {path}')
            raw[filename] = content.decode('utf-8')
            source_paths.append(path)
        commands = {
            variant: (f'python -m wolfalibi.{name}_verify --expectations {prefix}/pins.json '
                      f'--evidence {prefix}/{variant}.json --challenge {raw["challenge.txt"].strip()}')
            for variant in ('genuine', 'tampered')
        }
        data['cases'][name] = {'raw': raw, 'commands': commands,
                               'results': {variant: result[variant] for variant in commands}}
    # A malicious string in a future public sample must remain inert HTML data.
    payload = json.dumps(data, ensure_ascii=True, separators=(',', ':')).replace('&', '\\u0026').replace('<', '\\u003c').replace('>', '\\u003e')
    ui = LAB / 'ui'
    page = (ui / 'template.html').read_text(encoding='utf-8')
    style = (ui / 'style.css').read_text(encoding='utf-8')
    script = '\n'.join((ui / name).read_text(encoding='utf-8') for name in ('record-check.js', 'explorer.js'))
    for slot, content in [('STYLE', f'<style>\n{style}\n</style>'),
                          ('DATA', f'<script type="application/json" id="lab-data">{payload}</script>'),
                          ('SCRIPT', f'<script>\n{script}\n</script>')]:
        marker = f'<!-- LAB_{slot} -->'
        if page.count(marker) != 1:
            raise ValueError(f'expected exactly one {slot} template slot')
        page = page.replace(marker, content)
    return {PAGE: page.encode('utf-8'), REPORT: completed.stdout}, source_paths


def package(generated, vectors):
    source = ['public_lab/README.md', 'public_lab/preview.jpg', 'public_lab/manifest.json', 'public_lab/reports/provenance.json', 'scripts/public_lab.py',
              'scripts/public_lab_finding.py', 'test_public_lab.py', 'test_public_lab_finding.py', 'alibi.py',
              *vectors, *(f'wolfalibi/{module}.py' for module in MODULES)]
    entries = {**generated, **{name: (ROOT / name).read_bytes() for name in source}}
    entries['START-HERE.txt'] = (
        'QUORVANE  /  PUBLIC LAB 001\n\nExtract the entire ZIP. Open public_lab/index.html in your browser.\n'
        'Read public_lab/README.md for the offline verifier and findings workflow.\n'
        'From this folder: python scripts/public_lab.py verify\n'
        'Python verification requires Python 3.11+ and cryptography==50.0.0 already installed.\n'
    ).encode('utf-8')
    buffer = BytesIO()
    with ZipFile(buffer, 'w') as archive:
        for name, content in sorted(entries.items()):
            entry = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            # Store verbatim bytes so zlib versions cannot change the public ZIP hash.
            archive.writestr(entry, content)
    return buffer.getvalue()


def replace_output(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    stream = tempfile.NamedTemporaryFile(dir=path.parent, delete=False)
    temporary = Path(stream.name)
    try:
        with stream:
            stream.write(content)
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument('--check', action='store_true', help='compare all tracked outputs without writing')
    action.add_argument('--archive', type=Path, help='write a new copy of the review ZIP at this path')
    args = parser.parse_args()
    result = {'schema': 'QUORVANE_PUBLIC_LAB_BUILD_V1', 'outcome': 'BLOCKED'}
    try:
        files, vectors = render()
        files[ARCHIVE] = package(files, vectors)
        result['artifacts'] = {name: sha256(content).hexdigest() for name, content in files.items()}
        if args.archive:
            with args.archive.open('xb') as output:
                output.write(files[ARCHIVE])
        else:
            for name, content in files.items():
                path = ROOT / name
                if args.check and (not path.is_file() or path.read_bytes() != content):
                    raise ValueError(f'stale or missing generated file: {name}')
                if not args.check:
                    replace_output(path, content)
        result['outcome'] = 'PASS'
    except (OSError, ValueError, KeyError) as exc:
        result['reason'] = str(exc)
    print(json.dumps(result, sort_keys=True))
    return 0 if result['outcome'] == 'PASS' else 2


if __name__ == '__main__':
    raise SystemExit(main())
