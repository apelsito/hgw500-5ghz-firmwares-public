"""Verify the published source snapshot; does not access hardware."""
from pathlib import Path
import hashlib,json
root=Path(__file__).resolve().parents[1]
manifest=json.loads((root/'PUBLICATION.json').read_text(encoding='utf-8'))
errors=[]
for row in manifest['files']:
    path=root/row['path']
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=row['sha256']:
        errors.append(row['path'])
if errors:
    raise SystemExit('Public snapshot mismatch: '+', '.join(errors))
print('PASS: '+str(len(manifest['files']))+' published files; historical firmware receipts were not rerun.')
