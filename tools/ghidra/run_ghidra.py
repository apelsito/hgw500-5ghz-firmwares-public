"""Analyze a pinned Quantenna carrier and preserve native Ghidra output."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

PINS = {
    'muc': ('qtn_driver.qtn_ruby.0.bin', '71dcd32849f122c09397490914227af6f77e51c34d15615028faa3d0fabb0fe4'),
    'auc': ('auc_driver.nomu.0.bin', 'c10018f4fe384d753a800bbbcd5ef3c85c568d0852c221009063282d30fd85f6'),
    'dsp': ('rdsp_driver.0.bin', '87c882910d87cd29ba2004c4154e9240291aaad6aedb0ff4d90c7a5570be79fd'),
}

def run(command, output, label):
    (output / (label + '-command.json')).write_text(json.dumps(command, indent=2) + '\n')
    with (output / (label + '.stdout')).open('w') as stdout, (output / (label + '.stderr')).open('w') as stderr:
        result = subprocess.run(command, stdout=stdout, stderr=stderr)
    if result.returncode:
        raise RuntimeError(label + ' exited ' + str(result.returncode))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--role', required=True, choices=PINS)
    parser.add_argument('--input', required=True, type=Path)
    parser.add_argument('--workspace', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--ghidra', type=Path, default=Path('/opt/engineering/tools/ghidra_12.1.3_PUBLIC'))
    parser.add_argument('--scripts', type=Path, default=Path(__file__).parent / 'scripts')
    parser.add_argument('--analysis-timeout', type=int, default=600)
    parser.add_argument('--decompile-timeout', type=int, default=30)
    args = parser.parse_args()
    name, sha = PINS[args.role]
    if args.input.name != name or hashlib.sha256(args.input.read_bytes()).hexdigest() != sha:
        raise ValueError('Pinned input mismatch')
    args.workspace.mkdir(parents=True, exist_ok=False)
    args.output.mkdir(parents=True, exist_ok=False)
    headless = str(args.ghidra / 'support/analyzeHeadless')
    command = [headless, str(args.workspace), 'quantenna-' + args.role,
        '-import', str(args.input), '-processor', 'ARCompact:LE:32:default', '-cspec', 'default',
        '-loader', 'BinaryLoader', '-loader-baseAddr', '0x0',
        '-analysisTimeoutPerFile', str(args.analysis_timeout), '-max-cpu', '2',
        '-scriptPath', str(args.scripts), '-preScript', 'MapQuantennaCarrier.java',
        str(args.input), args.role, str(args.output), '-postScript', 'ExportQuantenna.java',
        str(args.output), str(args.decompile_timeout), '-postScript', 'SnapshotQuantenna.java',
        str(args.output / 'ghidra-snapshot.json'), '-log', str(args.output / 'headless.log')]
    run(command, args.output, 'analysis')
    exported = json.loads((args.output / 'ghidra-export.json').read_text())
    if exported['instruction_byte_mismatches']:
        raise ValueError('Instruction byte mismatch')
    roundtrip = args.workspace / 'roundtrip'
    roundtrip.mkdir()
    command = [headless, str(roundtrip), 'restored', '-import',
        str(args.output / 'quantenna-analysis.gzf'), '-noanalysis', '-max-cpu', '2',
        '-scriptPath', str(args.scripts), '-postScript', 'SnapshotQuantenna.java',
        str(args.output / 'roundtrip-snapshot.json'), '-log', str(args.output / 'roundtrip.log')]
    run(command, args.output, 'roundtrip')
    before = json.loads((args.output / 'ghidra-snapshot.json').read_text())
    after = json.loads((args.output / 'roundtrip-snapshot.json').read_text())
    if before != after:
        raise ValueError('Portable Ghidra database roundtrip differs')
    run(['python3', str(args.scripts / 'compare.py'), str(args.output / 'ghidra-snapshot.json'),
         str(args.output / 'roundtrip-snapshot.json'), '--output', str(args.output / 'roundtrip-verification.json')], args.output, 'compare')
    run(['python3', str(args.scripts / 'verify_export.py'), '--role', args.role, '--original', str(args.input),
         '--export', str(args.output), '--output', str(args.output / 'byte-verification.json')], args.output, 'verify')
    result = dict(exported, roundtrip_matches=True, source_sha256=sha)
    (args.output / 'preservation-result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))

if __name__ == '__main__':
    main()
