#!/usr/bin/env python3
"""Build versioned binaries and platform-specific release assets."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.request
import zipfile

NT_URL = 'https://download.wireguard.com/wireguard-nt/wireguard-nt-1.1.zip'
NT_SHA = 'dceb30a9bc4be48cce0f74160fc88a585a2c2627366e8f846fc6658f9038dace'
parser = argparse.ArgumentParser()
parser.add_argument('--version', required=True)
parser.add_argument('--os', choices=['linux', 'darwin', 'windows'])
parser.add_argument('--arch', choices=['amd64', 'arm64'])
parser.add_argument('--target', help='GoReleaser target in GOOS_GOARCH[_variant] form')
parser.add_argument('--output', default='dist')
parser.add_argument('--binary', help='existing binary built for the selected target')
parser.add_argument('--resources-only', action='store_true', help='prepare notices and the Windows driver for GoReleaser')
args = parser.parse_args()
if args.target:
    target = re.fullmatch(r'(linux|darwin|windows)_(amd64|arm64)(?:_v[0-9]+(?:\.[0-9]+)?)?', args.target)
    if not target:
        parser.error('--target must be a supported GoReleaser GOOS_GOARCH target')
    target_os, target_arch = target.groups()
    if args.os and args.os != target_os or args.arch and args.arch != target_arch:
        parser.error('--target conflicts with --os or --arch')
    args.os, args.arch = target_os, target_arch
if args.os not in ('linux', 'darwin', 'windows') or args.arch not in ('amd64', 'arm64'):
    parser.error('provide a supported --os/--arch pair or --target')
if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?', args.version):
    parser.error('version must be a v-prefixed release tag')
env = dict(os.environ, GOOS=args.os, GOARCH=args.arch, CGO_ENABLED='0')
if subprocess.check_output(['go', 'env', 'GOVERSION'], env=env, text=True, encoding="utf-8").strip() != 'go1.27.4':
    raise SystemExit('Release builds require exact Go 1.27.4')
output = Path(args.output).absolute()
output.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix='peerimeter-package-') as tmp:
    root = Path(tmp)
    binary_name = 'peerimeter-agent' + ('.exe' if args.os == 'windows' else '')
    binary = root / binary_name
    if not args.resources_only:
        if args.binary:
            binary.write_bytes(Path(args.binary).read_bytes())
        else:
            subprocess.run(['go', 'build', '-mod=readonly', '-trimpath', '-ldflags',
                            '-s -w -X github.com/peerimeter/peerimeter-agent/internal/cli.Version=' + args.version,
                            '-o', str(binary), './cmd/peerimeter-agent'], env=env, check=True)
        binary.chmod(0o755)
    # Include license notices for every module present in this target's build.
    raw = subprocess.check_output(['go', 'list', '-deps', '-json', './cmd/peerimeter-agent'], env=env, text=True, encoding="utf-8")
    decoder = json.JSONDecoder()
    modules = {}
    while raw.strip():
        raw = raw.lstrip()
        package, index = decoder.raw_decode(raw)
        raw = raw[index:]
        mod = package.get('Module', {})
        if mod and not mod.get('Main') and mod.get('Dir'):
            modules[mod['Path']] = mod
    notices = ['Peerimeter Agent: bundled third-party software notices.\n']
    for source in sorted(Path('third_party').glob('*/LICENSE*')):
        notices.append('\n=== ' + str(source.parent) + ' ===\n' + source.read_text(encoding='utf-8') + '\n')
    for name, mod in sorted(modules.items()):
        files = [p for p in Path(mod['Dir']).iterdir() if p.is_file() and p.name.upper().startswith(('LICENSE', 'COPYING', 'NOTICE'))]
        if not files:
            # Nested modules can share an upstream repository license in parent.
            directory = Path(mod['Dir'])
            for parent in list(directory.parents)[:2]:
                files = [p for p in parent.glob('LICENSE*') if p.is_file()]
                if files:
                    break
        if not files:
            # go-localereader v0.0.1 states its MIT license in README.md but
            # omits the LICENSE file from its Go module archive.
            override = Path('third_party/licenses') / name / 'LICENSE'
            if override.is_file():
                files = [override]
            else:
                raise SystemExit('Missing third-party license notice for ' + name)
        notices.append('\n=== ' + name + ' ' + mod.get('Version', '') + ' ===\n')
        for source in sorted(files):
            notices.append(source.read_text(errors='replace') + '\n')
    if args.os == 'windows':
        with urllib.request.urlopen(NT_URL, timeout=60) as response:
            archive = response.read(32 << 20)
        if hashlib.sha256(archive).hexdigest() != NT_SHA:
            raise SystemExit('Official WireGuardNT archive hash mismatch')
        with zipfile.ZipFile(io.BytesIO(archive)) as archive:
            binary_path = f'wireguard-nt/bin/{args.arch}/wireguard.dll'
            (root / 'wireguard.dll').write_bytes(archive.read(binary_path))
            licenses = [name for name in archive.namelist() if re.search(r'/(?:COPYING|LICENSE)(?:\.[^/]*)?$', name, re.I)]
            if not licenses:
                raise SystemExit('Missing official WireGuardNT license')
            notices.append('\n=== Official WireGuardNT 1.1 ===\n')
            for name in licenses:
                notices.append(archive.read(name).decode(errors='replace') + '\n')
    (root / 'peerimeter-agent.NOTICES.txt').write_text(''.join(notices))
    asset_arch = {'amd64': 'x86_64', 'arm64': 'aarch64'}[args.arch]
    if args.resources_only:
        (output / f'peerimeter-agent-{args.os}-{asset_arch}.NOTICES.txt').write_bytes(
            (root / 'peerimeter-agent.NOTICES.txt').read_bytes()
        )
        if args.os == 'windows':
            (output / f'wireguard-{args.arch}.dll').write_bytes((root / 'wireguard.dll').read_bytes())
        raise SystemExit(0)
    suffix = '.zip' if args.os == 'windows' else ''
    asset = output / f'peerimeter-agent-{args.os}-{asset_arch}{suffix}'
    if args.os == 'windows':
        with zipfile.ZipFile(asset, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for source in sorted(root.iterdir()):
                archive.write(source, source.name)
    else:
        asset.write_bytes(binary.read_bytes())
        asset.chmod(0o755)
        notice_asset = output / f'{asset.name}.NOTICES.txt'
        notice_asset.write_bytes((root / 'peerimeter-agent.NOTICES.txt').read_bytes())
    checksummed = [asset]
    if args.os != 'windows':
        checksummed.append(notice_asset)
    sums = ''.join(f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n' for path in checksummed)
    (output / 'SHA256SUMS').write_text(sums, newline='\n')
    print(asset)
