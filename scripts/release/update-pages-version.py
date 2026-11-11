#!/usr/bin/env python3
"""Update release version examples in the static GitHub Pages site."""
import argparse
from pathlib import Path
import re

parser = argparse.ArgumentParser()
parser.add_argument('version', help='v-prefixed release tag')
parser.add_argument('--file', type=Path, required=True, help='gh-pages index.html')
args = parser.parse_args()

if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?', args.version):
    parser.error('version must be a v-prefixed release tag')

page = args.file.read_text(encoding='utf-8')
version_pattern = re.compile(r'(<span data-agent-version>).*?(</span>)')
updated, count = version_pattern.subn(lambda match: match.group(1) + args.version + match.group(2), page)
if count == 0:
    raise SystemExit(f'No release version found in {args.file}')

args.file.write_text(updated, encoding='utf-8')
print(f'Updated {count} version reference(s) in {args.file}.')
