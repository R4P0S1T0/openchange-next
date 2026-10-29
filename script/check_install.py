#!/usr/bin/env python3
"""Check a trusted DESTDIR installation without starting or provisioning a server.

Loads installed libraries, runs CLI help and validates installed template discovery
from an empty working directory. Emits a JSON inventory with file hashes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
LIBRARIES = tuple(name + '.so.0' for name in (
    'libmapi', 'libmapipp', 'libocpf', 'libmapiadmin',
    'libmapiproxy', 'libmapiserver', 'libmapistore',
))
MODULES = tuple(name + '.so' for name in (
    'dcesrv_mapiproxy', 'dcesrv_asyncemsmdb', 'exchange_nsp',
    'exchange_emsmdb', 'exchange_ds_rfr', 'mpm_pack', 'mpm_cache',
    'mpm_dummy', 'mpm_downgrade',
))
COMMANDS = ('mapiprofile', 'openchangeclient', 'openchangepfadmin', 'mapipropsdump')
ADMIN = ('openchange_provision', 'openchange_migrate', 'openchange_newuser',
         'openchange_neworganization', 'openchange_group')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def inspect(stage):
    stage = Path(stage).resolve(strict=True)
    if not stage.is_dir() or stage == Path('/'):
        raise ValueError('Use a dedicated DESTDIR directory, not the system root')
    report = {'scope': 'staged install only; no live AD/RPC/Outlook validation',
              'platform': ' '.join((platform.system(), platform.release(), platform.machine())), 'python': platform.python_version(),
              'files': [], 'checks': [], 'errors': []}
    entries = sorted(stage.rglob('*'))
    for path in entries:
        relative = str(path.relative_to(stage))
        mode = path.lstat().st_mode
        if not path.resolve().is_relative_to(stage) or not path.exists():
            report['errors'].append('Broken or escaping path: ' + relative)
        elif stat.S_ISLNK(mode):
            report['files'].append({'path': relative, 'link': os.readlink(path)})
        elif stat.S_ISREG(mode):
            report['files'].append({'path': relative, 'sha256': digest(path),
                                    'mode': oct(stat.S_IMODE(mode))})
        elif not stat.S_ISDIR(mode):
            report['errors'].append('Not a regular file or directory: ' + relative)

    if report['errors']:
        return report

    def unique(name):
        found = [p for p in entries if p.name == name and p.is_file()]
        if len(found) != 1:
            report['errors'].append('Expected exactly one installed ' + name)
            return None
        return found[0]

    libraries = [unique(name) for name in LIBRARIES + MODULES]
    commands = [unique(name) for name in COMMANDS + ADMIN]
    module = unique('provision.py')
    namedprops = unique('mapistore_namedprops.ldif')
    if namedprops:
        setup = namedprops.parent.parent
        for source in sorted((ROOT / 'setup/AD').iterdir()):
            installed = setup / 'AD' / source.name
            if source.is_file() and (not installed.is_file() or digest(installed) != digest(source)):
                report['errors'].append('Missing or changed AD template: ' + source.name)
        for source in sorted((ROOT / 'setup/openchangedb').glob('oc_provision*')):
            installed = setup / 'openchangedb' / source.name
            if not installed.is_file() or digest(installed) != digest(source):
                report['errors'].append('Missing or changed mailbox template: ' + source.name)
    if report['errors']:
        return report

    env = os.environ.copy()
    env['LD_LIBRARY_PATH'] = str(libraries[0].parent) + os.pathsep + env.get('LD_LIBRARY_PATH', '')
    env['PYTHONPATH'] = str(module.parent.parent) + os.pathsep + env.get('PYTHONPATH', '')
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    # All checks run away from the source tree, so source imports cannot hide missing files.
    with tempfile.TemporaryDirectory(prefix='openchange-install-check-') as cwd:
        def check(name, command):
            try:
                result = subprocess.run(command, cwd=cwd, env=env, capture_output=True,
                                        text=True, timeout=30, check=False)
                ok = result.returncode == 0
                detail = '' if ok else (result.stdout + result.stderr)[-4000:]
            except (OSError, subprocess.TimeoutExpired) as error:
                ok, detail = False, str(error)
            report['checks'].append({'name': name, 'ok': ok, 'detail': detail})
            if not ok:
                report['errors'].append('Runtime check failed: ' + name)

        check('installed libraries and modules', [sys.executable, '-c',
              'import ctypes,sys; [ctypes.CDLL(p) for p in sys.argv[1:]]',
              *map(str, libraries)])
        check('installed Python and template discovery', [sys.executable, '-c',
              'import sys; from pathlib import Path; import openchange.provision as p; '
              'assert Path(p.__file__).resolve() == Path(sys.argv[1]).resolve(); '
              'assert Path(p.find_setup_dir()).resolve() == Path(sys.argv[2]).resolve()',
              str(module), str(setup)])
        for command in commands:
            argv = [sys.executable, str(command)] if command.name in ADMIN else [str(command)]
            check(command.name + ' --help', argv + ['--help'])
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destdir', type=Path)
    args = parser.parse_args(argv)
    try:
        report = inspect(args.destdir)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(report, indent=2))
    return int(bool(report['errors']))


if __name__ == '__main__':
    raise SystemExit(main())
