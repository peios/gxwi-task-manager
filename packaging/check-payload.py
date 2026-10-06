import json, pathlib, sys, subprocess, tomllib
root = pathlib.Path(sys.argv[1])
for binary in ['gxwi-task-manager']:
    elf = root / 'usr/bin' / binary
    assert elf.is_file()
    dynamic = subprocess.check_output(['readelf', '-dW', elf], text=True)
    assert 'BIND_NOW' in dynamic and 'RELR' in dynamic
    assert 'RPATH' not in dynamic and 'RUNPATH' not in dynamic and 'TEXTREL' not in dynamic
    notes = subprocess.check_output(['readelf', '-n', elf], text=True)
    assert 'IBT' in notes and 'SHSTK' in notes
    build_id = notes.split('Build ID: ')[1].split()[0]
    debug = root / 'debug' / 'gxwi-task-manager' / 'usr/lib/debug/.build-id' / build_id[:2] / (build_id[2:] + '.debug')
    assert debug.is_file()
    assert (root / 'usr/share/man/man1' / (binary + '.1.gz')).is_file()
for seed in (root / 'usr/share/regim').glob('*.reg'):
    data = json.loads(seed.read_text())
    assert data['keys']
    assert '/tmp/' not in seed.read_text() and '/share/' not in seed.read_text()
apps = list((root / 'usr/share/apps').glob('*.toml'))
assert [a.name for a in apps] == ['dev.peios.gxwi-task-manager.toml'], apps
for app in apps:
    declared = tomllib.loads(app.read_text())
    assert declared['program'] == '/usr/bin/gxwi-task-manager', declared
    icon = root / 'usr/share/icons/base' / ('dev.peios.gxwi-task-manager.svg')
    assert icon.is_file()
