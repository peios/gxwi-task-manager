import pathlib, sys, tomllib
expression = pathlib.Path(sys.argv[1]).read_text().strip()
for file in pathlib.Path('packages.pekit').glob('dev.*.toml'):
    actual = tomllib.loads(file.read_text())['package']['license']
    assert actual == expression, f"{file}: expected {expression}, got {actual}"
