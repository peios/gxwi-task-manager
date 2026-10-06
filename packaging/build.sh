set -eu
SRC=$(pwd -P)
COMPONENT=gxwi-task-manager
export CARGO_HOME="$PEKIT_OUT/cargo-home"
mkdir -p "$CARGO_HOME"
cp "$PEKIT_VENDOR_OUT/cargo-config.toml" "$CARGO_HOME/config.toml"
unset PEIOS_LIB_DIR PEIOS_INCLUDE PKM_UAPI
pkg-config --atleast-version=0.5.8 peios
export BINDGEN_EXTRA_CLANG_ARGS="-isystem $(gcc -print-file-name=include) ${BINDGEN_EXTRA_CLANG_ARGS:-}"
export RUSTC_BOOTSTRAP=1
export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-Zcf-protection=full --remap-path-prefix=$PEKIT_WORKSPACE_ROOT=/usr/src/debug/dev.peios.$COMPONENT/.workspace --remap-path-prefix=$PEKIT_OUT_BASE=/usr/src/debug/dev.peios.$COMPONENT/.build --remap-path-prefix=$SRC=/usr/src/debug/dev.peios.$COMPONENT --remap-path-prefix=$PEKIT_VENDOR_OUT/vendor=/usr/src/debug/dev.peios.$COMPONENT/vendor"
cargo build --release --workspace --bins --locked --offline --target-dir "$PEKIT_OUT/target"
/usr/libexec/peios-packaging/collect-rust-licences --licence-root "$PEKIT_OUT/licenses" --root gxwi-task-manager --notice "git+https://github.com/peios/authd.git=third-party/authd-LICENSE" --notice "git+https://github.com/peios/gxwi.git=third-party/gxwi-LICENSE" --notice "git+https://github.com/peios/gxwi-sd-editor.git=third-party/gxwi-sd-editor-LICENSE" --notice "git+https://github.com/peios/peinit.git=third-party/peinit-LICENSE" --notice "git+https://github.com/peios/peios-rs.git=third-party/peios-rs-LICENSE" --expression-out "$PEKIT_OUT/license-expression"
python3 packaging/check-licenses.py "$PEKIT_OUT/license-expression"
mkdir -p "$PEKIT_OUT/usr/bin" "$PEKIT_OUT/usr/share/apps" "$PEKIT_OUT/usr/share/icons/base"
cp "$PEKIT_OUT/target/release/gxwi-task-manager" "$PEKIT_OUT/usr/bin/gxwi-task-manager"
cp dev.peios.gxwi-task-manager.toml "$PEKIT_OUT/usr/share/apps/"
cp gxwi-task-manager.svg "$PEKIT_OUT/usr/share/icons/base/dev.peios.gxwi-task-manager.svg"
: > "$PEKIT_OUT/.debug-sources"
split_debug() {
  component=$1
  elf=$2
  list="$PEKIT_OUT/.debug-$component"
  debugedit -b "$SRC" -d /usr/src/debug/dev.peios.$COMPONENT -l "$list" -n "$elf"
  cat "$list" >> "$PEKIT_OUT/.debug-sources"
  build_id=$(readelf -n "$elf" | sed -n 's/^[[:space:]]*Build ID: //p' | head -1)
  [ -n "$build_id" ] || {
    echo "$COMPONENT: $elf has no build ID" >&2
    exit 1
  }
  first=$(printf %s "$build_id" | cut -c1-2)
  rest=$(printf %s "$build_id" | cut -c3-)
  debug="$PEKIT_OUT/debug/$component/usr/lib/debug/.build-id/$first/$rest.debug"
  mkdir -p "$(dirname "$debug")"
  objcopy --only-keep-debug "$elf" "$debug"
  strip --strip-unneeded "$elf"
  objcopy --add-gnu-debuglink="$debug" "$elf"
  rm -f "$list"
}

split_debug gxwi-task-manager "$PEKIT_OUT/usr/bin/gxwi-task-manager"
DEBUG_ROOT="$PEKIT_OUT/usr/src/debug/dev.peios.$COMPONENT"
mkdir -p "$DEBUG_ROOT"
tr '\0' '\n' < "$PEKIT_OUT/.debug-sources" | LC_ALL=C sort -u | while IFS= read -r rel; do
  [ -n "$rel" ] || continue
  case "$rel" in */) continue ;; esac
  case "$rel" in
    vendor/*) origin="$PEKIT_VENDOR_OUT/$rel" ;;
    *)        origin="$SRC/$rel" ;;
  esac
  [ -f "$origin" ] || continue
  mkdir -p "$DEBUG_ROOT/$(dirname "$rel")"
  cp "$origin" "$DEBUG_ROOT/$rel"
done
rm -f "$PEKIT_OUT/.debug-sources"
test -n "$(find "$DEBUG_ROOT" -type f -print -quit)"

mkdir -p "$PEKIT_OUT/usr/share/man/man1"
for manual in man/*.1; do gzip -n -9 -c "$manual" > "$PEKIT_OUT/usr/share/man/man1/$(basename "$manual").gz"; done
