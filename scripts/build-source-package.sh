#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 OUTPUT.crate" >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
output=$1
output_parent=$(dirname -- "$output")

[ -d "$output_parent" ] || { echo "output parent does not exist: $output_parent" >&2; exit 1; }
[ ! -e "$output" ] || { echo "refusing to overwrite: $output" >&2; exit 1; }
[ ! -e "$output.sha256" ] || { echo "refusing to overwrite: $output.sha256" >&2; exit 1; }

package_dir=$(mktemp -d "${TMPDIR:-/tmp}/tiana-sdk-package.XXXXXX")
trap 'rm -rf -- "$package_dir"' EXIT HUP INT TERM

CARGO_TARGET_DIR="$package_dir/target" cargo package \
    --locked \
    --manifest-path "$repo_dir/Cargo.toml"

package_file=$(find "$package_dir/target/package" -maxdepth 1 -type f -name 'tiana-sdk-*.crate' -print)
[ -n "$package_file" ] && [ "$(printf '%s\n' "$package_file" | wc -l)" -eq 1 ] \
    || { echo "cargo produced an unexpected package set" >&2; exit 1; }

install -m 0444 "$package_file" "$output"
output_name=$(basename -- "$output")
(
    cd "$output_parent"
    sha256sum "$output_name" >"$output_name.sha256"
)
chmod 0444 "$output.sha256"
printf 'created %s\n' "$output"
