#!/usr/bin/env bash
set -euo pipefail
cmd_dir=''
while (($#)); do
    case "$1" in
        --cmd-dir)
            if (($# < 2)); then printf '%s\n' 'Missing directory after --cmd-dir' >&2; exit 2; fi
            cmd_dir=$2
            shift 2
            ;;
        -h|--help)
            printf '%s\n' 'Usage: ./install.sh [--cmd-dir DIRECTORY]'
            exit 0
            ;;
        *) printf 'Unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
bin_dir="$HOME/.local/bin"
mkdir -p -- "$bin_dir"
# Replace only our own symlink; do not overwrite another executable.
if [[ -e "$bin_dir/nodetest" || -L "$bin_dir/nodetest" ]]; then
    if [[ ! -L "$bin_dir/nodetest" ]] || [[ "$(readlink -- "$bin_dir/nodetest")" != "$source_dir/nodetest.py" ]]; then
        printf '%s\n' 'Existing nodetest entry differs; move it aside before installing.' >&2
        exit 1
    fi
else
    ln -s -- "$source_dir/nodetest.py" "$bin_dir/nodetest"
fi
if [[ -n "$cmd_dir" ]]; then
    mkdir -p -- "$cmd_dir"
    if [[ -e "$cmd_dir/nodetest.cmd" ]] && ! cmp -s -- "$source_dir/nodetest.cmd" "$cmd_dir/nodetest.cmd"; then
        printf '%s\n' 'Existing nodetest.cmd differs; move it aside before copying.' >&2
        exit 1
    fi
    cp -- "$source_dir/nodetest.cmd" "$cmd_dir/nodetest.cmd"
fi
printf '%s\n' 'Installed: ~/.local/bin/nodetest'
case ":$PATH:" in
    *":$bin_dir:"*) ;;
    *) printf '%s\n' 'Add ~/.local/bin to your login shell PATH, then reopen the terminal.' ;;
esac
