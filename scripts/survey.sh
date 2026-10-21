#!/usr/bin/env bash
# survey.sh — the untranslated pool: C progs with no progs/<name>.rs and not in
# scripts/non-targets.tsv. One line per object, sorted by size:
#   <lines> <#__failure> <#__success|__retval> <#SEC> <name> | <local includes>
# Usage: scripts/survey.sh [-f | -s | -m]   (-f: only pure-failure objects,
#        -s: only objects with no __failure, -m: only mixed failure+success)
set -euo pipefail
cd "$(dirname "$0")/.."
C=.build/bpf-next/tools/testing/selftests/bpf/progs
mode=${1:-}
for f in "$C"/*.c; do
  n=$(basename "$f" .c)
  [ -e "progs/$n.rs" ] && continue
  command grep -q "^$n	" scripts/non-targets.tsv 2>/dev/null && continue
  fc=$(command grep -c '__failure' "$f" || true)
  sc=$(command grep -cE '__success|__retval' "$f" || true)
  case $mode in
    -f) [ "$fc" != 0 ] && [ "$sc" = 0 ] || continue ;;
    -s) [ "$fc" = 0 ] || continue ;;
    -m) [ "$fc" != 0 ] && [ "$sc" != 0 ] || continue ;;
  esac
  l=$(wc -l < "$f"); sec=$(command grep -cE '^SEC\(' "$f" || true)
  inc=$(command grep -oE '#include "[^"]+"' "$f" | sed 's/#include //' | tr '\n' ' ' || true)
  printf '%4d %3d %3d %3d %s | %s\n' "$l" "$fc" "$sc" "$sec" "$n" "$inc"
done | sort -n
