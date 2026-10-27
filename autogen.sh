#!/bin/sh

# Generate the top-level, hand-maintained Autoconf build.
# Tool overrides are executable names or paths (without extra arguments).
set -eu

: "${AUTOCONF:=autoconf}"
: "${AUTOHEADER:=autoheader}"
: "${ACLOCAL:=aclocal}"

for tool in "$AUTOCONF" "$AUTOHEADER" "$ACLOCAL"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "$0: required tool not found: $tool" >&2
        exit 1
    fi
done

# Compare major as well as minor so a future 3.x is not mistaken for 2.0.
for tool in "$AUTOCONF" "$AUTOHEADER"; do
    if ! "$tool" --version | awk '
        NR == 1 {
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^[0-9]+\.[0-9]+/) {
                    split($i, version, ".")
                    if (version[1] > 2 || (version[1] == 2 && version[2] >= 57))
                        valid = 1
                    break
                }
            }
        }
        END { exit !valid }
    '; then
        echo "$0: $tool must be version 2.57 or later" >&2
        exit 1
    fi
done

# pkg.m4 is provided by pkg-config/pkgconf development tooling.
# aclocal honours ACLOCAL_PATH for dependencies installed in a custom prefix.
echo "$0: running $ACLOCAL"
"$ACLOCAL"
echo "$0: running $AUTOHEADER"
"$AUTOHEADER" --force
echo "$0: running $AUTOCONF"
"$AUTOCONF" --force

echo "Now run ./configure and make"
