#!/usr/bin/env bash
# Render the README demo animation from the recorded cast.
#
# Deterministic: the same demo.cast in produces the same docs/img/demo.svg out,
# so the shipped asset is a build product of this script, not a hand-tuned file.
#
# Pipeline:
#   1. termsvg exports the asciicast to an animated SVG using its DEFAULT palette.
#      (termsvg's own -b/-t theme flags COLLAPSE the ANSI palette to a single
#      colour, which hides the coloured prompt and the method-chrome - so the
#      theme is applied here as a post-process on the SVG instead.)
#   2. Recolour to the sigwood terminal look: black background, lime default text,
#      bright-orange prompt (the castrc PS1 colours only the prompt glyphs), with
#      the detector method-chrome left cyan.
#   3. Fix termsvg's font-family (it ships a "Monago" typo) to a clean monospace
#      stack, and make the animation play once and HOLD the final frame instead of
#      looping (so a reader can actually read the report).
#
# Requires: termsvg (brew install termsvg) and perl.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CAST="$HERE/demo.cast"
OUT="$HERE/../docs/img/demo.svg"

command -v termsvg >/dev/null 2>&1 || { echo "render.sh: need termsvg (brew install termsvg)" >&2; exit 1; }

termsvg export "$CAST" -o "$OUT"

perl -0777 -i -pe '
  s/#282d35/#000000/g;                                                       # window bg  -> black
  s/\.a\{fill:#e5e5e5\}/.a{fill:#28fe14}/;                                    # default text -> lime
  s/\.b\{fill:#cd00cd\}/.b{fill:#ff9800}/;                                    # prompt (magenta glyphs) -> orange
  s/\.c\{fill:#00cdcd\}/.c{fill:#ff9800}/;                                    # prompt (cyan glyph)     -> orange
  s/font-family:[^;}"]*/font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace/g;
  s/animation-iteration-count:infinite/animation-iteration-count:1;animation-fill-mode:forwards/g;
  s/(?:\.[a-d]\{fill:#[0-9a-f]{6}\}){4}/.a{fill:#28fe14}.b{fill:#ff9800}.c{fill:#ff9800}.d{fill:#00ffff}/;  # canonicalize termsvg random palette-class order -> deterministic output
' "$OUT"

echo "render.sh: wrote $OUT"
