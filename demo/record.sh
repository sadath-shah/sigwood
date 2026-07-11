#!/usr/bin/env bash
# Build the sandbox and print the steps to (re)record the README demo cast.
#
# The recording itself is interactive (you type the commands at a live prompt),
# so this script only builds a throwaway sandbox HOME - the demo corpus, a config,
# and a prompt - and then prints the record / convert / trim / render commands.
# Your real $HOME and ~/.sigwood are never touched: `~` resolves into the sandbox
# for the recording shell only.
#
#   bash demo/record.sh           # build the sandbox, then follow the printed steps
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SANDBOX="${1:-/tmp/sigwoodcast}"

command -v asciinema >/dev/null 2>&1 || { echo "record.sh: need asciinema (brew install asciinema)" >&2; exit 1; }

rm -rf "$SANDBOX"
mkdir -p "$SANDBOX/.sigwood"

# Demo corpus into ~/zeek and ~/syslog (gen_corpus.py writes <out>/zeek + <out>/syslog).
"$REPO/.venv/bin/python" "$REPO/demo/gen_corpus.py" "$SANDBOX" >/dev/null

# A config at ~/.sigwood/config.toml so a bare `sigwood hunt` just works.
cat > "$SANDBOX/.sigwood/config.toml" <<'TOML'
[sigwood]
zeek_dir = "~/zeek"
syslog_dir = "~/syslog"
default_window = "all"
TOML

# rc for the recording shell: sigwood on PATH via the repo venv (no venv prompt
# prefix), a slick prompt (its colours are re-themed at render time), start in ~.
cat > "$SANDBOX/.castrc" <<RC
unset SIGWOOD_ROOT
export VIRTUAL_ENV_DISABLE_PROMPT=1
source "$REPO/.venv/bin/activate"
export PS1='\[\e[35m\]λ\[\e[0m\] \[\e[36m\]\w\[\e[0m\] \[\e[35m\]›\[\e[0m\] '
cd "\$HOME"
clear
RC

cat <<EOF
sandbox ready: $SANDBOX
(~ resolves into the sandbox for the recording shell only; your real \$HOME is untouched)

1. record (asciinema 3.x writes asciicast v3):

     HOME="$SANDBOX" asciinema rec /tmp/demo.cast --cols 120 --rows 55 \\
       -c 'bash --rcfile "$SANDBOX/.castrc" -i'

   at the prompt, type:   sigwood digest ~/zeek/dns.log     then     sigwood hunt     then     exit

2. convert v3 -> v2 (termsvg reads v2 only) and trim the trailing 'exit' events so
   the final held frame is the report + a clean prompt (portable: head -n +N, not -N):

     asciinema convert -f asciicast-v2 /tmp/demo.cast /tmp/demo.v2.cast
     L=\$(wc -l < /tmp/demo.v2.cast)
     head -n \$((L - 3)) /tmp/demo.v2.cast > "$REPO/demo/demo.cast"

3. render the themed, play-once SVG into docs/img/:

     bash "$REPO/demo/render.sh"

teardown:  rm -rf "$SANDBOX" /tmp/demo.cast /tmp/demo.v2.cast
EOF
