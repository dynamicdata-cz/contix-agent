#!/bin/sh
# Instalace agenta CONTIX jako služby systemd (Linux se systemd).
#
#   sudo sh install-agent.sh --concentrator https://konc.firma.cz:8443 --token ctxe_… --ca-fingerprint <sha256> [--binary ./contix-agent]
#
# Token a otisk CA vypíše na koncentrátoru: sudo -u contix-agent contix-agent concentrator token --state-dir /var/lib/contix-agent/concentrator
# Opakované spuštění = aktualizace programu a služby (přihlášení agenta se nemění).
set -eu

CONC="" TOKEN="" FP="" BIN=""
DIR="$(cd "$(dirname "$0")" && pwd)"
STATE=/var/lib/contix-agent-host
while [ $# -gt 0 ]; do
  case "$1" in
    --concentrator) CONC="$2"; shift ;;
    --token) TOKEN="$2"; shift ;;
    --ca-fingerprint) FP="$2"; shift ;;
    --binary) BIN="$2"; shift ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "neznámý parametr: $1" >&2; exit 2 ;;
  esac
  shift
done

die() { echo "✖ $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "spusťte jako root (sudo)"
command -v systemctl >/dev/null || die "chybí systemd"
[ -n "$BIN" ] || BIN="$DIR/contix-agent"
[ -x "$BIN" ] || die "program $BIN nenalezen (parametr --binary)"
"$BIN" version >/dev/null || die "$BIN nejde spustit (jiná architektura?)"
[ -s /etc/machine-id ] || die "chybí /etc/machine-id (stálá identita serveru)"

install -d -m 0700 -o root -g root "$STATE"
# stejný program jako koncentrátor: běžící službu koncentrátoru restartujeme, aby používala novou verzi
install -m 0755 "$BIN" /usr/local/bin/contix-agent
install -m 0644 "$DIR/systemd/contix-agent.service" /etc/systemd/system/contix-agent.service
echo "✔ program $(/usr/local/bin/contix-agent version) a služba nainstalovány"

if [ ! -f "$STATE/state.json" ]; then
  [ -n "$CONC" ] && [ -n "$TOKEN" ] && [ -n "$FP" ] || die "první instalace potřebuje --concentrator, --token a --ca-fingerprint"
  /usr/local/bin/contix-agent agent enroll --state-dir "$STATE" --concentrator "$CONC" --token "$TOKEN" --ca-fingerprint "$FP"
else
  echo "✔ agent už je přihlášený ($STATE)"
fi

systemctl daemon-reload
systemctl enable contix-agent >/dev/null
systemctl restart contix-agent
if systemctl is-active --quiet contix-concentrator 2>/dev/null; then systemctl restart contix-concentrator; fi
sleep 2
systemctl --no-pager --lines=5 status contix-agent || true
echo
echo "Hotovo. V CONTIXu (Administrace → Konektory → Agenti) agenta schvalte – do schválení jsou data v karanténě."
echo "Co agent posílá: sudo contix-agent agent collect | less"
echo "Stav:            sudo contix-agent agent status --state-dir $STATE"
echo "Logy:            journalctl -u contix-agent -f"
