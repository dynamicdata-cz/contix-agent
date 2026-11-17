#!/bin/sh
# Instalace koncentrátoru CONTIX jako služby systemd (Ubuntu / Debian a další se systemd).
#
#   sudo sh install-concentrator.sh --url https://contix.firma.cz --code ctxr_… [--server-name konc.firma.cz] [--binary ./contix-agent]
#
# Vytvoří uživatele contix-agent, nainstaluje program do /usr/local/bin, službu contix-concentrator,
# zaregistruje koncentrátor v CONTIXu (kód je jednorázový) a službu spustí. Opakované spuštění = aktualizace
# programu a služby (registrace se nemění).
set -eu

URL="" CODE="" NAMES="" BIN=""
DIR="$(cd "$(dirname "$0")" && pwd)"
STATE=/var/lib/contix-agent/concentrator
while [ $# -gt 0 ]; do
  case "$1" in
    --url) URL="$2"; shift ;;
    --code) CODE="$2"; shift ;;
    --server-name) NAMES="$2"; shift ;;
    --binary) BIN="$2"; shift ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
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

if ! id contix-agent >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/contix-agent --no-create-home --shell /usr/sbin/nologin contix-agent
  echo "✔ uživatel contix-agent"
fi
install -d -m 0700 -o contix-agent -g contix-agent /var/lib/contix-agent
install -m 0755 "$BIN" /usr/local/bin/contix-agent
install -m 0644 "$DIR/systemd/contix-concentrator.service" /etc/systemd/system/contix-concentrator.service
echo "✔ program $(/usr/local/bin/contix-agent version) a služba nainstalovány"

if [ ! -f "$STATE/state.json" ]; then
  [ -n "$URL" ] && [ -n "$CODE" ] || die "první instalace potřebuje --url a --code (registrační kód z CONTIXu)"
  runuser -u contix-agent -- /usr/local/bin/contix-agent concentrator register --state-dir "$STATE" --url "$URL" --code "$CODE" ${NAMES:+--server-name "$NAMES"}
else
  echo "✔ koncentrátor už je zaregistrovaný ($STATE)"
fi

systemctl daemon-reload
systemctl enable contix-concentrator >/dev/null
# restart = první spuštění i aktualizace programu
systemctl restart contix-concentrator
sleep 2
systemctl --no-pager --lines=5 status contix-concentrator || true

if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  echo "ℹ firewall ufw je zapnutý – povolte agentům port 8443: sudo ufw allow 8443/tcp"
fi
echo
echo "Hotovo. Token pro agenty: sudo -u contix-agent contix-agent concentrator token --state-dir $STATE --uses 10"
echo "Stav:                     sudo -u contix-agent contix-agent concentrator status --state-dir $STATE"
echo "Logy:                     journalctl -u contix-concentrator -f"
