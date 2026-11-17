# CONTIX agent a koncentrátor

Agent a koncentrátor pro sběr stavu serverů do [CONTIXu](https://github.com/dynamicdata-cz/contix) z oddělených zón
(kancelář, DMZ, OT, izolované sítě). Architektura: CONTIX `docs/01_architecture/agenti-koncentratory.md`, ADR-177.

- **Agent** (Linux amd64/arm64, Windows) jen čte stav hostitele a posílá podepsané zprávy. Nepřijímá příkazy
  a nemá žádný naslouchající port.
- **Koncentrátor** (stejný program, role `concentrator`) běží jeden na zónu: registrace agentů, mTLS, fronta
  na disku, filtry, předání odchozím spojením do CONTIXu nebo nadřazeného koncentrátoru.

## Stav

Fáze 1: protokol v1 (podpisy RFC 8785 + Ed25519) a **koncentrátor**. Fáze 2: **agent pro Linux** (zobrazení v CONTIXu následuje).

## Instalace koncentrátoru (systemd)

1. V CONTIXu: **Administrace → Konektory → Koncentrátory a agenti** → vytvořte koncentrátor (název, zóna)
   a zkopírujte **registrační kód** (zobrazí se jednou, platí 24 h).
2. Na serveru zóny (Ubuntu / Debian se systemd) zkopírujte program `contix-agent` a složku `packaging/` a spusťte:

   ```sh
   sudo sh packaging/install-concentrator.sh --url https://contix.firma.cz --code ctxr_… --binary ./contix-agent
   ```

   Skript vytvoří uživatele `contix-agent`, službu `contix-concentrator` (bez práv roota, zápis jen do
   `/var/lib/contix-agent`), zaregistruje koncentrátor a spustí ho. Certifikát CONTIXu musí být pro server
   důvěryhodný (interní CA → `/usr/local/share/ca-certificates/` + `update-ca-certificates`).
3. Agentům povolte port **8443/tcp**. Token pro agenty:
   `sudo -u contix-agent contix-agent concentrator token --state-dir /var/lib/contix-agent/concentrator --uses 10`

Stav: `sudo -u contix-agent contix-agent concentrator status --state-dir /var/lib/contix-agent/concentrator`,
logy: `journalctl -u contix-concentrator -f`.

### Jak koncentrátor funguje

- Do CONTIXu se přihlašuje vlastním klíčem Ed25519 a **podepisuje každý požadavek** (registrační kód jen jednou).
- Pro agenty má **vlastní CA zóny**: agent se přihlásí tokenem (`/v1/enroll`), dostane klientský certifikát a dál
  posílá zprávy jen přes **mTLS** (`/v1/batch`, TLS 1.3). Podpis každé zprávy ověří koncentrátor i CONTIX.
- Zprávy ukládá do **fronty na disku** (limit 2 GB, 7 dní) a předává je, dokud je CONTIX nepřijme – při výpadku
  CONTIXu nic neztratí. Každých 15 minut hlásí CONTIXu svůj stav (verze, fronta, poslední chyba).
- Nepřijímá a nevykonává žádné příkazy.

## Sestavení

```sh
make build   # bin/contix-agent
make test
make dist    # Linux amd64/arm64, Windows amd64
```

Sestavení je reprodukovatelné (`CGO_ENABLED=0`, `-trimpath`, bez build ID).

## Instalace agenta (Linux, systemd)

1. Na koncentrátoru vytvořte token (vypíše i hotový instalační příkaz s otiskem CA zóny):
   `sudo -u contix-agent contix-agent concentrator token --state-dir /var/lib/contix-agent/concentrator --uses 10`
2. Na serveru zkopírujte `contix-agent` a `packaging/` a spusťte (adresu koncentrátoru zadejte jménem nebo IP,
   které jsou v jeho certifikátu – jméno serveru a jeho IP adresy, případně `--server-name` při registraci):

   ```sh
   sudo sh packaging/install-agent.sh --concentrator https://192.0.2.10:8443 --token ctxe_… --ca-fingerprint <sha256> --binary ./contix-agent
   ```

3. V CONTIXu agenta schvalte (Administrace → Konektory → Agenti). Do schválení jsou jeho data v karanténě.

Co agent čte (jen čtení, `sudo contix-agent agent collect` ukáže přesně to, co by odeslal):

| Modul | Zdroj | Co se nikdy neposílá |
|---|---|---|
| systém | `/etc/os-release`, `/etc/machine-id`, `/proc` | – |
| porty | `/proc/net/*`, vlastník soketu z `/proc/<pid>/fd` | data spojení |
| služby | `systemctl list-units`, `list-unit-files` | – |
| balíčky | `/var/lib/dpkg/status`, `rpm -qa` | – |
| účty | `/etc/passwd`, `/etc/group`, stav pole v `/etc/shadow` | hash hesla |
| SSH klíče | `~/.ssh/authorized_keys` | klíč (jen otisk, typ, délka, komentář) |
| firewall | `nft list ruleset` / `iptables-save`, ufw | pravidla (jen otisk bez čítačů, počet, výchozí politika) |
| plánované úlohy | cron, systemd timery | příkaz (jen program a otisk řádku) |

Úplný snímek při startu a denně, kontrola změn každých 5 minut (posílají se jen rozdíly), stav každých 15 minut.
Zprávy čekají ve frontě na disku (256 MB, 7 dní), když koncentrátor není dostupný. Služba běží jako root jen
s oprávněními ke čtení (`CAP_DAC_READ_SEARCH`, `CAP_SYS_PTRACE`, `CAP_NET_ADMIN`), systém vidí jen pro čtení
a zapisuje jen do `/var/lib/contix-agent-host`.

## Licence

AGPL-3.0, stejně jako CONTIX. Viz [LICENSE](LICENSE).
