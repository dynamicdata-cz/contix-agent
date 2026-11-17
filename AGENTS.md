# AGENTS.md – pravidla repozitáře contix-agent (pro vývojáře i AI asistenty)

Agent a koncentrátor CONTIXu v Go. Architektura a rozhodnutí jsou v repozitáři CONTIX:
`docs/01_architecture/agenti-koncentratory.md` a `docs/05_decisions/ADR-177-agenti-a-koncentratory.md`.
Dokumentace je **česky**, kód, identifikátory a commit zprávy **anglicky**.

## Příkazy

- `make build` · `make test` · `make vet` · `make dist`
- Před dokončením změny: `gofmt -l .` (prázdný výstup), `make vet`, `make test`.

## Struktura

- `cmd/contix-agent` – jeden program, role `agent` / `concentrator` / `version`.
- `internal/protocol` – obálka, druhy zpráv, kanonický JSON, podpis Ed25519.
- `internal/identity` – klíče (TLS + podpisový), registrace, pinning klíče instalace.
- `internal/concentrator` – mTLS server, fronta, filtry, předávání, export `.ctxb`.
- `internal/agent` – moduly sběru.
- `internal/config` – podepsaný balíček konfigurace.
- `schema/` – JSON Schema protokolu exportované z CONTIXu (ručně neupravovat), `testdata/` – vzorové zprávy.

## Pravidla

- **Agent jen čte.** Žádné spouštění příkazů, stahování skriptů ani shell na pokyn ze sítě – ani „dočasně“ pro ladění.
  Ze serveru se přijímá jen podepsaná konfigurace (co sbírat a jak často).
- Agent nemá naslouchající port. Koncentrátor naslouchá jen na 8443 do zóny, odchozí spojení jen nahoru.
- **Žádná tajemství ven**: z klíčů jen otisky, z konfigurací jen vybraná nastavení nebo hashe, procesy bez argumentů
  (pokud filtr výslovně nepovolí). Nikdy hesla, obsah souborů ani logy (to je role SIEM).
- Podpis zprávy je Ed25519 nad kanonickým JSON obálky bez `sig`; kanonizace jen v `internal/protocol`.
  Koncentrátor zprávy agentů nepřebaluje ani nemění.
- Konfiguraci použít jen s platným podpisem instalace a vyšší verzí. Aktualizaci jen s podpisem vydavatele, nikdy starší verzi.
- Změna protokolu = nejdřív schéma v CONTIXu (`packages/shared`), export do `schema/`, vzorová zpráva v `testdata/` a test.
- TLS jen 1.3. Klíče v souborech s právy 0600.
- Závislosti minimální: standardní knihovna Go a `golang.org/x/...`; každá nová závislost se zdůvodněním v PR (SBOM, CRA).
- Sestavení reprodukovatelné přes `make` (`CGO_ENABLED=0`, `-trimpath`, bez build ID).
- V repozitáři žádné interní IP, servery, zákazníci ani osobní údaje – příklady z 192.0.2.0/24 a `example`.
- Každá změna s testem. Nové vydání = sekce v `CHANGELOG.md`.
- Architektonická rozhodnutí zapisuj jako ADR do repozitáře CONTIX (`docs/05_decisions/`).

## Repozitáře a vydání

- Hlavní repozitář je interní GitLab, veřejný `github.com/dynamicdata-cz/contix-agent`
  dostává jen vydání (ADR-178): tag `v<verze>` a `infra/scripts/publish.sh --source <contix-agent> --ref v<verze>`
  z repozitáře CONTIX. Historie se na GitHub nikdy nepushuje.
