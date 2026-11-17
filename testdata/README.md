# Vzorové zprávy

Sdílené testovací vektory protokolu: ověřuje je agent (Go) i CONTIX (TypeScript), aby obě implementace
kanonického JSON (RFC 8785) a podpisu Ed25519 dávaly stejný výsledek.

- `protocol-v1/change-signed.json` – zpráva `change` podepsaná **veřejně známým testovacím klíčem** (seed 0x00–0x1f).
  Tento klíč se nikdy nesmí použít mimo testy. Obnovení: `go test ./internal/protocol -update`.

Žádné skutečné údaje: adresy jen z 192.0.2.0/24, názvy `example`.
