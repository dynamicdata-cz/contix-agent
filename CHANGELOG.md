# Změny

## 0.2.2

- Kostra repozitáře: program `contix-agent` (role agent / koncentrátor), obálka protokolu v1.
- Protokol v1: kanonický JSON podle RFC 8785, podpis a ověření zpráv Ed25519 (ověření nad přijatými bajty, odmítnutí duplicitních klíčů a neznámých polí), sdílený testovací vektor.
- Identita: generování podpisového klíče, uložení PKCS#8 s právy 0600 bez přepsání, otisk `SHA256:`.
- Koncentrátor: `concentrator register | run | token | status`; registrace jednorázovým kódem, podepsané požadavky
  do CONTIXu, CA zóny (certifikát serveru, klientské certifikáty agentů), přihlášení agentů tokenem, mTLS příjem
  dávek s ověřením podpisu, fronta na disku, opakované předávání, hlášení stavu; služba systemd a instalační skript.
- Koncentrátor posílá agentům i certifikát CA zóny (pinning podle otisku); `concentrator token` vypíše instalační příkaz agenta.
- Agent pro Linux: `agent enroll | run | status | collect`; přihlášení tokenem s ověřením CA koncentrátoru podle otisku,
  moduly porty, služby, balíčky, účty, SSH klíče, firewall, plánované úlohy (bez hesel, klíčů a příkazů), snímek, změny,
  stav, fronta na disku, mTLS; služba systemd s oprávněními jen ke čtení a instalační skript.
- Agent zapíše do logu první úspěšné doručení po startu nebo po výpadku (`messages delivered to concentrator`, počet a zbytek fronty).
