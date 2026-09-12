# CHORUS – minimal-invasiver Implementierungsfahrplan

## 1. Ziel und Leitprinzip

Die bestehende Spectrum-Implementierung wird nicht neu geschrieben. Sie bleibt die
kryptographische und verteilte Transportbasis für die Main-Phase. CHORUS wird als
dünne Integrations- und Protokollschicht darum aufgebaut.

Jeder Implementierungsschritt muss:

1. genau ein klar beschriebenes Verhalten hinzufügen oder korrigieren,
2. durch einen Test oder eine überprüfbare Beobachtung abgesichert sein,
3. den bestehenden Spectrum-Datenpfad möglichst unverändert lassen,
4. einen weiterhin kompilierbaren und ausführbaren Zwischenstand ergeben und
5. verständlich sein, bevor der nächste Schritt begonnen wird.

Bootstrap wird parallel entwickelt. Die Main-Phase hängt deshalb nur von einer
kleinen, stabilen Bootstrap-Ausgabeschnittstelle ab und nicht von der internen
Riposte-Implementierung.

## 2. Verbindliche Zielarchitektur

CHORUS besteht aus folgenden sichtbaren Rollen:

```text
                         ┌───────────────────────────┐
                         │         Authority         │
                         │                           │
                         │  ┌─────────┐ ┌─────────┐  │
                         │  │Key      │ │Verifier │  │
                         │  │Manager  │ │         │  │
                         │  └─────────┘ └────┬────┘  │
                         │                   │       │
                         │              ┌────▼────┐  │
                         │              │Publisher│  │
                         │              └────┬────┘  │
                         └───────────────────┼───────┘
                                             │
                                      verified rounds
                                             │
                                             ▼
                                        Consumer

 Member ── share A ──► ShareServer A ── aggregate A ──┐
        └─ share B ──► ShareServer B ── aggregate B ──┴─► Authority
```

### 2.1 ShareServer

Es gibt genau zwei voneinander getrennte ShareServer: `A` und `B`. Ein
ShareServer wird zunächst durch die bestehende Kombination aus einem Spectrum-
Worker und einem Spectrum-Leader realisiert. `workers_per_group` wird auf `1`
gesetzt.

Die interne Aufteilung in Worker und Leader ist außerhalb des ShareServers nicht
Teil des CHORUS-Protokolls. Sicherheitsrelevant bleibt jedoch:

- ShareServer A darf niemals eine rohe DPF-Share für B besitzen.
- ShareServer B darf niemals eine rohe DPF-Share für A besitzen.
- Die beiden ShareServer laufen in getrennten Prozessen und später auf getrennten
  Hosts.
- Audit findet vor der Aggregation statt.
- Jeder ShareServer gibt nur seine eigene signierte Aggregat-Share aus.

### 2.2 Authority

Die Authority ist verpflichtend eine logische CHORUS-Komponente mit drei
Verantwortungsbereichen:

1. **KeyManager:** verwaltet Authority-eigene Schlüssel und stellt
   BBS+-Credentials aus. Das geheime Member-Attribut `k` wird blind eingebracht
   und nicht von der Authority gespeichert.
2. **Verifier:** empfängt die beiden signierten Aggregat-Shares, rekonstruiert die
   Channel-Payloads und führt Self-Binding-, ZKP- und Duplicate-Prüfungen aus.
3. **Publisher:** erzeugt daraus signierte, versionierte und abrufbare
   Veröffentlichungen.

Diese Verantwortungsbereiche gehören zur selben sichtbaren Authority, werden im
Code aber als getrennte Module mit kleinen Schnittstellen gehalten. Dadurch wird
verhindert, dass Schlüsselverwaltung, Verifikationszustand und Ausgabeformat zu
einem schwer testbaren Block verschmelzen.

Der vorhandene Spectrum-Publisher ist der Ausgangspunkt für den
Verifier-/Publisher-Datenpfad der Authority. Die KeyManager-Funktionalität kommt
als neue Authority-interne Komponente hinzu.

### 2.3 Member und Consumer

- Der Member erzeugt pro Main-Round genau eine Submission für jeden ShareServer:
  echten Broadcast oder Cover.
- Der Consumer liest ausschließlich Authority-Publikationen und führt die lokale
  Threshold-Entscheidung aus.
- Der Consumer besitzt keine Server- oder Authority-Geheimnisse.

## 3. Regeln zum Schutz des Spectrum-Originalcodes

### 3.1 Zunächst unangetastet

Diese Bereiche werden nicht verändert, solange kein konkreter Test beweist, dass
CHORUS dort eine andere Eigenschaft benötigt:

- `spectrum_primitives/src/dpf/`
- `spectrum_primitives/src/vdpf/`
- `spectrum_primitives/src/prg/`
- `spectrum_protocol/src/secure.rs`
- der bestehende `Protocol`-Trait

### 3.2 Erlaubte Integrationspunkte

Gezielte Änderungen sind voraussichtlich nur hier erforderlich:

- `spectrum/src/worker/mod.rs`: Audit-Gating und Round-Zuordnung
- `spectrum/src/leader.rs`: Ausgabe einer identifizierten Aggregat-Share
- `spectrum/src/publisher.rs`: wiederverwendbarer Aggregat-Eingang für die Authority
- `spectrum/proto/spectrum.proto`: CHORUS-Envelopes mit Rolle, Window und Round
- `spectrum/src/experiment.rs`: feste Zwei-ShareServer-Konfiguration für den
  ersten Entwicklungsmodus

Neue fachliche CHORUS-Logik wird unter `chorus/` implementiert. Bestehende
Spectrum-Binaries bleiben zunächst als Referenz- und Regressionstest erhalten.
Es wird kein Spectrum-Code kopiert.

### 3.3 Änderungsdisziplin

- Keine Umbenennungen zusammen mit Verhaltensänderungen.
- Keine vorsorglichen Abstraktionen ohne mindestens zwei konkrete Nutzer.
- Keine neue Dependency ohne eine benötigte Fähigkeit und dokumentierte
  Begründung.
- Keine Änderung an einer kryptographischen Primitive ohne Known-Answer- oder
  Property-Test.
- Keine `unwrap()`-Aufrufe an Netzwerk-, Datei- oder Deserialisierungsgrenzen.
- Pro Commit nur ein fachlicher Grund für die Änderung.

## 4. Phasenplan

## Phase 0 – Baseline und Datenfluss

### Ziel

Den unveränderten Spectrum-Main-Pfad reproduzierbar verstehen und ausführen.

### Arbeit

- Bestehende Tests ausführen und bekannte Umgebungsprobleme getrennt notieren.
- Den Typfluss eines Broadcasts verfolgen:
  `broadcast → upload → gen_audit → check_audit → to_accumulator → leader → publisher`.
- Festhalten, welcher Prozess zu jedem Zeitpunkt welche Daten besitzt.
- Einen vorhandenen erfolgreichen Broadcast und einen Cover-Write nachvollziehen.

### Änderungen

Keine funktionalen Änderungen.

### Fertig, wenn

- ein unveränderter Spectrum-Roundtrip läuft,
- Broadcast- und Cover-Datenfluss erklärt werden können und
- der Ausgangszustand als Vergleichsbasis feststeht.

### Rust-Lernziele

Traits, Associated Types, Generics, `Vec<T>`, `Into`/`TryInto`, Module und Crates.

## Phase 1 – CHORUS-Rollenskelett über Spectrum

### Ziel

Der ausführbare Systemaufbau zeigt von Anfang an die CHORUS-Rollen, obwohl die
Main-Phase intern noch unverändertes Spectrum verwendet.

### Arbeit

- Ein einzelnes CHORUS-Integrations-Crate unter `chorus/` anlegen.
- CHORUS-Einstiegspunkte für folgende Rollen vorsehen:
  - `chorus-share-server` mit expliziter Rolle A oder B,
  - `chorus-authority`,
  - später `chorus-member` und `chorus-consumer`.
- `chorus-share-server` komponiert intern genau einen vorhandenen Worker und
  Leader.
- `chorus-authority` verwendet zunächst den vorhandenen Publisher-Datenpfad als
  noch unverifizierenden Aggregat-Empfänger.
- Dieser Zwischenstand muss sichtbar als Entwicklungsmodus gekennzeichnet sein;
  er ist noch keine sichere CHORUS-Implementierung.

### Änderungen am Original

Nur Exporte oder kleine Konstruktoren ergänzen, falls die bestehenden
`run`-Funktionen nicht direkt komponierbar sind. Keine Logik kopieren.

### Fertig, wenn

- zwei ShareServer-Prozesse und eine Authority gestartet werden können und
- ein bestehender Spectrum-Dummy-Payload den neuen CHORUS-benannten Pfad
  durchläuft.

### Rust-Lernziele

Binär-Targets, Bibliotheks-APIs, Komposition, `async fn` und Tokio-Tasks.

## Phase 2 – Audit muss Aggregation kontrollieren

### Ziel

Invariante „Audit vor Aggregation“ tatsächlich erzwingen.

### Arbeit

1. Einen Regressionstest für eine ungültige Submission schreiben.
2. Einen fachlichen Status `AuditRejected` ergänzen.
3. Bei fehlgeschlagenem Audit vor `to_accumulator` zurückkehren.
4. Abgelehnte Submissions weder aggregieren noch als erfolgreich zählen.
5. Prüfen, warum der bestehende Code fehlgeschlagene Audits bislang trotz
   Warnung akzeptiert; eventuelle Serialisierungsfehler zuerst beheben.

### Änderungen am Original

Kleine, lokale Änderung in `spectrum/src/worker/mod.rs` plus Tests.

### Fertig, wenn

- eine ungültige Submission bitgenau denselben Aggregatzustand ergibt wie eine
  ausgelassene Submission und
- gültige Spectrum-Submissions unverändert funktionieren.

### Rust-Lernziele

Enums, exhaustive `match`, frühe Rückgaben, fachliche Fehler gegenüber
technischen `Result`-Fehlern und Ownership über Await-Grenzen.

## Phase 3 – Typisierte ShareServer-Identität

### Ziel

Jede Nachricht und jedes Aggregat ist eindeutig ShareServer A oder B zugeordnet.

### Arbeit

- `ServerRole`, `ServerA` und `ServerB` als Domänentypen einführen.
- Gruppennummern nur an einer Adapterstelle in Serverrollen übersetzen.
- Die Serverrolle in Aggregat-Envelopes aufnehmen.
- Doppelte, fehlende oder widersprüchlich markierte Shares ablehnen.
- Noch keine Window-/Round-Zustandsmaschine ergänzen.

### Änderungen am Original

Additive Felder beziehungsweise neue Protobuf-Messages und ein kleiner Adapter
an Leader/Authority-Grenze. Die kryptographischen Share-Typen bleiben
unverändert.

### Fertig, wenn

- A und B nicht vertauscht werden können,
- die Authority genau eine Share jeder Rolle erwartet und
- doppelte A- oder B-Shares nicht als vollständiges Paar gelten.

### Rust-Lernziele

Newtype Pattern, Marker Types, `TryFrom`, Validierung und unzulässige Zustände im
Typsystem.

## Phase 4 – Window- und Round-Lebenszyklus

### Ziel

Aus Spectrums One-Shot-Ablauf wird eine Folge klar getrennter CHORUS-Main-Rounds.

### Arbeit

- `WindowId` und `RoundId` als Newtypes einführen.
- Beide IDs in Upload-, Audit- und Aggregat-Envelopes mitführen.
- ShareServer-Zustand pro `(window, round)` verwalten.
- Eine Round genau einmal finalisieren.
- Veraltete, zukünftige, doppelte und Round-fremde Nachrichten ablehnen.
- Round-Wechsel zunächst explizit durch einen Test-Koordinator auslösen; noch
  keine Wall-Clock-Scheduling-Logik hinzufügen.

### Änderungen am Original

Transport-Envelopes und die Zustandsverwaltung in Worker/Leader. DPF,
`WriteToken` und `Protocol` bleiben unverändert.

### Fertig, wenn

- mindestens zwei aufeinanderfolgende Rounds unabhängig rekonstruiert werden,
- keine Daten aus Round 1 in Round 2 erscheinen und
- Cross-Round-Shares zuverlässig abgelehnt werden.

### Rust-Lernziele

Zustandsmaschinen, `HashMap`, Schlüsseltypen, Borrowing von Einträgen und
idempotente Übergänge.

## Phase 5 – Signierte Aggregate und Authority-Rekonstruktion

### Ziel

Jeder ShareServer erzeugt eine eigene signierte Aggregat-Share. Nur die
Authority kombiniert A und B.

### Arbeit

- Ein versioniertes `SignedAggregateShare`-Envelope definieren.
- ShareServer-Rolle, Window, Round, Konfigurationsbindung und Channel-Daten
  signieren.
- Die Authority prüft Signatur und Metadaten vor der Rekonstruktion.
- Der bisherige Publisher-Akkumulator wird in einen Authority-internen
  Round-Collector überführt.
- Der Collector kombiniert nur A und B mit identischem Kontext.
- Das rekonstruierte Ergebnis wird zunächst an einen testbaren In-Memory-Sink
  übergeben.

### Änderungen am Original

Leader-Ausgabe, Publisher-Eingang und Protobuf-Wire-Format. Die eigentliche
Spectrum-Aggregation bleibt unverändert.

### Fertig, wenn

- A oder B allein keinen Channel-Klartext ergeben,
- A und B derselben Round den Dummy-Payload rekonstruieren,
- manipulierte Signaturen abgelehnt werden und
- Shares unterschiedlicher Rounds niemals kombiniert werden.

### Rust-Lernziele

Owned versus borrowed data, Trait-basierte Sinks, Fehlerpropagierung und
asynchrone Sammler.

## Phase 6 – Versionierter CHORUS-ChannelPayload

### Ziel

Spectrum transportiert einen opaken, fest großen CHORUS-Payload, ohne dessen
Inhalt zu kennen.

### Arbeit

- Einen versionierten `ChannelPayload` in der CHORUS-Schicht definieren.
- Nutzlänge explizit codieren und auf die feste Spectrum-Slotgröße auffüllen.
- Decoder gegen unbekannte Versionen, Überlänge, Trunkierung und inkonsistente
  Längen absichern.
- Zunächst Dummy-STIX und eindeutig markierte Platzhalter für noch fehlende
  kryptographische Felder verwenden.

### Änderungen am Original

Keine, sofern `Bytes` als Spectrum-Nachricht beibehalten werden kann.

### Fertig, wenn

- `decode(encode(payload)) == payload`,
- fehlerhafte Daten als `Result::Err` statt durch Panic enden und
- der Payload den vollständigen ShareServer-/Authority-Pfad bitgenau durchläuft.

### Rust-Lernziele

Structs, Slices, Serialisierung, eigene Fehlertypen, Bounds-Checks und
Trust-Boundaries.

## Phase 7 – STIX-Fingerprint und Self-Binding

### Ziel

Atomare Fingerprints berechnen und nach Rekonstruktion durch die Authority
überprüfen.

### Arbeit

- `structured_digest_v1` als reine CHORUS-Bibliothekslogik implementieren.
- Kanonische Sortierung und Normalisierung testgetrieben entwickeln.
- Fingerprints in `ChannelPayload` aufnehmen.
- Authority berechnet die Fingerprints erneut.
- Abweichungen als `self-binding-fail` markieren und nicht als internen Fehler
  behandeln.

### Änderungen am Original

Keine.

### Fertig, wenn

- äquivalente STIX-Bundles dieselben Fingerprints erzeugen,
- relevante Änderungen andere Fingerprints erzeugen und
- ein falsch deklarierter Fingerprint markiert wird.

### Rust-Lernziele

Iteratoren, Sortierung, `HashSet` versus sortierte Vektoren, Serde und pure
Funktionen.

## Phase 8 – Authority-KeyManager, BBS+ und Pseudonyme

### Ziel

Credential-basierte Mitgliedschaft und content-bound Pseudonyme integrieren.

### Arbeit

- Authority-KeyManager mit getrennter Issuance-API implementieren.
- Member-Geheimnis `k` blind in das Credential einbringen.
- Sicherstellen, dass die Authority `k` niemals speichert.
- Pseudonyme und komponierten Beweis beim Member erzeugen.
- Pseudonyme und Proof in `ChannelPayload` aufnehmen.
- Authority-Verifier prüft BBS+-Knowledge- und Pseudonym-Bindung.
- Kryptographische Bibliotheken über kleine lokale Wrapper kapseln; keine eigene
  Pairing- oder Kurvenarithmetik implementieren.

### Änderungen am Original

Keine, abgesehen von einer eventuell notwendigen größeren, weiterhin opaken
Spectrum-Slotgröße.

### Fertig, wenn

- gültige Credentials und korrekt gebundene Pseudonyme akzeptiert werden,
- falsche Credentials, Proofs und mit anderem `k` erzeugte Pseudonyme abgelehnt
  werden und
- die Authority trotz KeyManager keinen Member-Witness aus ihrem Zustand
  auslesen kann.

### Rust-Lernziele

Secret-Wrappers, Sichtbarkeit, Zeroization, RNG-Injektion, typisierte Crypto-APIs
und negative Tests.

## Phase 9 – Persistentes Seen-Set und Authority-Publisher

### Ziel

Verifizierte Channels atomar deduplizieren und als stabile Authority-Ausgabe
publizieren.

### Arbeit

- Persistentes Exact-Set mit atomarem `insert_if_absent` einführen.
- Duplicate-Status pro Atom setzen.
- Aus verifizierten Channels ein versioniertes `PublishedRound` erzeugen.
- Veröffentlichung durch die Authority signieren.
- Bereits veröffentlichte Rounds idempotent behandeln.
- Restart- und Parallelitätsverhalten testen.

### Änderungen am Original

Keine. Der Spectrum-Publisher-Code dient nur noch als wiederverwendete
Transport-/Collector-Basis innerhalb der Authority.

### Fertig, wenn

- ein Pseudonym genau einmal als neu gilt,
- parallele Wiederholungen nicht doppelt zählen,
- ein Neustart das Seen-Set nicht verliert und
- dieselbe Round nicht widersprüchlich erneut publiziert werden kann.

### Rust-Lernziele

Persistenzabstraktionen, atomare Operationen, Locks, Transaktionen und
Idempotenz.

## Phase 10 – Consumer und Threshold

### Ziel

Nur ausreichend unabhängig bestätigte IOC-Atome ausgeben.

### Arbeit

- Authority-Signaturen und Formatversion prüfen.
- Ungültige beziehungsweise markierte Atome ignorieren.
- Unterschiedliche Pseudonyme pro Fingerprint zählen.
- Threshold `T` konfigurierbar machen.
- Emission zunächst über einen testbaren In-Memory-Sink, erst später über SIEM.

### Änderungen am Original

Keine.

### Fertig, wenn

- Wiederholungen desselben Members nicht mehrfach zählen,
- verschiedene Member mit demselben Fingerprint zählen,
- unterhalb `T` keine Ausgabe erfolgt und
- beim Erreichen von `T` genau eine Ausgabe erfolgt.

### Rust-Lernziele

Collections, fachliche Invarianten, generische Output-Sinks und deterministische
Tests.

## Phase 11 – Bootstrap-Integration

### Ziel

Die parallel entwickelte Bootstrap-Phase ohne Umbau der Main-Phase anbinden.

### Erwartete Bootstrap-Ausgabe

Die Main-Phase erwartet ausschließlich ein signiertes, kanonisch geordnetes
Channel-Set mit:

- Window-ID,
- geordneten Channel-Verifikationsschlüsseln,
- resultierender Channelzahl `L_w`,
- Formatversion und
- notwendigen Signaturen.

Für jedes neue Channel-Set wird eine neue Spectrum-Protokollinstanz mit genau
`L_w` Channels erzeugt. Die bestehende DPF-Implementierung muss dadurch keine
dynamisch veränderliche Channelzahl unterstützen.

### Fertig, wenn

- ein erfolgreiches Bootstrap-Resultat genau ein Main-Window startet,
- `L_w = 0` eine signierte leere Ausgabe ohne Main-Submissions erzeugt,
- ein ungültiges oder veraltetes Channel-Set keine Round startet und
- der Window-Wechsel atomar erfolgt.

## Phase 12 – Netzwerkhärtung, Telemetrie und Evaluation

Erst nach funktionaler Ende-zu-Ende-Korrektheit folgen:

- mTLS beziehungsweise authentifizierte Endpoints,
- Timeouts, Backpressure und kontrollierte Retries,
- strukturierte Telemetrie ohne Member-Identitäten oder STIX-Payloads,
- Adversary-Tests,
- Benchmarks gegen unverändertes Spectrum,
- Multi-Host- und Raspberry-Pi-Deployment.

## 5. Reihenfolge der ersten konkreten Arbeitseinheiten

Die ersten Einheiten werden strikt in dieser Reihenfolge bearbeitet:

1. Spectrum-Broadcastpfad gemeinsam lesen und Typen notieren.
2. Bestehenden Baseline-Test ausführbar machen, ohne das Protokoll zu verändern.
3. CHORUS-Rollenskelett mit zwei ShareServern und einer Authority aufsetzen.
4. Regressionstest für fehlgeschlagenes Audit schreiben.
5. Audit-Rejection implementieren.
6. A/B-Rollen in das Aggregat-Envelope aufnehmen.
7. Zwei aufeinanderfolgende Rounds zunächst ohne STIX ausführen.

Nach jeder Einheit erfolgt ein Review, bevor die nächste Änderung begonnen wird.
Der erste sicherheitsrelevante Umbau ist Audit-vor-Aggregation; der erste
CHORUS-spezifische Architekturumbau ist das Rollenskelett.

## 6. Definition von „minimal-invasiv“

Eine Änderung ist notwendig, wenn mindestens eine dieser Bedingungen gilt:

- Ohne sie lässt sich eine spezifizierte CHORUS-Nachricht oder ein Zustand nicht
  ausdrücken.
- Ohne sie wird eine CHORUS-Sicherheitsinvariante verletzt.
- Ohne sie kann ein benötigter Prozess keine klar definierte Ein- oder Ausgabe
  anbieten.
- Ohne sie ist das Verhalten nicht automatisiert testbar.

Nicht notwendig und daher zunächst ausgeschlossen sind:

- kosmetische Umbenennungen im Spectrum-Code,
- ein vollständiger Neuaufbau der vorhandenen DPF-/VDPF-Schichten,
- die sofortige Aufteilung in viele kleine Crates,
- generische Frameworks für nur einen konkreten Anwendungsfall,
- Deployment-Optimierung vor einem korrekten lokalen Ende-zu-Ende-Pfad und
- Performance-Optimierung ohne vorherige Messung.

