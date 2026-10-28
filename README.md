# SpamSharp

Spamfilter für beliebige IMAP-Postfächer: prüft neue Mails mit [rspamd](https://rspamd.com) und verschiebt Spam
in den Spam-Ordner des Postfachs. Wirkt dadurch auf allen Geräten gleich. Ein Docker-Container, eine Weboberfläche
(Blazor), Backend in C#.

- **Sofort statt alle paar Minuten:** neue Mails meldet der Mailserver per IMAP IDLE.
- **Mehrere Postfächer**, auch bei verschiedenen Anbietern, Spam-Schwelle je Postfach.
- **Mehrere Benutzer:** jeder sieht nur seine eigenen Postfächer, gelernt wird gemeinsam.
- **Schnell eingerichtet:** E-Mail-Adresse eingeben, Server und Port werden erkannt – aus einer Liste gängiger
  Anbieter (Gmail, GMX, WEB.DE, T-Online, Strato, IONOS, …) mit Hinweisen wie „App-Passwort nötig“, sonst per
  Autodiscovery wie in Thunderbird (autoconfig, Thunderbird-Datenbank, DNS-SRV, Mailserver der Domain).
  Den Spam-Ordner meldet der Server selbst (z. B. „Spamverdacht“ bei GMX, „[Gmail]/Spam“ bei Gmail).
- **Trainieren per Verschieben** im Mailprogramm, auf jedem Gerät.
- Mails bleiben ungelesen. Fällt der Container aus, kommen Mails einfach ungefiltert an.

## Für Benutzer

### Anmelden

- Anmelden mit E-Mail-Adresse und Passwort. Die Anmeldung gilt 30 Tage, **Abmelden** oben rechts.
- **Einladung:** Mit der Einladungsmail legst du dein Passwort selbst fest (mind. 8 Zeichen). Der Link gilt 7 Tage.
- **Passwort vergessen?** auf der Anmeldeseite schickt einen Link an deine Adresse, gültig 1 Stunde.
  Erscheint der Link nicht, ist kein Mailversand eingerichtet – dann setzt admin das Passwort neu.

### Postfach hinzufügen

1. In der **Übersicht** auf **+ Postfach hinzufügen**, E-Mail-Adresse und Passwort eingeben.
   Bei manchen Anbietern (z. B. Gmail) braucht es ein App-Passwort, darauf weist die Seite hin.
2. **Verbindung testen** zeigt, ob alles passt und wohin Spam verschoben wird. Dann **Speichern**.
3. Optional: **Spam ab Score** – rspamd-Standard 6, niedriger = strenger.

Beim ersten Lauf werden die letzten 50 Mails im Posteingang geprüft, danach jede neue Mail.

### Übersicht

- **Postfächer** mit Status. Knöpfe je Postfach:
  - **Pause / Weiter** – Prüfen anhalten oder fortsetzen
  - **Jetzt prüfen** – sofort nachsehen statt auf den Server zu warten
  - **Neu prüfen** – die letzten Mails im Posteingang erneut prüfen
  - **Spam lernen / Ham lernen** – siehe [Anlernen](#anlernen)
- **Letzte Mails** mit Score und Ergebnis, „nur Spam“ filtert. Klick auf den Betreff zeigt **Warum?** –
  alle rspamd-Regeln, die angeschlagen haben, mit Punkten.
- Knöpfe **Spam / Ham** je Mail: falsch einsortierte Mail lernen und verschieben.

### Trainieren im Mailprogramm

Geht auf jedem Gerät, ohne Weboberfläche:

- Mail nach **Spam-lernen** verschieben → wird als Spam gelernt und in den Spam-Ordner verschoben
- Mail nach **Kein-Spam** verschieben → wird als kein Spam gelernt und zurück in den Posteingang verschoben
- Mail aus dem Spam-Ordner **zurückholen** → wird als kein Spam gelernt und nicht erneut verschoben

Die Ordner legt SpamSharp selbst an. Gelernt wird für alle Benutzer gemeinsam.

### Anlernen

Der lernende Teil von rspamd (Bayes) wird erst aktiv, wenn er je **200 Spam- und 200 normale Mails** gelernt hat
(Anzeige in der Übersicht); bis dahin arbeiten die übrigen rspamd-Regeln (Inhalt, Links, Header, DKIM/DMARC).
Schneller geht es mit den Knöpfen in der Übersicht:

- **Spam lernen:** bis zu 1000 Mails aus dem Spam-Ordner
- **Ham lernen:** bis zu 1000 Mails aus dem Posteingang, die älter als 7 Tage sind. Vorher den Posteingang grob von Spam befreien.

Sehr kurze Mails überspringt rspamd beim Lernen.

## Für Admins

### Einrichten in Portainer

1. **Stacks → Add stack → Web editor**, Name `spamsharp`, Inhalt von [`docker-compose.yml`](docker-compose.yml) einfügen.
2. Unten bei **Environment variables** `ADMIN_PASSWORD` setzen.
   Optional für Einladungen und „Passwort vergessen“: `PUBLIC_URL` (Adresse der Weboberfläche, für den Link in der Mail)
   und `SMTP_HOST`, `SMTP_PORT` (Standard 587), `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` (leer = `SMTP_USER`).
3. **Deploy the stack**, dann `http://<server>:8083` öffnen. Anmelden als `admin` mit `ADMIN_PASSWORD`.

Daten liegen in `/opt/spamsharp` (legt Docker beim ersten Start an). Das ist auch das Backup.

Umzug von älteren Installationen mit `/opt/spamfilter`: Stack stoppen, auf dem Server
`sudo mv /opt/spamfilter /opt/spamsharp`, dann den Stack mit der neuen `docker-compose.yml` aktualisieren.
Ohne Umzug startet SpamSharp leer (keine Postfächer, nichts gelernt).

Updates: Das Image wird bei jeder Änderung und wöchentlich neu gebaut (neues rspamd).
In Portainer im Stack **Editor → Update the stack** mit „Re-pull image and redeploy“.

### Benutzer verwalten

Unter **Einstellungen → Benutzer** (nur für admin sichtbar):

- **Anlegen:** E-Mail-Adresse eingeben (ist der Benutzername) und Passwort (mind. 8 Zeichen).
  Mit SMTP: Passwort leer lassen = Einladungsmail, der Benutzer legt sein Passwort selbst fest.
  Nochmal mit leerem Passwort speichern = Einladung erneut senden.
- **Passwort ändern:** vorhandene Adresse mit neuem Passwort speichern.
- **Umbenennen** und **Löschen** (löscht auch die Postfächer des Benutzers).
- **Postfächer zuweisen:** Besitzer je Postfach wählen. Postfächer aus der Zeit vor mehreren Benutzern gehören admin.

admin hat kein eigenes Benutzerkonto in der Liste; sein Passwort ist immer `ADMIN_PASSWORD`.

### Was nur admin darf

| | Benutzer | admin |
|---|---|---|
| eigene Postfächer anlegen, ändern, prüfen, trainieren | ✓ | ✓ |
| Zähler „Mails geprüft / als Spam verschoben“ (alle Benutzer) | | ✓ |
| **Regeln:** Gewichte der rspamd-Regeln ändern (auch per Klick in „Warum?“) | | ✓ |
| **Einstellungen:** Prüfintervall, Namen der Lernordner, max. Mailgröße, Mails beim ersten Lauf | | ✓ |
| Benutzer verwalten, Postfächer zuweisen | | ✓ |

Regeln und Einstellungen gelten für alle Benutzer.

## Sicherheit

- Login über eigene Anmeldeseite (Cookie, 30 Tage); Anfragen fremder Webseiten werden abgelehnt. Nur im eigenen Netz betreiben
  oder hinter einen Reverse-Proxy mit HTTPS stellen.
- IMAP-Passwörter liegen verschlüsselt in `/opt/spamsharp/spamsharp.db`, der Schlüssel in `/opt/spamsharp/keys`.
  Wer den ganzen Ordner hat, kann sie entschlüsseln – Ordner schützen, am besten App-Passwörter nutzen.
  Fehlt `keys`, müssen die Passwörter neu eingegeben werden.
- IMAP nur verschlüsselt: Port 143 mit STARTTLS, sonst SSL/TLS. Zertifikat und Hostname werden geprüft
  (Sperrlisten nicht, wie bei Browsern). Server mit selbst ausgestelltem Zertifikat werden abgelehnt.
- rspamd und redis laufen im Container nur auf `127.0.0.1`; nach außen ist nur die Weboberfläche offen.
- Der Container startet als root, übernimmt `/data` und läuft dann als Benutzer `_rspamd`.

## Grenzen

- Outlook, Hotmail und Microsoft 365 erlauben keine IMAP-Anmeldung per Passwort mehr und werden nicht unterstützt.
- Autodiscovery fragt mit der Domain (nicht der Adresse) die Thunderbird-Datenbank `autoconfig.thunderbird.net` ab.
  Fehlersuche: `docker exec spamsharp /app/SpamSharp --discover name@domain.de`
- rspamd sieht die Mails erst nach der Zustellung. Prüfungen der Absender-IP (SPF, IP-Blocklisten) entfallen
  weitgehend – die macht der Mailanbieter bereits.
- DNS-Blocklisten wie Spamhaus beantworten keine Anfragen über große öffentliche DNS-Server (8.8.8.8, 1.1.1.1).
  Für bessere Erkennung auf dem Server einen eigenen DNS-Resolver nutzen.
- Neue Ordner (Spam, Lernordner) werden direkt unter der Wurzel angelegt; verschachtelte Namen vorher im
  Mailprogramm anlegen.

## Entwicklung

```
src/                C#-Projekt (ASP.NET Core, Blazor Server, MailKit, Dapper, SQLite)
rspamd/local.d/     rspamd-Konfiguration, wird ins Image kopiert
test/e2e.sh         End-to-end-Test mit Test-Mailserver (GreenMail)
Dockerfile          rspamd-Image + redis + App in einem Container
```

Test lokal (braucht Docker und openssl): `sh test/e2e.sh` – läuft auch in GitHub Actions vor jedem Image-Build.
