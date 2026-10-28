# SpamSharp

Spamfilter für beliebige IMAP-Postfächer: prüft neue Mails mit [rspamd](https://rspamd.com) und verschiebt Spam
in den Spam-Ordner des Postfachs. Wirkt dadurch auf allen Geräten gleich. Ein Docker-Container, eine Weboberfläche
(Blazor), Backend in C#.

- **Sofort statt alle paar Minuten:** neue Mails meldet der Mailserver per IMAP IDLE.
- **Mehrere Postfächer**, auch bei verschiedenen Anbietern, Spam-Schwelle je Postfach.
- **Schnell eingerichtet:** E-Mail-Adresse eingeben, Server und Port werden erkannt – aus einer Liste gängiger
  Anbieter (Gmail, GMX, WEB.DE, T-Online, Strato, IONOS, …) mit Hinweisen wie „App-Passwort nötig“, sonst per
  Autodiscovery wie in Thunderbird (autoconfig, Thunderbird-Datenbank, DNS-SRV, Mailserver der Domain).
  Den Spam-Ordner meldet der Server selbst (z. B. „Spamverdacht“ bei GMX, „[Gmail]/Spam“ bei Gmail).
- **Trainieren per Verschieben** im Mailprogramm, auf jedem Gerät:
  - Mail nach **Spam-lernen** → wird als Spam gelernt und in den Spam-Ordner verschoben
  - Mail nach **Kein-Spam** → wird als kein Spam gelernt und zurück in den Posteingang verschoben
  - Mail aus dem Spam-Ordner **zurückgeholt** → wird als kein Spam gelernt und nicht erneut verschoben
- **Weboberfläche:** Postfächer verwalten, Verlauf mit „Warum Spam?“ (alle rspamd-Treffer je Mail),
  Gewichte der rspamd-Regeln ändern, Einstellungen.
- Mails bleiben ungelesen. Fällt der Container aus, kommen Mails einfach ungefiltert an.

## Einrichten in Portainer

1. **Stacks → Add stack → Web editor**, Name `spamsharp`, Inhalt von [`docker-compose.yml`](docker-compose.yml) einfügen.
2. Unten bei **Environment variables** `ADMIN_PASSWORD` setzen.
3. **Deploy the stack**, dann `http://<server>:8083` öffnen (Benutzer `admin`, Passwort = `ADMIN_PASSWORD`). Weitere Benutzer legt admin unter **Einstellungen** an; und weist dort auch vorhandene Postfächer zu (bestehende gehören zunächst admin); jeder sieht nur seine eigenen Postfächer, gelernt wird gemeinsam, Regeln und Einstellungen ändert nur admin.
4. **+ Postfach hinzufügen**, E-Mail-Adresse und Passwort eingeben. „Verbindung testen“ zeigt, ob alles passt
   und wohin Spam verschoben wird.

Daten liegen in `/opt/spamfilter` (legt Docker beim ersten Start an). Das ist auch das Backup.

Updates: Das Image wird bei jeder Änderung und wöchentlich neu gebaut (neues rspamd).
In Portainer im Stack **Editor → Update the stack** mit „Re-pull image and redeploy“.

## Anlernen

Der lernende Teil von rspamd (Bayes) wird erst aktiv, wenn er je **200 Spam- und 200 normale Mails** gelernt hat;
bis dahin arbeiten die übrigen rspamd-Regeln (Inhalt, Links, Header, DKIM/DMARC). Schneller geht es mit den Knöpfen
in der Übersicht:

- **Spam lernen:** bis zu 1000 Mails aus dem Spam-Ordner
- **Ham lernen:** bis zu 1000 Mails aus dem Posteingang, die älter als 7 Tage sind. Vorher den Posteingang grob von Spam befreien.

Sehr kurze Mails überspringt rspamd beim Lernen.

## Sicherheit

- Login über eigene Anmeldeseite (Cookie, 30 Tage); Anfragen fremder Webseiten werden abgelehnt. Nur im eigenen Netz betreiben
  oder hinter einen Reverse-Proxy mit HTTPS stellen.
- IMAP-Passwörter liegen im Klartext in `/opt/spamfilter/spamsharp.db`. Ordner schützen, am besten App-Passwörter nutzen.
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
