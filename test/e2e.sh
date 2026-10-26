#!/bin/sh
# End-to-end-Test: baut das Image, startet einen Test-Mailserver (GreenMail, TLS mit eigener CA)
# und prüft Spam verschieben, Zurückholen, Lernordner und Login. Aufruf: sh test/e2e.sh
set -eu
cd "$(dirname "$0")/.."
T=$(mktemp -d)
NET=spamsharp-test
PW=test-admin
cleanup() {
    docker rm -f spamsharp-test greenmail-test >/dev/null 2>&1 || true
    docker network rm $NET >/dev/null 2>&1 || true
    docker run --rm -v "$T:/t" alpine:3 rm -rf /t/data >/dev/null 2>&1 || true
    rm -rf "$T"
}
[ "${KEEP:-}" = 1 ] || trap cleanup EXIT   # KEEP=1: Container zum Nachsehen stehen lassen

echo "== Zertifikate"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=Test CA" -keyout "$T/ca.key" -out "$T/ca.pem" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=greenmail-test" -keyout "$T/gm.key" -out "$T/gm.csr" 2>/dev/null
printf 'subjectAltName=DNS:greenmail-test\n' > "$T/ext"
openssl x509 -req -in "$T/gm.csr" -CA "$T/ca.pem" -CAkey "$T/ca.key" -CAcreateserial -days 1 -extfile "$T/ext" -out "$T/gm.pem" 2>/dev/null
openssl pkcs12 -export -inkey "$T/gm.key" -in "$T/gm.pem" -name greenmail -passout pass:changeit -out "$T/gm.p12"
chmod 755 "$T" && chmod 644 "$T"/*

echo "== Image bauen"
docker build -q -t spamsharp:test . >/dev/null

echo "== Container starten"
docker network create $NET >/dev/null
docker run -d --name greenmail-test --network $NET -v "$T:/certs:ro" \
    -e "GREENMAIL_OPTS=-Dgreenmail.setup.test.all -Dgreenmail.hostname=0.0.0.0 -Dgreenmail.users=test:pw@test.local -Dgreenmail.users.login=email -Dgreenmail.tls.keystore.file=/certs/gm.p12 -Dgreenmail.tls.keystore.password=changeit" \
    greenmail/standalone:2.1.3 >/dev/null
mkdir -p "$T/data"
docker run -d --name spamsharp-test --network $NET -p 127.0.0.1:18083:8080 -v "$T/data:/data" -v "$T:/certs:ro" \
    -e ADMIN_PASSWORD=$PW -e SSL_CERT_FILE=/certs/ca.pem spamsharp:test >/dev/null

# Hilfscontainer für SMTP/IMAP/sqlite; Python liest das Skript von stdin
py() { docker run --rm -i --network $NET -v "$T/data:/data" python:3.13-slim python - "$@"; }

echo "== Warten auf Weboberfläche"
for i in $(seq 60); do curl -fs -o /dev/null -u x:$PW http://127.0.0.1:18083/ && break; sleep 1; done
test "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18083/)" = 401
test "$(curl -s -o /dev/null -w '%{http_code}' -u x:falsch http://127.0.0.1:18083/)" = 401
test "$(curl -s -o /dev/null -w '%{http_code}' -u x:$PW -H 'Origin: http://evil.example' http://127.0.0.1:18083/)" = 403
test "$(curl -s -o /dev/null -w '%{http_code}' -u x:$PW http://127.0.0.1:18083/_framework/blazor.web.js)" = 200
echo "   Login, Origin-Schutz und Blazor-Skript OK"

echo "== Postfach anlegen, Mails einliefern"
py <<'EOF'
import smtplib, sqlite3
GTUBE = "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"
def mail(subj, body): return (f"From: Hans <hans@example.org>\r\nTo: test@test.local\r\nSubject: {subj}\r\n"
    f"Date: Mon, 26 Oct 2026 10:00:00 +0000\r\nMessage-ID: <{subj}@example.org>\r\n\r\n{body}\r\nGruss\r\n").encode()
with smtplib.SMTP("greenmail-test", 3025) as s:
    text = " ".join(f"Wort{i} Treffen Projekt Besprechung Kalender Woche Termin" for i in range(40))  # lang genug zum Lernen
    s.sendmail("hans@example.org", ["test@test.local"], mail("Hallo", text))
    s.sendmail("hans@example.org", ["test@test.local"], mail("Gewinn", GTUBE))
import imaplib
m = imaplib.IMAP4("greenmail-test", 3143); m.login("test@test.local", "pw"); m.create("Spamverdacht"); m.logout()  # wie bei GMX
db = sqlite3.connect("/data/spamsharp.db")
db.execute("insert into accounts(name,host,port,username,password,folder,spamfolder,threshold,enabled) "
           "values('Test','greenmail-test',3993,'test@test.local','pw','INBOX','',6,1)")
db.execute("insert or replace into settings values('interval','10')")
db.commit()
EOF
docker restart spamsharp-test >/dev/null   # Postfach wurde direkt in die DB geschrieben

py <<'EOF'
import imaplib, sqlite3, smtplib, time
def wait(what, fn, timeout=90):
    end = time.time() + timeout
    while time.time() < end:
        try:
            if fn(): print("   OK:", what); return
        except Exception: pass
        time.sleep(2)
    db = sqlite3.connect("/data/spamsharp.db")
    print("   Status:", db.execute("select status from accounts").fetchall())
    print("   Log:", db.execute("select subject, score, action from log").fetchall())
    raise SystemExit("FEHLER: " + what)
def imap():
    m = imaplib.IMAP4("greenmail-test", 3143); m.login("test@test.local", "pw"); return m
def subjects(folder):
    m = imap(); m.select(folder, readonly=True)
    uids = m.uid("SEARCH", None, "ALL")[1][0].split()
    res = [m.uid("FETCH", u, "(FLAGS BODY.PEEK[HEADER.FIELDS (SUBJECT)])")[1][0] for u in uids]
    m.logout()
    return {r[1].decode().strip().removeprefix("Subject: "): r[0].decode() for r in res}
def move(subject, src, dst):
    m = imap(); m.select(src)
    uid = next(u for u in m.uid("SEARCH", None, "ALL")[1][0].split()
               if subject in m.uid("FETCH", u, "(BODY.PEEK[HEADER.FIELDS (SUBJECT)])")[1][0][1].decode())
    m.uid("COPY", uid, dst); m.uid("STORE", uid, "+FLAGS", r"(\Deleted)"); m.expunge(); m.logout()
log = lambda: [r[0] for r in sqlite3.connect("/data/spamsharp.db").execute("select action from log")]

wait("Spam-Ordner automatisch erkannt (Spamverdacht), normale Mail bleibt", lambda: "Gewinn" in subjects("Spamverdacht") and "Hallo" in subjects("INBOX"))
wait("Lernordner angelegt", lambda: imap().select("Spam-lernen")[0] == "OK" and imap().select("Kein-Spam")[0] == "OK")
assert all("\\Seen" not in f for f in {**subjects("INBOX"), **subjects("Spamverdacht")}.values()), "Mails wurden als gelesen markiert"
print("   OK: Mails bleiben ungelesen")

move("Gewinn", "Spamverdacht", "INBOX")
wait("zurückgeholte Mail bleibt im Posteingang", lambda: any(a.startswith("zurückgeholt") for a in log()))
time.sleep(12)
assert "Gewinn" in subjects("INBOX"), "zurückgeholte Mail wurde erneut verschoben"
print("   OK: zurückgeholte Mail bleibt auch nach weiterem Lauf im Posteingang")

move("Hallo", "INBOX", "Spam-lernen")
wait("Lernordner: als Spam gelernt und in den Spam-Ordner verschoben",
     lambda: "Hallo" in subjects("Spamverdacht") and any("als Spam gelernt" in a for a in log()))  # lange Mail: wirklich gelernt
move("Hallo", "Spamverdacht", "Kein-Spam")
wait("Lernordner: als kein Spam gelernt und zurück in den Posteingang",
     lambda: "Hallo" in subjects("INBOX") and any("als kein Spam gelernt" in a for a in log()))
time.sleep(12)
assert "Hallo" in subjects("INBOX"), "als kein Spam gelernte Mail wurde erneut verschoben"
print("   OK: als kein Spam gelernte Mail bleibt im Posteingang")
EOF

echo "== rspamd hat gelernt"
docker exec spamsharp-test rspamc -h 127.0.0.1:11334 stat | grep -q "Messages learned: [1-9]"
echo "   OK: rspamd hat aus den Lernordnern gelernt"
docker exec spamsharp-test sh -c 'test -s /data/redis/dump.rdb || sleep 61; ls /data/redis/dump.rdb' >/dev/null
echo "   OK: redis speichert in /data/redis"
echo "ALLE TESTS BESTANDEN"
