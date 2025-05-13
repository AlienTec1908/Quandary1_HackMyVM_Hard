# Quandary1 - HackMyVM (Hard)

![Quandary1.png](Quandary1.png)

## Übersicht

*   **VM:** Quandary1
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Quandary1)
*   **Schwierigkeit:** Hard
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 12. April 2023
*   **Original-Writeup:** https://alientec1908.github.io/Quandary1_HackMyVM_Hard/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "Quandary1" zu erlangen. Der Weg dorthin begann mit der Enumeration von Webdiensten, wobei Splunk (Port 8000/8089) und ein DirectAdmin-Panel (VHost `directadmin.quandary.hmv`) entdeckt wurden. Das Passwort für den DirectAdmin-Benutzer `admin` (`qazxsw`) wurde per Brute-Force gefunden. Im DirectAdmin-Dashboard wurde ein unvollständiges privates SSH-Schlüsselfragment für den Benutzer `lawrence` sowie dessen öffentlicher Schlüssel gefunden. Mittels `RsaCtfTool` konnte der private Schlüssel rekonstruiert werden, was SSH-Zugriff als `lawrence` ermöglichte. Im Home-Verzeichnis von `admin` (auf das `lawrence` Lesezugriff hatte) wurde eine Datei `cred` mit hex-kodierten Credentials (`admin:w5VJ9i#3!os`) gefunden. Mit diesen konnte sich als `admin` per SSH angemeldet werden. Die finale Rechteausweitung zu Root gelang durch Ausnutzung einer unsicheren `sudo`-Regel, die `admin` erlaubte, `snap install *` ohne Passwort auszuführen. Durch Erstellen und Installieren eines bösartigen Snap-Pakets wurde ein neuer Benutzer mit `sudo`-Rechten angelegt, was den Root-Zugriff ermöglichte.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `curl` (implizit)
*   `wfuzz`
*   `hydra`
*   `nano`
*   Base64 Decoder (implizit)
*   `xxd`
*   `tr`
*   `apt`
*   `git`
*   Python3
*   `pip`
*   `RsaCtfTool`
*   `hash-identifier`
*   `hashid`
*   CyberChef (extern)
*   `ssh`
*   `sudo`
*   `snap`
*   Standard Linux-Befehle (`cat`, `echo`, `ls`, `whoami`, `id`, `chmod`, `su`, `pwd`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Quandary1" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web/Service Enumeration:**
    *   IP-Adresse des Ziels (192.168.2.126) mit `arp-scan` identifiziert. Hostname `quandary.hmv` in `/etc/hosts` eingetragen.
    *   `nmap`-Scan offenbarte Port 22 (SSH), 80 (HTTP, Apache "Under Construction"), 8000 (HTTP, Splunkd Login) und 8089 (HTTPS, Splunkd Management, Version 7.1.9).
    *   Auf Port 80 wurde die E-Mail `admin@quandary.hmv` gefunden. In Splunk-Antworten (Port 8000) wurde der Hinweis `"password": "Remote-Passwort"` entdeckt.
    *   Mittels `wfuzz` VHost-Enumeration wurde `directadmin.quandary.hmv` gefunden und in `/etc/hosts` eingetragen.
    *   Mit `hydra` wurde das Passwort für den `admin`-Benutzer auf `http://directadmin.quandary.hmv/login.php` zu `qazxsw` gebruteforced.

2.  **Initial Access (SSH als `lawrence` via DirectAdmin & SSH Key Reconstruction):**
    *   Nach dem Login in DirectAdmin (`admin:qazxsw`) wurde im Dashboard ein unvollständiges privates SSH-Schlüsselfragment und der vollständige öffentliche SSH-Schlüssel für den Benutzer `lawrence@quandary` gefunden.
    *   Das Base64-kodierte Fragment wurde manuell korrigiert/geparst und der relevante Hex-Teil (`ssh_magic`) extrahiert.
    *   Mittels `RsaCtfTool` (`python3 RsaCtfTool.py -q 0x$(cat ssh_magic) -e 65537 -n [MODULUS_AUS_PUBKEY] --private --output idmy`) wurde der private Schlüssel von `lawrence` erfolgreich rekonstruiert.
    *   Erfolgreicher SSH-Login als `lawrence` mit dem rekonstruierten Schlüssel.

3.  **Privilege Escalation (von `lawrence` zu `admin` via Credential Leak):**
    *   Als `lawrence` wurde im Verzeichnis `/home/admin/splunk-backup/` die lesbare Datei `cred` gefunden.
    *   Der Inhalt von `cred` war ein Hex-String (`6164...73`), der zu `admin:w5VJ9i#3!os` dekodiert wurde.
    *   Erfolgreicher SSH-Login als `admin` mit dem Passwort `w5VJ9i#3!os`.
    *   Die User-Flag (`491af4faeac2a53adf47f2642ab7a769`) wurde in `/home/admin/user.txt` gefunden.

4.  **Privilege Escalation (von `admin` zu `root` via `sudo snap install`):**
    *   `sudo -l` als `admin` zeigte, dass `/usr/bin/snap install *` als `root` ohne Passwort ausgeführt werden durfte: `(ALL : ALL) NOPASSWD: /usr/bin/snap install *`.
    *   Ein bösartiges Snap-Paket (`payload.snap`) wurde auf dem Zielsystem in `/tmp` erstellt. Der Base64-kodierte Payload dieses Pakets enthielt Befehle, um einen neuen Benutzer `dirty_sock` mit dem Passwort `dirty_sock` zu erstellen, ihn zur `sudo`-Gruppe hinzuzufügen und einen entsprechenden `sudoers`-Eintrag zu generieren.
    *   Das bösartige Snap wurde mit `sudo snap install /tmp/payload.snap --dangerous --devmode` installiert.
    *   Mit `su dirty_sock` (Passwort: `dirty_sock`) wurde zum neuen Benutzer gewechselt.
    *   Mittels `sudo bash` (Passwort: `dirty_sock`) wurde eine Root-Shell erlangt.
    *   Die Root-Flag (`3b6c2400f61971aca564a57dc35335bd`) wurde in `/root/root.txt` gefunden.

## Wichtige Schwachstellen und Konzepte

*   **Schwache Web-Login-Credentials:** Das Passwort für DirectAdmin (`admin:qazxsw`) konnte gebruteforced werden.
*   **Information Disclosure (SSH Key Fragment):** Teile eines privaten SSH-Schlüssels und der vollständige öffentliche Schlüssel wurden im DirectAdmin-Panel preisgegeben, was die Rekonstruktion des privaten Schlüssels ermöglichte.
*   **Klartext-Credentials in Datei:** Hex-kodierte Zugangsdaten (`admin:w5VJ9i#3!os`) wurden in einer Backup-Datei gefunden.
*   **Unsichere `sudo`-Regel (`snap install`):** Ein Benutzer durfte `snap install *` als Root ohne Passwort ausführen, was das Installieren bösartiger Snap-Pakete und somit Root-Eskalation ermöglichte (Dirty Sock ähnlicher Vektor).
*   **VHost Enumeration:** Auffinden der Subdomain `directadmin.quandary.hmv`.

## Flags

*   **User Flag (`/home/admin/user.txt`):** `491af4faeac2a53adf47f2642ab7a769`
*   **Root Flag (`/root/root.txt`):** `3b6c2400f61971aca564a57dc35335bd`

## Tags

`HackMyVM`, `Quandary1`, `Hard`, `DirectAdmin`, `Web Brute-Force`, `SSH Key Reconstruction`, `RsaCtfTool`, `Information Disclosure`, `sudo Exploit`, `snap install Exploit`, `Dirty Sock`, `Linux`, `Web`, `Privilege Escalation`, `Apache`, `Splunk`
