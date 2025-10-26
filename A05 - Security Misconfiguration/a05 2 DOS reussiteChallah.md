# Étape 0 : Vérification
Vérifier que le script est bien placé et accessible via HTTP et que la VM dispose d’un interpréteur Python compatible (le script est en Python2).

## Sous-étapes :
### 1) vérifier le fichier dans le conteneur
docker exec -it bwapp bash -c "ls -l /app/evil/nginx_dos.py || ls -l /var/www/html/evil/nginx_dos.py"

### 2) tester qu'il est servi par le web
curl -I http://127.0.0.1:8081/evil/nginx_dos.py

### 3) vérifier la présence de Python sur la machine hôte/VM
which python3 || true
python3 --version 2>/dev/null || true

## Conclusion en théorie (attendu)
ls -l affiche le fichier dans /app/evil (existe).
curl -I renvoie HTTP/1.1 200 OK.
python2 --version renvoie une version 2.x.
## Conslusion
Fichier présent dans le docker et accesible via le web. Et python 3.12.3

