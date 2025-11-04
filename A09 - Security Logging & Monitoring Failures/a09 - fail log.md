# A09:2021 – Security Logging and Monitoring Failures

## Introduction
Cette catégorie regroupe les failles liées à l’absence ou à l’insuffisance de journalisation et de surveillance des activités de sécurité dans les applications et serveurs.
Elle occupe cette position car la détection et la réponse aux attaques sont souvent négligées, bien que cruciales pour la traçabilité, la visibilité et la gestion des incidents.
Avec un taux d’incidence moyen de 6.51%, un total de 53 615 occurrences et 242 CVE recensées, cette vulnérabilité reste fréquente malgré sa criticité.
Elle découle souvent d’événements non enregistrés (comme les échecs de connexion) ou de logs non surveillés, empêchant la détection rapide d’intrusions actives.

---

# Étape 0 : Vérification des logs existants

**Sous-étapes :**
1. Rechercher les répertoires de logs sur l’hôte :  
   ```bash
   ls /var/log/apache2
   ls /var/log/httpd
   ```
   → Aucun répertoire trouvé sur l’hôte.

2. Vérifier à l’intérieur du container bWAPP :  
   ```bash
   docker exec -it bwapp bash -c "ls -la /var/log/apache2"
   ```
   **Résultat obtenu :**
   ```
   total 12
   drwxr-x--- 1 root adm  4096 ...
   -rw-r----- 1 root adm  1890 access.log
   -rw-r----- 1 root adm   532 error.log
   ```
   → Présence confirmée des fichiers `access.log` et `error.log`.

**Attendu :** accès possible aux logs internes du container.  
**Observé :** logs présents et lisibles dans `/var/log/apache2`.

---

# Étape 1 : Création du script d’audit `collect_a09.sh`

Ce script a pour but de :

- générer un identifiant unique (MARKER) pour tracer les requêtes,  
- envoyer automatiquement des requêtes HTTP marquées,  
- collecter les fichiers de logs avant et après,  
- compresser le tout pour analyse.

## Lignes de commande principales :

1. **Génération du marqueur**
   ```bash
   MARKER="LOGTEST-$(date +%Y%m%d-%H%M%S)"
   ```
   → Produit un identifiant unique comme `LOGTEST-20251026-182903`.

2. **Liste des containers et état initial**
   ```bash
   docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Ports}}"
   ```
   → Affiche les containers en cours et sauvegarde l’état initial dans `docker_ps.txt`.

3. **Collecte initiale des logs**
   ```bash
   docker logs --tail 1000 bwapp > bwapp_docker_logs_before.txt
   docker exec bwapp bash -c "ls -la /var/log/apache2" > bwapp_var_log_listing.txt
   ```
   → Exporte les logs système et confirme la présence des fichiers internes.

4. **Envoi des requêtes marquées**
   ```bash
   curl -s -I -A "$MARKER-USERAGENT" "http://127.0.0.1:8081/bWAPP/login.php"
   curl -s -I -H "Referer: http://evil.example/$MARKER-REF" "http://127.0.0.1:8081/bWAPP/login.php"
   curl -s -I -H "X-Test: $MARKER-HEADER" "http://127.0.0.1:8081/bWAPP/login.php"
   ```
   → Ces commandes utilisent des en-têtes HTTP personnalisés pour insérer le marqueur dans les logs.

5. **Test d’injection (log poisoning)**
   ```bash
   curl -s -I -H $'X-Inject: '"$MARKER$'\r\nInjected:bad'" "http://127.0.0.1:8081/bWAPP/login.php"
   ```
   → Injection de caractères de contrôle (`\r\n`) pour tester la neutralisation des logs (uniquement en labo).

6. **Extraction post-attaque**
   ```bash
   docker exec bwapp bash -c "tail -n 500 /var/log/apache2/access.log" > bwapp_after_access.log
   docker exec bwapp bash -c "tail -n 500 /var/log/apache2/error.log" > bwapp_after_error.log
   ```

7. **Analyse automatique des marqueurs**
   ```bash
   grep -i "$MARKER" -R a09_logs_$MARKER > summary_marker_hits.txt
   ```

8. **Compression des résultats**
   ```bash
   tar -czf a09_logs_$MARKER.tar.gz a09_logs_$MARKER
   ```

## Explication du fonctionnement global du script :
Le script exécute une boucle sur tous les containers listés, vérifie leur présence, récupère leurs logs avant attaque, puis envoie des requêtes avec un marqueur unique.  
Après les requêtes, il réextrait les logs (« après ») et cherche le marqueur.  
Il produit enfin une archive `.tar.gz` contenant toutes les preuves : logs avant/après, extraits grep, rapports Docker et état réseau.

**Attendu :** génération automatique des preuves pour audit.  
**Observé :** archive créée (`a09_logs_LOGTEST-20251026-182903.tar.gz`).

---

# Étape 2 : Envoi et observation des requêtes marquées

**Sous-étapes :**
- Envoi des requêtes HEAD avec les headers contrôlés (User-Agent, Referer, X-Test, X-Inject).  
- Attente de 2 secondes pour permettre la rotation des logs.  
- Re-collecte complète.

**Résultat dans access.log :**
```
172.18.0.1 - - [26/Oct/2025:22:29:20 +0000] "HEAD /bWAPP/login.php HTTP/1.1" 404 139 "-" "LOGTEST-20251026-182903-USERAGENT"
172.18.0.1 - - [26/Oct/2025:22:29:20 +0000] "HEAD /bWAPP/login.php HTTP/1.1" 404 139 "http://evil.example/LOGTEST-20251026-182903-REF" "curl/8.5.0"
```

**Attendu :** apparition du marqueur dans les logs applicatifs (`access.log` et `error.log`).  
**Observé :**
- marqueur trouvé uniquement dans `access.log`,  
- rien dans `error.log` ni dans `docker logs`.

---

# Étape 3 : Collecte et analyse des logs

**Sous-étapes :**
- Lecture et comparaison « avant / après » :  
  - `bwapp_docker_logs_before.txt` : uniquement le démarrage de MySQL et Apache.  
  - `bwapp_docker_logs_after.txt` : identique, aucune ligne liée aux requêtes.  
  - `bwapp_after_access.log` : contient bien le marqueur.  
  - `bwapp_after_error.log` : aucune trace.

- Génération automatique du résumé (`summary_marker_hits.txt`).

**Attendu :** traces dans plusieurs logs.  
**Observé :** seulement `access.log` montre le marqueur → **A09 confirmé.**

---

# Étape 4 : Analyse technique de la vulnérabilité

- **Manque de journalisation applicative :** aucun enregistrement des événements de connexion, erreurs d’authentification ou d’activité utilisateur.
- **Absence d’alerting :** aucune alerte en cas de requêtes suspectes.
- **Entrées non neutralisées :** champs `User-Agent` et `Referer` apparaissent tels quels dans `access.log`, prouvant une absence de filtrage.

**Risques :**
- Difficile d’investiguer une attaque après coup.  
- Possibilité de corrompre ou d’injecter dans les logs (log poisoning).

**Conclusion technique :**  
bWAPP présente une vulnérabilité claire correspondant à **A09:2021 – Security Logging & Monitoring Failures.**

---

# Étape 5 : Préparation du correctif

**Sous-étapes :**
- Création d’un logger applicatif (`app_log()` en PHP).  
- Adoption du format JSON pour lecture et corrélation automatiques.  
- Ajout d’un encodage des entrées utilisateur avant écriture.  
- Intégration d’un envoi des logs vers un collecteur (ELK / rsyslog).

## Code PHP proposé
```php
function app_log($user, $action, $outcome, $details = []) {
    $entry = [
        'ts' => gmdate('Y-m-d\TH:i:s\Z'),
        'request_id' => bin2hex(random_bytes(8)),
        'user' => substr($user ?? 'anon', 0, 64),
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'action' => $action,
        'outcome' => $outcome,
        'ua' => mb_substr(($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 512),
        'details' => $details
    ];
    $json = json_encode($entry, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
    file_put_contents('/var/log/app/app_structured.log', $json . PHP_EOL, FILE_APPEND | LOCK_EX);
}
```

## Explication du code :
- Chaque appel à `app_log()` écrit une entrée JSON sur une seule ligne.  
- `random_bytes()` génère un identifiant unique de requête.  
- Les champs sont tronqués et encodés pour éviter les injections.  
- Le fichier `/var/log/app/app_structured.log` devient append-only et exploitable par un SIEM.

---

# Étape 6 : Vérification post-remédiation (à faire)

**Sous-étapes prévues :**
- Déployer la fonction `app_log()` dans bWAPP.  
- Relancer le script `collect_a09.sh`.  
- Vérifier la présence d’entrées JSON dans `/var/log/app/app_structured.log`.  
- Confirmer l’apparition des alertes dans le collecteur central.

**Attendu :** logs complets, codés et sécurisés.  
**Observé :** test à exécuter après déploiement du correctif.

---

# Conclusion finale

La vulnérabilité **A09** est confirmée sur bWAPP.  
L’application ne journalise pas les actions critiques et n’alerte pas en cas d’activité anormale.

Le correctif recommandé repose sur :
- la mise en place d’un logger structuré,  
- la centralisation et la surveillance des logs,  
- la définition d’alertes automatiques.

**Résultat attendu après correction :**  
Chaque action sensible (connexion, modification, upload) produit une entrée JSON fiable, consultable et corrélée dans un tableau de bord de sécurité.

# Rapport — A09:2021 Security Logging & Monitoring Failures  
**Environnement** : VM Docker. Tests exécutés avec marqueur `LOGTEST-20251026-182903`. Applications présentes : bWAPP (port 8081), DVWA (4280), WebGoat (8080), Juice-Shop (3000).  
---

## Sommaire
1. Contexte et objectifs  
2. Résumé exécutif  
3. Méthodologie de test (script & actions)  
4. Analyse détaillée par application (avant / après)  
5. Comparaison inter-application (tableau + observations)  
6. Preuves (extraits de logs)  
7. Interprétation technique et impact  
8. Correctif proposé (approche, tests, code d’illustration)  
9. Plan de validation après remédiation  
10. Annexes (fichiers analysés, commandes utiles)

---

## 1. Contexte et objectifs
But du projet : montrer et corriger des vulnérabilités du Top-10 OWASP (A09). Objectif spécifique ici : démontrer l’absence de journalisation applicative, la possibilité de log-poisoning et l’absence d’alerting pour bWAPP et comparer le comportement attendu vs observé pour DVWA, WebGoat, Juice-Shop.

---

## 2. Résumé exécutif
- Preuve fournie que bWAPP n’émet que des traces HTTP (`access.log`) pour les requêtes marquées et n’a pas de logs applicatifs visibles ou d’alerting actif.  
- Les champs contrôlés par l’utilisateur (User-Agent, Referer) sont enregistrés tels quels dans `access.log`, démontrant un risque de **CWE-117 / CWE-532**.  
- Docker logs sont limités à l’initialisation (supervisor / MySQL / Apache) et n’indiquent pas d’événements applicatifs significatifs.

Conclusion : A09 reproductible sur bWAPP. Recommandations inclues ci-dessous.

---

## 3. Méthodologie de test (rappel)
Actions exécutées automatiquement par le script fourni :
- génération d’un marqueur unique `MARKER=LOGTEST-YYYYMMDD-HHMMSS`  
- dump `docker ps` et `docker logs` avant tests  
- envoi de requêtes marquées (User-Agent, Referer, header X-Test) vers endpoints (bWAPP/DVWA/WebGoat/Distracted)  
- tentative contrôlée d’injection d’en-tête `X-Inject` pour tester corruption de log  
- collecte `docker logs` et extraction des `access.log`/`error.log` internes si présents  
- production d’un résumé `summary_marker_hits.txt` et d’une archive.  

---

## 4. Analyse détaillée par application

### bWAPP — résultats « avant / après »
- `docker logs` (before/after) n’affichent que l’initialisation de MySQL et Apache. Pas d’événements métiers ni d’audit applicatif.  
- `error.log` contient seulement les notices de démarrage d’Apache. Aucune erreur liée aux actions testées.  
- `access.log` contient les requêtes marquées :  
  ```
  172.18.0.1 - - [26/Oct/2025:22:29:20 +0000] "HEAD /bWAPP/login.php HTTP/1.1" 404 139 "-" "LOGTEST-20251026-182903-USERAGENT"
  172.18.0.1 - - [26/Oct/2025:22:29:20 +0000] "HEAD /bWAPP/login.php HTTP/1.1" 404 139 "http://evil.example/LOGTEST-20251026-182903-REF" "curl/8.5.0"
  ```

### DVWA / WebGoat / Juice-Shop — à compléter
Collecter les mêmes fichiers (`*_docker_logs_after.txt`, `*_access_tail.txt`, `*_error_tail.txt`) pour ces containers et répéter l’analyse.

---

## 5. Comparaison inter-application
| App | access.log | error.log | app logs (auth/events) | headers logged raw | docker stdout | alerting |
|-----|-------------|-----------|------------------------|--------------------|----------------|-----------|
| bWAPP | oui (hits) | oui (startup only) | non | oui (User-Agent/Referer) | init only | non |
| DVWA | à remplir | à remplir | à remplir | à remplir | à remplir | à remplir |
| WebGoat | à remplir | à remplir | à remplir | à remplir | à remplir | à remplir |
| Juice-Shop | à remplir | à remplir | à remplir | à remplir | à remplir | à remplir |

---

## 6. Interprétation technique et impact
- **Manque d’auditabilité** : pas de logs applicatifs, donc incapacité à reconstituer sessions utilisateur ou détecter motifs d’attaque.  
- **Log poisoning** : champs contrôlés par l’utilisateur apparaissent bruts dans `access.log`.  
- **Absence d’alerting** : même tests automatisés (script) n’ont déclenché aucune alerte.

Impact : période d’exfiltration prolongée possible, difficultés d’investigation, amendes potentielles.

---

## 7. Correctif proposé — approche, tests et code

### Approche
1. Activer logs applicatifs (login_success/failure, changement mot de passe, uploads, admin actions).  
2. Structurer les logs (format JSON line, échappement).  
3. Centraliser via rsyslog/TLS vers collecteur (ELK/EFK).  
4. Définir règles d’alerte (échecs multiples, champs suspects).  
5. Intégrité (append-only ou signature).

### Exemple de logger PHP
```php
function app_log($user, $action, $outcome, $details = []) {
    $entry = [
        'ts' => gmdate('Y-m-d\TH:i:s\Z'),
        'request_id' => bin2hex(random_bytes(8)),
        'user' => substr($user ?? 'anon', 0, 64),
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'action' => $action,
        'outcome' => $outcome,
        'ua' => mb_substr(($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 512),
        'details' => $details
    ];
    $json = json_encode($entry, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
    file_put_contents('/var/log/app/app_structured.log', $json . PHP_EOL, FILE_APPEND | LOCK_EX);
}
```

### Tests post-correctif
- Vérifier que chaque action produit une ligne JSON.  
- Tester injection CR/LF : vérifier que le log reste lisible et structuré.  
- Vérifier réception sur collecteur central et déclenchement d’alerte.  

---

## 8. Validation après remédiation
- [ ] Logs applicatifs générés pour chaque action.  
- [ ] Champs contrôlés encodés/tronqués.  
- [ ] Logs centralisés et protégés.  
- [ ] Alertes fonctionnelles.  
- [ ] Intégrité (append-only / HMAC).  
- [ ] Script marqueur renvoie hits sur collecteur.

---

## 9. Annexes
- Extraits : `access.log` (avec marqueur), `error.log` (aucun événement), `docker logs` (initialisation).  
- Commandes :  
  ```bash
  docker exec bwapp bash -c "tail -n 500 /var/log/apache2/access.log"
  grep -i LOGTEST-20251026-182903 -R .
  docker logs --tail 500 bwapp
  ```
