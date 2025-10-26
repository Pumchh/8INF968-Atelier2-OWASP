
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
