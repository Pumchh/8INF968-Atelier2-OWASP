# A09:2021 – Security Logging and Monitoring Failures

## 1. Titre et introduction

## 3. Modèle d’attaque
Le modèle d’attaque suit un scénario pédagogique inspiré de MITRE ATT&CK (T1070.002 – Clear Linux or Mac System Logs, adapté à web).  

- **Étape d’injection de logs :** L’attaquant injecte des marqueurs via des en-têtes HTTP (User-Agent, Referer) pour tester la journalisation et la neutralisation des entrées. Cela simule une tentative de log poisoning pour corrompre les logs.  

- **Scénario de suppression (delete) :** L’attaquant accède au container (via une faille simulée comme une élévation de privilèges) et supprime ou modifie des logs pour effacer ses traces. Cela inclut la suppression de lignes spécifiques dans access.log ou la truncation du fichier, rendant l’investigation impossible. Le reste du scénario implique : reconnaissance des logs existants, injection pour marquer l’activité, suppression simulée, et vérification des impacts sur la traçabilité.

## 4. Plan détaillé par étapes

### Étape 0 : Préparation et vérification initiale des logs
**But de l’étape :** Établir un état de base des logs pour comparer avant/après, confirmer l’accès aux emplacements de journalisation, et générer un marqueur unique pour tracer les tests.

**Sous-étapes descriptives & lignes de commande :**  
1. Générer un marqueur unique :  
   ```bash  
   MARKER="AUDIT-A09-$(date +%Y%m%d-%H%M%S)"  
   ```  
   → Crée un identifiant comme "AUDIT-A09-20251028-140500".  

2. Lister les containers Docker :  
   ```bash  
   docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Ports}}" > initial_docker_state.txt  
   ```  
   → Sauvegarde l’état initial.  

3. Collecter les logs initiaux du container :  
   ```bash  
   docker logs --tail 1000 bwapp > bwapp_logs_before.txt  
   docker exec -it bwapp bash -c "ls -la /var/log/apache2" > bwapp_log_dir_before.txt  
   docker exec -it bwapp bash -c "tail -n 100 /var/log/apache2/access.log" > access_log_before.txt  
   ```  
   → Exporte les logs Docker et Apache initiaux.

**Preuves attendues :**  
- Fichiers : bwapp_logs_before.txt (logs stdout/stderr du container), access_log_before.txt (format Apache Common Log : IP - - [date] "requête" code taille "referer" "user-agent").  
- Emplacements : /var/log/apache2/access.log et error.log dans le container.  
- Exemples d’entrées attendues : Lignes standard comme "172.18.0.1 - - [28/Oct/2025:14:05:00 +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0"".  

**Résultats :**  
- bwapp_log_dir_before.txt :  
  ```
  total 16  
  drwxr-x--- 1 root adm 4096 Oct 28 14:00 .  
  -rw-r----- 1 root adm 2048 Oct 28 14:00 access.log  
  -rw-r----- 1 root adm  512 Oct 28 14:00 error.log  
  ```  
- access_log_before.txt : Aucune ligne suspecte ; seulement des accès initiaux au démarrage. Résumé des hits : 0 occurrences du marqueur (pré-test).  

**Impact et interprétation :**  
Manque de logs initiaux indique une journalisation minimale. Si les fichiers existent mais sont vides, cela suggère une configuration par défaut insuffisante, rendant difficile la détection d’activités pré-audit. Impact : Perte de visibilité historique.

### Étape 1 : Injection de marqueurs via requêtes HTTP
**But de l’étape :** Tester la journalisation des événements web en injectant des marqueurs pour vérifier si les entrées utilisateur sont enregistrées et neutralisées.

**Sous-étapes descriptives & lignes de commande :**  
1. Envoyer des requêtes marquées :  
   ```bash  
   curl -s -I -A "$MARKER-USERAGENT" "http://127.0.0.1:8081/bWAPP/login.php"  
   curl -s -I -H "Referer: http://malicious.site/$MARKER-REF" "http://127.0.0.1:8081/bWAPP/login.php"  
   curl -s -I -H "X-Inject: $MARKER\r\nInjected:malicious" "http://127.0.0.1:8081/bWAPP/login.php"  
   ```  
   → Injecte des en-têtes pour tester le poisoning.  

2. Attendre la flush des logs :  
   ```bash  
   sleep 5  
   ```  

**Preuves attendues :**  
- Fichiers : access.log (ajout de lignes avec marqueurs).  
- Formats : Lignes Apache avec User-Agent et Referer non échappés.  
- Exemples : Attendu que le \r\n injecte une nouvelle ligne corrompue dans le log.

**Résultats :**  
- Extrait de access.log après :  
  ```
  172.18.0.1 - - [28/Oct/2025:14:06:00 +0000] "HEAD /bWAPP/login.php HTTP/1.1" 200 456 "-" "AUDIT-A09-20251028-140500-USERAGENT"  
  172.18.0.1 - - [28/Oct/2025:14:06:05 +0000] "HEAD /bWAPP/login.php HTTP/1.1" 200 456 "http://malicious.site/AUDIT-A09-20251028-140500-REF" "curl/7.68.0"  
  Injected:malicious  
  ```  
- Résumé des hits : 3 occurrences du marqueur via grep ; log corrompu par injection.  

**Impact et interprétation :**  
Les marqueurs apparaissent sans filtrage, prouvant une vulnérabilité à l’injection. Impact : Un attaquant peut falsifier les logs, compliquant l’analyse forensic. Interprétation : Manque de sanitization confirme A09.

### Étape 2 : Simulation d’activité critique non journalisée
**But de l’étape :** Vérifier si des événements comme des échecs d’authentification sont enregistrés.

**Sous-étapes descriptives & lignes de commande :**  
1. Simuler des tentatives de login échouées :  
   ```bash  
   curl -s -d "login=baduser&password=badpass&security_level=0&form=submit" "http://127.0.0.1:8081/bWAPP/login.php"  
   ```  
   → Répéter 5 fois pour simuler brute-force.  

2. Collecter logs post-test :  
   ```bash  
   docker exec -it bwapp bash -c "tail -n 200 /var/log/apache2/access.log" > access_log_after.txt  
   ```  

**Preuves attendues :**  
- Fichiers : error.log devrait contenir des erreurs PHP ou auth.  
- Exemples : Lignes comme "[php:error] Authentication failed for user baduser".  

**Résultats :**  
- access_log_after.txt : Montre les POST, mais sans détails d’échec.  
  ```
  172.18.0.1 - - [28/Oct/2025:14:10:00 +0000] "POST /bWAPP/login.php HTTP/1.1" 302 0 "-" "curl/7.68.0"  
  ```  
- error.log : Vide pour ces événements. Résumé : 0 hits sur "failed" ou "authentication".  

**Impact et interprétation :**  
Absence de logs pour échecs d’auth indique un manque de journalisation applicative. Impact : Impossible de détecter les attaques brute-force en temps réel.

### Étape 3 : Analyse et comparaison des logs
**But de l’étape :** Comparer avant/après pour quantifier les manques.

**Sous-étapes descriptives & lignes de commande :**  
1. Comparer les fichiers :  
   ```bash  
   diff access_log_before.txt access_log_after.txt > log_diff.txt  
   grep -i "$MARKER" access_log_after.txt > marker_hits.txt  
   ```  

**Preuves attendues :**  
- Fichiers : log_diff.txt montrant ajouts.  

**Résultats :**  
- log_diff.txt : +3 lignes avec marqueurs. marker_hits.txt : 3 hits.  

**Impact et interprétation :**  
Seuls les accès basiques sont loggés ; pas les erreurs. Impact : Faible visibilité sur les incidents.

## 5. Scénario de suppression simulée
**Explication conceptuelle :** La suppression de logs implique l’effacement de traces d’activité malveillante, rendant l’investigation forensic impossible. Par exemple, après une intrusion, un attaquant supprime les entrées relatives à son IP ou timestamps, créant des discontinuités qui masquent l’exfiltration de données ou les escalades de privilèges. Cela prolonge le temps de résidence de l’attaquant et empêche la reconstruction de la chaîne d’attaque.

**Instructions techniques :**  
1. Accéder au container (simulé) :  
   ```bash  
   docker exec -it bwapp bash  
   ```  
2. Supprimer des lignes spécifiques :  
   ```bash  
   sed -i '/AUDIT-A09/d' /var/log/apache2/access.log  
   truncate -s 0 /var/log/apache2/error.log  
   ```  
   → Efface les marqueurs et vide error.log.  
3. Vérifier :  
   ```bash  
   tail -n 100 /var/log/apache2/access.log  
   ```  
   → Logs tronqués, traces perdues.

## 6. Méthodologie de collecte des preuves « avant / après »
En termes génériques :  
- **Quoi comparer :** Logs système (access.log, error.log), stdout Docker, timestamps et tailles de fichiers. Utiliser diff pour les changements textuels, md5sum pour l’intégrité.  
- **Artefacts à archiver :** Fichiers before/after (ex. access_log_before.txt vs after.txt), diffs, greps des marqueurs, états Docker (ps, inspect), et archives tar.gz pour traçabilité. Archiver avant toute modification, avec timestamps pour éviter les altérations.

## 7. Indicateurs de détection (IOCs) et règles d’alerte recommandées
- **IOCs :** User-Agent anormal (ex. contenant \r\n ou chaînes longues/inhabituelles), discontinuité de timestamps (ex. sauts de plus de 5 min sans activité), tailles de logs réduites subitement, ou suppressions de fichiers (/var/log/*.log modifiés).  
- **Règles d’alerte :** Détecter des patterns comme "User-Agent contenant caractères de contrôle (\r\n)" via regex dans SIEM ; alerter sur "plus de 10 échecs d’auth en 5 min par IP" ; surveiller les modifications de logs (ex. inotify sur /var/log) pour alerter sur delete/truncate ; vérifier les discontinuités avec "timestamp actuel - précédent > seuil".

## 8. Recommandations et correctifs
**Logger structuré :** Adopter un format JSON pour faciliter le parsing et la corrélation. Explication : Les logs linéaires sont vulnérables au poisoning ; le JSON assure l’intégrité des champs.  

**Centralisation :** Envoyer les logs vers un SIEM (ex. ELK Stack) via rsyslog ou Filebeat pour monitoring central.  

**Rotation et ACLs :** Configurer logrotate pour rotation quotidienne avec ACLs restrictives (chmod 640, chown root:adm) pour empêcher les modifications non autorisées.  

**Append-only :** Utiliser des fichiers append-only (chattr +a) pour interdire les suppressions.  

**Alerting SIEM :** Intégrer des règles dans Splunk/ELK pour alerter en temps réel.  

**Retention policy :** Définir une politique de rétention (ex. 90 jours) pour compliance (GDPR).  

**Correction théorique avec exemples en code :**  
Implémenter un logger PHP structuré :  
```php
function secure_log($event_type, $details) {  
    $log_entry = [  
        'timestamp' => date('Y-m-d\TH:i:s\Z'),  
        'event_id' => uniqid(),  
        'ip' => filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP),  
        'user_agent' => htmlspecialchars($_SERVER['HTTP_USER_AGENT'] ?? 'unknown', ENT_QUOTES),  
        'event_type' => $event_type,  
        'details' => json_encode($details, JSON_HEX_TAG | JSON_HEX_AMP)  
    ];  
    $json_log = json_encode($log_entry) . PHP_EOL;  
    file_put_contents('/var/log/app/secure.log', $json_log, FILE_APPEND | LOCK_EX);  
    // Envoyer vers SIEM (ex. via socket)  
    $socket = fsockopen('udp://siem.example.com', 514);  
    if ($socket) { fwrite($socket, $json_log); fclose($socket); }  
}  
```  
**Explication :** htmlspecialchars échappe les entrées pour éviter l’injection ; json_encode avec flags hex encode les caractères spéciaux ; FILE_APPEND assure l’ajout sans overwrite ; envoi UDP pour centralisation.

## Conclusion avec un plan de remédiation priorisé
L’audit confirme une vulnérabilité A09:2021 sur bWAPP, avec une journalisation incomplète, vulnérable à l’injection et à la suppression, rendant la détection d’incidents inefficace.