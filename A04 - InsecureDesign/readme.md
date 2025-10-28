# Insecure Design

## Présentation
Une faille d’Insecure Design survient quand une protection n’a pas été pensée dès la conception : la logique métier ou l’architecture laisse des possibilités d’abus (on fait confiance au client, pas au serveur).  
Ici j’ai testé deux cas en labo : bypass de CAPTCHA (DVWA) et IDOR / modification du secret d’un autre utilisateur (bWAPP).

## Test 1 — Bypass du CAPTCHA (DVWA)

Objectif : vérifier si le changement de mot de passe peut être effectué sans résoudre le captcha.

Preuve
- Requête initiale :  
  ![Captcha](8INF968-Atelier2-OWASP\A04 - InsecureDesign\Captcha1.png)  
  (formulaire + param step=2 et champs mot de passe)

- Requête modifiée via Burp (on force le step et on soumet) :  
  ![Captcha](8INF968-Atelier2-OWASP\A04 - InsecureDesign\Captcha2.png)

- Résultat : mot de passe modifié sans validation du captcha :  
  ![Captcha](8INF968-Atelier2-OWASP\A04 - InsecureDesign\Captcha3.png)

### Analyse
- La logique se fie à des paramètres envoyés côté client (step) et/ou n’effectue pas de vérification serveur du token captcha.
- C’est une erreur de conception : le serveur doit valider le captcha et maintenir l’état côté serveur.

### Remédiation
1. Vérifier le token captcha côté serveur (ex. API reCAPTCHA) avant toute action sensible.  
2. Stocker en session un drapeau captcha_verified uniquement après vérification réussie.  
3. Ajouter un CSRF token sur le formulaire et invalider captcha_verified après usage. Un CSRF token est un jeton unique généré par le serveur et inclus dans les formulaires ou requêtes pour vérifier que l’action provient bien de l’utilisateur légitime, empêchant ainsi les attaques de type Cross-Site Request Forgery (CSRF).
4. Journaliser et appliquer un rate-limit sur l’endpoint.

### Extrait de code pour remédiation
Pour remédier à cette faille, il va falloir faire une vérification côté serveur pour valider la résolution du Captcha.

```php
// Vérif token captcha côté serveur
session_start();
$token = $_POST['g-recaptcha-response'] ?? '';
if (empty($token)) { http_response_code(400); exit; }

$secret = 'TA_CLE_SECRETE';
$resp = json_decode(file_get_contents(
  "https://www.google.com/recaptcha/api/siteverify?secret=".urlencode($secret)."&response=".urlencode($token)
), true);

if (empty($resp['success'])) { http_response_code(403); echo "Captcha invalide"; exit; }

$_SESSION['captcha_verified'] = true;
```

La correction permet lors de l'envoie de la requête de changement de mot de passe sans token ou avec token invalide d'envoyer une réponse 403 (accès interdit) et de vérifier que l’action ne passe que si captcha_verified en session est présent et valide ainsi que le CSRF soit bon.



## Test 2 — IDOR / modification d’un autre utilisateur (bWAPP)

Objectif : vérifier si, connecté en tant que Test, on peut modifier le secret d’un autre utilisateur en changeant le paramètre de requête.

Preuve
- Création utilisateur Test :  
  ![bWapp](8INF968-Atelier2-OWASP\A04 - InsecureDesign\bWapp1.png)

- Envoi de la requête de modification (param user ou uid) :  
  ![bWapp](8INF968-Atelier2-OWASP\A04 - InsecureDesign\bWapp2.png)

- Modification du paramètre pour viser un autre compte et envoi :  
  ![bWapp](8INF968-Atelier2-OWASP\A04 - InsecureDesign\bWapp3.png)

- Résultat : secret modifié pour l’autre compte :  
  ![bWapp](8INF968-Atelier2-OWASP\A04 - InsecureDesign\bWapp4.png)


### Analyse
- L’application accepte un identifiant fourni par le client sans vérifier l’ownership ou les droits.
- Erreur de conception : contrôles d’accès object-level manquants.

### Remédiation
1. Toujours vérifier côté serveur que l’utilisateur courant est propriétaire ou a le rôle nécessaire avant lecture/modification.  
2. Centraliser la logique d’autorisation (middleware / fonction authorize).  
3. Logguer les accès refusés et envisager IDs non-prévisibles (UUID) en complément.

Extrait PHP

```php
session_start();
$current = $_SESSION['user_id']; // id connecté
$target = $_POST['user_id'] ?? null;

// récupérer $owner_id depuis la BDD pour la ressource ciblée
// exemple simplifié : $owner_id = get_owner_id($target);
if ($owner_id !== $current && $_SESSION['role'] !== 'admin') {
    http_response_code(403);
    echo "403 Forbidden";
    exit;
}
// sinon autoriser la modification
```

En tant que User A, le fait de tenter de modifier la ressource de User B fais que le serveur renvoie 403 et la ressource reste inchangée.


## Conclusion
Les deux démonstrations ont la même racine : on fait confiance au client (paramètres / états) au lieu d’imposer toutes les vérifications côté serveur.  
Les remédiations consistent en valider côté serveur (captcha, ownership), utiliser CSRF tokens, centraliser les checks d’autorisation et journaliser les tentatives.


