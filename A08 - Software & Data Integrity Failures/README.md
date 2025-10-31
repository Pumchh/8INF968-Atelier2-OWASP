# A08 — SOFTWARE & DATA INTEGRITY FAILURES

## Introduction et Contexte
**Définition (A08)**  
A08 couvre les défaillances où le logiciel ou les données consommées ne peuvent pas être vérifiées quant à leur intégrité ou provenance. Cela inclut : artefacts mal signés, paquets compromis, builds non reproductibles, mais aussi données d’application (sessions, objets sérialisés, états de panier) acceptées sans vérification. L’impact peut aller d’une simple altération d’UI à une compromission complète de la chaîne d’approvisionnement ou une élévation de privilèges/RCE.

**Pourquoi c’est critique**

Les erreurs d’intégrité permettent l’introduction de code ou d’état malveillant à un point d’exécution (client, serveur, CI, runtime).

Elles sont difficiles à détecter sans mécanismes cryptographiques (signatures, HMAC, checksums vérifiés) ou garanties de provenance (SBOM, attestations).

**Cadre de test (labs PortSwigger / WebSecurity Academy)**
Les démonstrations et preuves qui suivent ont été réalisées sur des labs PortSwigger / WebSecurity Academy fournis en environnement isolé. Ces labs reproduisent deux catégories pratiques d’A08 :

1. Insecure Deserialization — modification d’un objet sérialisé dans un cookie pour escalader des privilèges.

2. Race Conditions (Limit overrun) — envoi de requêtes parallèles pour exploiter une fenêtre de course et appliquer plusieurs fois un coupon.

Ces environnements sont conçus pédagogiquement : les payloads et manipulations ont été effectués uniquement en labo.

## PREMIÈRE VULNÉRABILITÉ — INSECURE DESERIALIZATION
### Résumé

L’application sérialise un objet User dans un cookie côté client et utilise unserialize() (ou équivalent) côté serveur sans vérification d’intégrité. En modifiant le cookie (décodage Base64 → modification → réencodage), un attaquant peut changer des attributs sensibles (ex. admin) et obtenir des privilèges administratifs.

### Preuve de concept (PoC) — résumé des étapes

1. Connexion avec un compte normal (ex. wiener:peter).

2. Récupérer la requête post-login contenant le cookie session.

3. Décoder l’élément du cookie (URL decode → Base64 decode) → obtenir la chaîne PHP sérialisée :
```css
O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;}
```
4. Modifier b:0; → b:1;, ré-encoder et remplacer le cookie dans la requête (Burp Inspector / Repeater).

5. Ré-envoyer → l’application considère l’utilisateur comme admin → accès /admin → suppression d’un compte (preuve / lab solved).

(Joindre captures : cookie original, décodage, modification dans Burp, accès /admin, message de réussite.)

### Pourquoi ça fonctionne (technique)

unserialize() reconstruit les objets PHP exactement tels qu’ils ont été fournis.

Le cookie est non signé : aucune HMAC/GPG/clé secrète ne protège son intégrité.

Le serveur prend des décisions de sécurité basées sur des données contrôlables par le client.

## Correction (remontée — code & process)
1) Solution la plus sûre : sessions côté serveur

- Utiliser $_SESSION (ou store serveur) et ne stocker côté client qu’un identifiant de session opaque.

- Avantage : l’état sensible n’est jamais envoyé au client ; toute modification côté client est indépendante.

2) Si stockage côté client indispensable : signer et vérifier

- Utiliser JSON (ou autre format texte) + HMAC (SHA256) côté serveur.

- Exemple (PHP conceptuel) :
```css
// création
$payload = base64_encode(json_encode($data));
$sig = hash_hmac('sha256', $payload, SECRET_KEY);
setcookie('session', $payload . '.' . $sig, ['httponly'=>true,'secure'=>true]);

// validation
list($payload, $sig) = explode('.', $_COOKIE['session'], 2);
if (!hash_equals(hash_hmac('sha256', $payload, SECRET_KEY), $sig)) {
  // rejet : intégrité rompue
}
$data = json_decode(base64_decode($payload), true);
```
3) Empêcher la reconstruction d’objets via unserialize()

- Si on doit utiliser unserialize(), interdire la création d’objets :
unserialize($data, ["allowed_classes" => false]) ou whitelist explicite des classes autorisées.

- Valider strictement les types/valeurs après désérialisation.

4) Méthodes souples additionnelles

- Chiffrer le cookie (si stockage côté client) mais toujours accompagner d’une signature.

- Mettre HttpOnly, Secure, SameSite=strict et durée de vie courte pour réduire l’impact.

### Vérification post-fix

- Refaire l’altération côté client → serveur doit rejeter (signature invalide / session différente).

- Audit statique pour trouver usages dangereux (unserialize($_COOKIE...)) et remédier.

- Ajouter tests CI qui détectent stockage d’objets sérialisés non protégés.

## DEUXIÈME VULNÉRABILITÉ — RACE CONDITIONS (Limit overrun)

### Résumé

Des opérations concurrentes non synchronisées permettent d’appliquer un coupon plusieurs fois : en envoyant un grand nombre de requêtes POST /cart/coupon en parallèle, plusieurs requêtes passent la vérification (vérif avant mise à jour) avant que le système n’enregistre que le coupon a été appliqué — la réduction est appliquée plusieurs fois, permettant d’acheter un article à un prix très réduit.

### PoC — résumé des étapes

1. Ajouter un article (ex. Jacket à $1337) au panier.

2. Vérifier qu’aucun coupon n’est appliqué.

3. Capturer la requête POST /cart/coupon dans Burp Repeater.

4. Dupliquer la requête en ~20 onglets et envoyer le groupe en parallèle (mode single-packet / parallel).

5. Observer plusieurs réponses “Coupon applied” ; rafraîchir le panier → réduction multiple (total nettement inférieur).

6. inaliser l’achat si le total est inférieur au crédit → lab solved.

(Joindre captures : requête coupon, envoi en parallèle, réponses mixtes, total réduit, ordre final et message “Solved”.)

### Pourquoi ça fonctionne (technique)

- Le serveur vérifie puis met à jour sans verrou/transaction atomique : la séquence if not applied → apply n’est pas atomique.

- Plusieurs threads/processes lisent la même condition avant qu’un seul n’écrive la nouvelle valeur, créant une fenêtre de course.

## Corrections (technique & process)
1) Verrouiller / transaction atomique (recommandé)

- Au niveau base de données utiliser des verrous ou transactions atomiques :

    - SELECT ... FOR UPDATE (row-level lock) puis update et commit.

    - Transaction ACID : lire, valider, appliquer dans une même transaction.

Exemple (SQL pseudo) :
```css
BEGIN;
SELECT applied FROM coupons WHERE user_id = ? FOR UPDATE;
IF applied = false THEN
  UPDATE coupons SET applied = true WHERE user_id = ?;
  -- calcul du montant et enregistrement
END IF;
COMMIT;
```

2) Optimistic locking (versioning)

- Utiliser un champ version/etag : UPDATE ... WHERE id = ? AND version = ? et vérifier la ligne affectée ; si 0 → retry.

3) Opérations idempotentes / token unique

- Générer un idempotency key côté client/commande : serveur ignore doublons (stocke les IDs traités).

- Rendre l’opération d’application de coupon idempotente (la même requête multiple fois produit le même résultat).

4) Sérialisation côté application

- File d’attente ou mutex par panier utilisateur pour sérialiser les modifications concurrentes.

5) Vérification finale au checkout

- Recalculer et valider le prix au moment du paiement en refaisant tous les calculs côté serveur ; ne pas se reposer sur le total affiché côté client.

### Vérification post-fix

- Rejouer l’attaque parallèle → les requêtes supplémentaires doivent échouer ou être ignorées.

- Tests de charge / concurrence automatisés (integration tests) pour vérifier absence de duplication.

- Traces/logs : vérifier que seules des transactions légitimes passent, alerter en cas d’incidents anormaux.

## CONCLUSION & RECOMMANDATIONS GLOBALES

### Synthèse

A08 n’est pas qu’une histoire de « paquets mal signés » ; c’est aussi l’intégrité des données d’application (sessions, états, états d’opérations).

Les deux cas étudiés (désérialisation non sécurisée, race conditions) montrent que l’absence de contrôle d’intégrité ou d’atomicité peut entraîner des impacts sévères (élévation de privilèges, perte financière, compromission).

### Checklist opérationnelle à inclure dans ton rendu

Inventaire & SBOM (liste composants + versions).

Automatisation SCA (Dependency-Check, Snyk, Dependabot).

Signatures & vérifications (HMAC/GPG/Sigstore) pour artefacts et données stockées côté client.

Éviter unserialize() sur données client ; utiliser JSON signé ou sessions serveur.

Concurrence : transactions, verrous, idempotency keys, queueing.

Tests : ajouter tests unitaires / intégration pour désérialisation et scénarios concurrents.

Monitoring & alerting : logs d’événements suspects et alertes CVE.

## PREUVES À FOURNIR (annexes)

Captures PortSwigger/Browser montrant le PoC pour Insecure Deserialization (cookie original → décodé → modifié → accès admin).

Captures Burp montrant l’envoi parallèle pour le lab Race Conditions, réponses, total réduit et ordre final.

Extraits de logs / outputs de dependency-check si applicables.

Snippets de code corrigés (HMAC JSON example, transaction SQL example).

