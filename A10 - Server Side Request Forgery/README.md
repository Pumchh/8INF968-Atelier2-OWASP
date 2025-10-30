# Server Side Request Forgery

## Présentation

### Description

La SSRF (Server-Side Request Forgery) se produit lorsqu’une application web récupère des ressources distantes en se basant sur une URL fournie par l’utilisateur, sans valider correctement cette URL. L’application agit alors comme un proxy et peut être forcée à effectuer des requêtes vers des ressources internes ou externes que l’attaquant ne pourrait pas contacter directement.
Ces attaques permettent des accès non autorisé à des services internes (API privées, métadonnées cloud, bases de données administratives), ou encore des exfiltration d’informations.

## Quelques statistiques

D'après l’OWASP Top-10 2021, la catégorie "Server Side Request Forgery" a été testée sur 67.72 % des applications étudiées, avec ~9500 occurrences détectées et des taux d’incidence moyens d'environ 2.72 %. 

## Exemples d'utilisation

### 1. Accès à des ressources privées et utilisation comme proxy
 html viewer mais il a accès au réseau et si on connait l'url, on peut accéder à des ressources privées

Le site suivant permet d'afficher le code HTML et donne un aperçu du site.

<img src="SSRF_UseAsProxy.png" width=600/>

Ici on peut utiliser le site comme un proxy qui va exécuter pour nous les injections ou autres attaques sur un autre site. Dans l'exemple précédent, on pouvait attaquer WebGoat.

Mais il est aussi possible d'attaquer le site lui-même ou des sites privés situés sur son réseau auquel il fait parti. On va par exemple regarder les informations réseau du site en allant sur ```http://ifconfig.pro```

<img src="SSRF_StealInfo.png" width=600/>

Avec ces informations on peut chercher d'autres cibles sur le réseau privé puis les attaquer par le site de liseur html. Cela peut permettre de récupérer des informations qui était pourtant protégées.

<img src="SSRF_UseBecauseItHasAccess.png" width=600/>

Enfin, il est aussi possible de viser le site lui-même en téléchargeant notre propre malware.

<img src="SSRF_InstallMalware.png" width=600/>


### 2. Récupération de données non publiques

Ici on est sur un site qui effectue une action en fonction de notre rôle.

<img src="Change_URL-Ressource1.png" width=600/>

Normalement l'utilisateur lambda devrait recevoir une image de Tom.

<img src="Change_URL-Ressource2.png" width=600/>

Cependant, s'il on utilise un proxy (ici on utilise Burp), on remarque que l'on peut modifier l'url demandé qui vise l'image de Tom.

<img src="Change_URL-Ressource3.png" width=600/>

Si l'on sait ce que l'admin devrait avoir, on peut changer l'URL dans le proxy avant l'envoi pour se faire passer pour l'admin, au moins pour cette action. Ici on suppose que l'admin devrait voir Jerry, on va donc essayer.

<img src="Change_URL-Ressource4.png" width=600/>

On reçoit bien ce que seul l'admin devrait recevoir.


## Comment se défendre de ces attaques ?

### 

#### Avant



#### Après correction



### 

#### Avant



#### Après correction

