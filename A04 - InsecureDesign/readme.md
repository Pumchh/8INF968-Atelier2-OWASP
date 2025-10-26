
# Insecure Design

## Présentation

Un système Insecure Design est lorsque les protections nécessaires contre certaines menaces n’ont jamais été prévues dans le modèle de sécurité de l’application. C’est lorsque le concept même de la fonctionnalité est mal conçu pour résister aux attaques.

## Test sur DVWA

Sur DVWA, cela peut-être présenté dans la partie Captcha. Nous allons pouvoir essayer de passer le Captcha sans le résoudre.
Nous allons utiliser Burp suite et analyser le trafic.

![Captcha](Captcha1.png)

Voilà la requête originale envoyé lorsque que l'utilisateur change le mot de passe et valide le Captcha.

Nous voyons que les mots de passe ont la valeur "new-password" et que step est à "2". 

Nous allons essayer d'envoyer une requête contenant la valeur 2 et un nouveau mot de passe.

![Captcha bypass](Captcha2.png)

Et lorsque nous envoyons la requête modifié, voici le résultat :
![Captcha bypass result](Captcha3.png)

Ainsi, la requête a pu être envoyé et le mot de passe modifié sans valider le captcha.




