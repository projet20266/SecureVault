# SecureVault

Coffre de mots de passe chiffré dans le navigateur, sans email à l'inscription.

## Démarrer en local

```sh
node server.js
```

Ouvre ensuite [http://localhost:3000/](http://localhost:3000/) pour la page d'accueil ou [http://localhost:3000/app](http://localhost:3000/app) pour le coffre. WebCrypto nécessite HTTPS en production (localhost est accepté en développement).

## Ce qui fonctionne dans l'interface

- création d'un compte avec un numéro aléatoire généré par le navigateur ;
- ouverture et chiffrement du coffre en AES-GCM avec une clé dérivée par PBKDF2 ;
- ajout, recherche, affichage/masquage et suppression d'accès ;
- générateur de mots de passe via `crypto.getRandomValues` ;
- vérification locale des mots de passe faibles et réutilisés ;
- verrouillage manuel et automatique ;
- navigation vers l'accueil et la page de confidentialité.

Le panneau d'interface conserve le thème de connexion d'origine. L'outil de chiffrement de fichiers/dossiers a été retiré. Les fonctions de récupération, TOTP, extension et paiements ne sont pas annoncées comme actives dans cette version de l'interface tant que leurs parcours complets n'ont pas été réintégrés et vérifiés.

## Limites importantes

Ce dépôt n'a pas fait l'objet d'un audit de sécurité. N'y stocke pas de secrets importants avant revue indépendante et tests dans un vrai navigateur. PBKDF2 et les réponses serveur actuelles demandent notamment une revue cryptographique et opérationnelle avant tout déploiement public. Le service ne doit pas être présenté comme prêt pour une commercialisation.
