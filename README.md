# SecureVault

Coffre de mots de passe chiffré dans le navigateur, sans email à l'inscription.

## Démarrer en local

```sh
node server.js
```

Ouvre [http://localhost:3000/](http://localhost:3000/) pour l'accueil et [http://localhost:3000/app](http://localhost:3000/app) pour l'application. WebCrypto nécessite HTTPS en production (localhost est accepté en développement).

## Récupération administrée facultative

Le bot Telegram privé peut générer avec `/who <numéro>` une clé à usage unique, valide 60 secondes. Le titulaire l'entre sur `/recover.html` avec son numéro et choisit lui-même un nouveau mot de passe. La clé est stockée côté serveur sous forme d'empreinte et n'est consommable qu'une fois.

**C'est une réinitialisation destructive, pas une récupération des anciens secrets.** Le serveur ne possède pas la clé du coffre : la validation efface le coffre chiffré, l'historique et les clés de secours/leurre. Le bot ne reçoit et n'envoie aucun mot de passe de coffre. Si les anciens mots de passe doivent être conservés, le titulaire doit d'abord utiliser son mot de passe maître ou son kit de récupération.

Configuration : lancer le serveur avec `ADMIN_TOKEN` aléatoire et optionnellement `REQUIRE_SUB=true`; lancer le bot avec `BOT_TOKEN`, `ALLOWED_CHAT` (ID du chat privé du propriétaire), `ADMIN_TOKEN` et `ADMIN_URL`. Le port admin écoute uniquement sur 127.0.0.1. Protège aussi ton compte Telegram par 2FA.

## Vérification

```sh
node tests/server-hardening.test.js
node tests/admin-recovery.test.js
```

Le projet n'a pas encore fait l'objet d'un audit de sécurité indépendant et ne doit pas être considéré comme prêt pour stocker des secrets importants.
