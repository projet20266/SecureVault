# SecureVault

Coffre de mots de passe chiffré dans le navigateur, sans email à l'inscription.

## Démarrer en local

```sh
node server.js
```

Ouvre [http://localhost:3000/](http://localhost:3000/) pour l'accueil et [http://localhost:3000/app](http://localhost:3000/app) pour l'application. WebCrypto nécessite HTTPS en production (localhost est accepté en développement).

## Fonctionnalités et limites

L'interface conserve le thème de connexion d'origine. Le module de chiffrement de fichiers/dossiers a été retiré. Le stockage de versions côté serveur est limité à des blobs chiffrés; le serveur ne peut pas les déchiffrer. L'API peut comparer les versions pour détecter les mises à jour concurrentes. Ces mécanismes doivent être reliés à l'interface et testés avant d'être annoncés comme fonctions disponibles.

Le bot Telegram n'est pas et ne sera pas un moyen de lire les mots de passe des utilisateurs. Le serveur ne détient pas la clé permettant de déchiffrer un coffre. La récupération doit rester sous le contrôle du titulaire : kit de récupération conservé par lui, ou sauvegarde chiffrée qu'il déchiffre sur son propre appareil. Envoyer un mot de passe maître ou une clé de déchiffrement à Telegram exposerait durablement les secrets dans les messages, notifications et sauvegardes Telegram.

## Sécurité — état réel

Ce dépôt n'a pas fait l'objet d'un audit indépendant. N'y stocke pas de secrets importants avant revue. Le service n'est pas prêt à être commercialisé. Les clés, la récupération, la synchronisation, les extensions et les flux de paiement exigent une revue cryptographique et des tests de bout en bout. Configure `ADMIN_TOKEN` avec un secret aléatoire fort; l'API admin écoute uniquement sur 127.0.0.1.

Pour fermer les inscriptions libres, lance le serveur avec `REQUIRE_SUB=true` et crée les comptes via l'API admin locale. Les données sont stockées dans `data/` ou dans `DATA_DIR`.
