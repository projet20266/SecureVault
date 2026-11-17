# Journal de bord — SecureVault

## Point de départ

L'idée initiale : un gestionnaire de mots de passe sans email et sans stockage lisible côté serveur. Le chiffrement se fait dans le navigateur. Le serveur ne reçoit que des blocs chiffrés et des empreintes.

## Chiffrement

AES-256-GCM, pbkdf2 600 000 itérations. Le mot de passe maître reste local. Le serveur ne reçoit ni le mot de passe ni la clé de chiffrement.

## Serveur

Node.js pur. Les données stockées sont limitées à des empreintes et au coffre chiffré. Le service ne garde ni email, ni logs, ni IP.

## Extension

Le navigateur remplit automatiquement les identifiants et gère les formulaires à deux étapes, les codes 2FA, etc.

## Ce qui a été retiré

La fonction de chiffrement de fichiers ou dossiers locaux a été supprimée de la vue application. Elle ne correspond pas à l'objectif principal du produit et alourdit la logique visuelle et fonctionnelle.

## Ce qu'il reste à faire

- finaliser les tests navigateur
- améliorer le design global
- sécuriser la landing page et les liens internes
- simplifier la navigation et retirer les éléments de démonstration trop lourds
