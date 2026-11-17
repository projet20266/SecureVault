# SecureVault — coffre-fort zéro-knowledge

Projet de gestion de mots de passe sans email, chiffré dans le navigateur avant envoi.

## Lancer le site

npm install
node server.js

Puis ouvrir :
- http://localhost:3000/
- http://localhost:3000/app

## Structure

- public/ : pages web
- extension/ : extension navigateur
- admin/ : bot Telegram et webhook paiement
- tests/ : vérifications de base
- server.js : serveur HTTP minimal

## Sécurité

- plus simple, pas de journaux
- AES-256-GCM côté navigateur
- clé dérivée via PBKDF2
- aucune dépendance lourde

## Remarques

- Le chiffrement de fichier local a été retiré de l’interface pour garder le produit plus simple et plus cohérent.
- Les pages publiques sont pensées pour un rendu plus sobre et premium, sans style trop généré par IA.
