# Modèle de récupération SecureVault

Le support ou l'administrateur ne doit jamais pouvoir déchiffrer le coffre d'un utilisateur. Le bot Telegram ne reçoit donc ni mot de passe maître, ni clé de récupération, ni coffre en clair.

Pour aider un collègue qui a perdu son mot de passe, il faut lui remettre un kit qu'il a généré au préalable ou une sauvegarde chiffrée avec une clé qu'il contrôle. Il saisit lui-même la clé sur un appareil fiable et le déchiffrement se fait localement. Si le titulaire n'a conservé ni son mot de passe ni son kit, il n'existe pas de récupération zéro-knowledge : promettre le contraire nécessiterait une porte dérobée.

Une sauvegarde destinée à être transmise peut être stockée/envoyée chiffrée, mais la clé doit être communiquée séparément et jamais par le même compte Telegram. Le bot peut fournir des instructions ou un lien vers l'application; il ne doit pas recevoir la clé et ne doit pas renvoyer les identifiants en clair.

## Propriétés ajoutées côté serveur

- Historique plafonné à dix versions précédentes; seules les données chiffrées sont conservées.
- `GET /api/get` renvoie un numéro de version.
- `POST /api/put` accepte `expectedVersion`; une version périmée retourne `409` au lieu d'écraser une modification concurrente.
- `POST /api/history` renvoie l'historique chiffré au titulaire authentifié.
- Le port admin est inaccessible via le serveur public et reste lié à `127.0.0.1`.

Ces points sont des primitives serveur. L'interface doit encore les utiliser pour proposer une restauration/conflict UX sûre.
