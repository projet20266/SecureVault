# Récupération administrée SecureVault

Le bot Telegram propose `/who <numéro>` uniquement dans le chat privé configuré par `ALLOWED_CHAT`. Il délivre une clé aléatoire valable 60 secondes. Côté serveur, seule l'empreinte de cette clé est conservée. Une nouvelle clé invalide la précédente.

Le titulaire entre le numéro, la clé temporaire et un nouveau mot de passe sur `/recover.html`. Le serveur remplace le jeton de connexion, invalide les clés de récupération et le mot de passe leurre, révoque les appareils, puis efface le coffre chiffré et son historique. Il ne déchiffre aucun secret et ne transmet aucun mot de passe au bot.

**Cette procédure ne récupère pas les anciens mots de passe.** Sans le mot de passe maître ou le kit de récupération du titulaire, ils sont cryptographiquement irrécupérables. La réinitialisation est destructive et l'interface l'annonce avant validation.

Sécurité opérationnelle : protège ton compte Telegram avec la 2FA, ne lance pas le bot dans un groupe, utilise un `ADMIN_TOKEN` fort, garde le port admin sur localhost et ne transfère la clé qu'au titulaire par un canal privé. Le délai d'une minute limite la fenêtre d'utilisation, mais ne rend pas Telegram confidentiel.
