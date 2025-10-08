# HistariApp

Ce dépôt regroupe les fichiers nécessaires pour héberger l'API PHP consommée par le front-end HistariApp. L'API est une implémentation légère (pas de framework) qui reprend la logique du point d'entrée historique `/api/index.php`, se connecte directement à la base MySQL utilisée en production et déplace davantage de logique côté serveur (navigation par ville, création/mise à jour du catalogue via le panneau d'administration).

## Structure

- `api/` : script PHP (`index.php`), configuration exemple et documentation dédiée.
- `docker-compose.yml` : environnement optionnel basé sur Apache/PHP pour lancer l'API rapidement.

## Démarrage rapide

1. **Cloner le dépôt**
2. **Configurer l'API**
   - Copier `api/.env.example` en `api/.env` et modifier les identifiants si nécessaire.
3. **Lancer en local**
   - Sans Docker : `php -S 0.0.0.0:8000 -t api`
   - Avec Docker : `docker-compose up --build`

Une fois démarrée, l'API est accessible via `http://localhost:8000/index.php?action=...`.

Consultez `api/README.md` pour plus de détails sur les actions disponibles et les variables d'environnement.
