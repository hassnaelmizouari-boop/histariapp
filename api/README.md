# API PHP pour HistariApp

Ce dossier contient une API PHP légère chargée de servir les données de la base MySQL existante utilisée par HistariApp. Le script `index.php` s'appuie sur PDO et expose désormais des actions supplémentaires pour charger les pages ville côté serveur et alimenter le panneau d'administration (création/mise à jour de quêtes et récompenses).

## Démarrage rapide

1. **Prérequis**
   - PHP 8.1+
   - Extension `pdo_mysql`
   - (Optionnel) Docker Compose si vous souhaitez lancer l'API dans un conteneur

2. **Configuration**
   - Copiez le fichier `.env.example` en `.env` et ajustez les identifiants de base de données ou de domaine si nécessaire.
   - Le fichier `.htaccess` permet de rediriger toutes les requêtes vers `index.php` lors d'un déploiement sous Apache.

3. **Lancement sans Docker**

   ```bash
   php -S 0.0.0.0:8000 -t api
   ```

   L'API sera disponible sur `http://localhost:8000/index.php`.

4. **Lancement avec Docker Compose**
   - Voir les instructions dans le fichier `docker-compose.yml` à la racine pour démarrer un serveur PHP Apache prêt à l'emploi.

## Actions disponibles

| Action (`action=`)      | Méthode | Description |
|-------------------------|---------|-------------|
| `get_initial_data`      | GET     | Récupère les quêtes, partenaires, récompenses, la liste des villes et éventuellement les informations utilisateur |
| `get_city_data`         | GET     | Charge uniquement les données d'une ville (quêtes/partenaires/récompenses filtrés) pour basculer la navigation par pages |
| `auth`                  | POST    | Authentifie un utilisateur (login ou inscription selon le champ `isSignup`) |
| `save_quest_reward`     | POST    | Enregistre une récompense de quête terminée et crédite les HistaCoins |
| `create_quest`          | POST    | Crée une nouvelle quête (réservé aux administrateurs) |
| `update_quest`          | POST    | Met à jour une quête existante (réservé aux administrateurs) |
| `create_reward`         | POST    | Crée une nouvelle récompense (réservé aux administrateurs) |
| `update_reward`         | POST    | Met à jour une récompense existante (réservé aux administrateurs) |

> ℹ️ Les actions d'administration attendent un objet `auth` contenant l'e-mail et le mot de passe de l'administrateur (ou les identifiants spéciaux définis via `HISTARI_ADMIN_EMAIL` / `HISTARI_ADMIN_PASSWORD`).

### Exemple : chargement d'une page ville

```
GET /api/index.php?action=get_city_data&city=agadir
```

Réponse type :

```json
{
  "status": "success",
  "data": {
    "city": { "key": "agadir", "label": "Agadir" },
    "quests": [...],
    "partners": [...],
    "rewards": [...]
  }
}
```

### Exemple : création d'une quête

```json
POST /api/index.php?action=create_quest
{
  "auth": { "email": "admin@histari.app", "password": "••••" },
  "quest": {
    "title": "Nouvelle quête",
    "city": "agadir",
    "steps": [ ... ]
  }
}
```

La réponse contient l'enregistrement stocké (avec les champs calculés ou convertis par MySQL) et les valeurs JSON (`steps`) déjà décodées pour un affichage immédiat côté front-end.

Les réponses sont retournées au format JSON UTF-8.

## Variables d'environnement supportées

| Nom | Description | Valeur par défaut |
|-----|-------------|-------------------|
| `HISTARI_ALLOWED_ORIGIN` | Domaine autorisé pour les requêtes CORS | `*` |
| `HISTARI_DB_HOST` | Hôte MySQL | `sdb-e.hosting.stackcp.net` |
| `HISTARI_DB_NAME` | Base de données | `histaria_db-3138332e70` |
| `HISTARI_DB_USER` | Nom d'utilisateur MySQL | `histadmin` |
| `HISTARI_DB_PASSWORD` | Mot de passe MySQL | `g4:M,Xp^E8D>` |
| `HISTARI_DB_CHARSET` | Jeu de caractères MySQL | `utf8mb4` |
| `HISTARI_ADMIN_EMAIL` | Identifiant spécial d'administration | `ADMIN` |
| `HISTARI_ADMIN_PASSWORD` | Mot de passe spécial d'administration | `ADMIN` |

Adaptez ces valeurs en fonction de votre environnement d'hébergement.
