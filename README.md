# Analyseur de Sécurité IoT

Une application Next.js pour analyser les menaces de cybersécurité dans les environnements IoT. Cette application fournit une surveillance en temps réel, une analyse des menaces et des évaluations de sécurité pour les appareils et réseaux IoT.

## Fonctionnalités

- **Surveillance des Menaces en Temps Réel** : Tableau de bord affichant les menaces actives et l'état des appareils
- **Analyse des Menaces** : Vue détaillée des alertes de sécurité et de l'historique des menaces
- **Gestion des Appareils IoT** : Surveiller et gérer les appareils IoT connectés
- **Score de Sécurité** : Évaluation globale de vulnérabilité
- **Actualisation des Données** : Fonctionnalité d'actualisation manuelle pour mettre à jour les données depuis les API externes

## Stack Technologique

- **Framework** : Next.js 16 avec App Router
- **Langage** : TypeScript
- **Stylisation** : Tailwind CSS avec thème cyber personnalisé
- **Base de Données** : PostgreSQL
- **Conteneurisation** : Docker & Docker Compose
- **Déploiement** : Conteneurisé avec configuration prête pour la production

## Démarrage

### Prérequis

- Docker et Docker Compose installés
- Node.js 18+ (pour le développement local)

### Installation

1. **Cloner et configurer le projet** :
   ```bash
   cd /chemin/vers/votre/projet
   ```

2. **Installer les dépendances** (pour le développement local) :
   ```bash
   npm install
   ```

3. **Exécuter avec Docker Compose** :
   ```bash
   docker-compose up --build
   ```

4. **Accéder à l'application** :
   - Frontend : http://localhost:3000
   - Base de données : localhost:5432 (postgres/password)

### Développement Local (sans Docker)

```bash
# Installer les dépendances
npm install

# Exécuter le serveur de développement
npm run dev

# Construire pour la production
npm run build

# Démarrer le serveur de production
npm start
```

## Structure du Projet

```
src/
├── app/                    # Next.js App Router
│   ├── api/               # Routes API
│   │   └── refresh/       # Point de terminaison d'actualisation des données
│   ├── threats/           # Page d'analyse des menaces
│   ├── layout.tsx         # Layout racine avec navigation
│   ├── page.tsx           # Page tableau de bord
│   └── globals.css        # Styles globaux
├── components/            # Composants React
│   └── Navbar.tsx         # Composant de navigation
├── services/              # Logique métier et appels API
│   └── securityService.ts # Service de données de sécurité
└── types/                 # Définitions de types TypeScript
    └── security.ts        # Types liés à la sécurité
```

## Intégration API

L'application est conçue pour s'intégrer avec des API de cybersécurité externes :

### Implémentation Actuelle
- **Service de Données Factices** : Génère des données factices réalistes pour le développement
- **Appels API Simulés** : Inclut des délais réalistes et des structures de données
- **Fonctionnalité d'Actualisation** : Actualisation manuelle des données avec états de chargement


## Schéma de Base de Données

La base de données PostgreSQL est configurée et prête pour :
- Stockage de l'historique des menaces
- Registre des appareils
- Gestion des utilisateurs
- Configurations d'alertes

## Variables d'Environnement

Créez un fichier `.env.local` pour le développement local :

```env
# Base de données
DATABASE_URL=postgresql://postgres:password@localhost:5432/iot_security

# Clés API (pour usage futur)
API_KEY=
```
