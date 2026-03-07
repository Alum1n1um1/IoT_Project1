## Application d'analyse de risque pour caméras IoT

Cette application console Python collecte automatiquement des informations publiques de vulnérabilités pour des caméras réseau IoT, puis calcule un score de risque pour les appareils que vous possédez.

Sources de données :
- **NVD (CVE)** via l'API `cves/2.0` pour les vulnérabilités et leurs CPE (identification des modèles de caméras).
- **CISA Known Exploited Vulnerabilities (KEV)** pour savoir si une vulnérabilité est activement exploitée.
- **FIRST EPSS** pour obtenir la probabilité d'exploitation (EPSS) de chaque CVE.

Les données sont stockées localement dans une base **SQLite** (`camera_risk.db`).

---

## Installation

1. Créez un environnement virtuel (recommandé) et activez‑le.
2. Installez les dépendances :

```bash
pip install -r requirements.txt
```

3. (Optionnel) Pour augmenter le quota NVD, définissez la variable d'environnement `NVD_API_KEY` avec votre clé API NVD.

---

## Lancer l'application

Depuis le répertoire du projet :

```bash
python camera_risk_app.py
```

Une base SQLite `camera_risk.db` sera créée automatiquement au premier lancement.

---

## Fonctionnement général

Le menu principal propose :

1. **Mettre à jour les données (NVD / KEV / EPSS)**  
   - Interroge l'API NVD avec le mot‑clé `camera`.  
   - Analyse les CPE associés aux CVE et identifie les équipements matériels (part `h`) qui ressemblent à des caméras IP (heuristiques sur vendor / nom de produit).  
   - Met à jour la table `cves`, la table `cameras` et les liaisons `camera_cves`.  
   - Récupère ensuite le catalogue KEV (CISA) et marque les CVE exploitées.  
   - Enfin, interroge l'API EPSS pour tous les CVE présents dans la base et stocke les scores EPSS.

2. **Parcourir les caméras connues et en ajouter à mes équipements**  
   - Permet de rechercher des caméras par vendor ou nom de produit (pagination).  
   - Chaque entrée correspond à un CPE matériel (`vendor`, `product`, `version`).  
   - Vous pouvez choisir un ID de caméra et l'ajouter à vos équipements en lui donnant éventuellement un nom ou un emplacement (ex. `Entrée entrepôt`).

3. **Gérer mes caméras sélectionnées**  
   - Liste les caméras que vous avez ajoutées.  
   - Permet de supprimer une caméra de votre sélection.

4. **Afficher le tableau de bord de risque**  
   - Pour chaque caméra sélectionnée, l'application récupère toutes les vulnérabilités liées (via NVD), ainsi que leurs données KEV et EPSS.  
   - Elle calcule un **score de risque par CVE** combinant :
     - CVSS (normalisé sur \[0,1\])  
     - EPSS (déjà sur \[0,1\])  
     - Présence dans KEV (+ majoration si associé à des campagnes ransomwares)  
   - Un **score de risque par appareil** est ensuite calculé à partir des vulnérabilités associées (pondération du maximum et de la moyenne des scores les plus élevés).  
   - Le tableau de bord affiche :
     - Vos caméras (vendor, produit, version, nom)  
     - Le score de risque par appareil et un niveau (NÉGLIGEABLE / FAIBLE / MOYEN / ÉLEVÉ / CRITIQUE)  
     - Le détail des vulnérabilités (CVE, CVSS, EPSS, présence KEV, CWE, résumé).  
   - Une synthèse globale récapitule :
     - Nombre de caméras suivies  
     - Nombre total de vulnérabilités et de CVE dans KEV  
     - Score moyen et maximal de risque appareil.

---

## Remarques

- L'identification des caméras à partir des CPE repose sur des heuristiques simples (mots‑clés `camera`, `cam`, `ipcam`, etc. et quelques vendeurs courants). Selon votre parc, il peut être nécessaire d'ajuster la logique dans `feeds.py`.  
- L'application reste entièrement **locale** : seule la collecte des données interroge les APIs publiques NVD, CISA et FIRST EPSS ; l'analyse et le stockage se font dans votre environnement.

