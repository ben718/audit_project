# Projet d'Audit de Configuration Linux et Apache

Ce projet contient un script Python permettant d'auditer la configuration d'un serveur Linux et d'un serveur web Apache, dans une logique d'audit de sécurité.

## Structure du Projet

```
audit_project/
├── src/
│   ├── main.py
│   └── modules/
│       ├── linux_audit.py
│       └── apache_audit.py
├── reports/
├── docs/
├── logs/
└── README.md
```

- `src/main.py`: Le point d'entrée principal du script, gérant le menu interactif.
- `src/modules/linux_audit.py`: Contient les fonctions d'audit spécifiques au système Linux.
- `src/modules/apache_audit.py`: Contient les fonctions d'audit spécifiques au serveur Apache.
- `reports/`: Dossier où les résultats des audits (fichiers `.txt` et `.json`) seront sauvegardés.
- `docs/`: Dossier pour la documentation supplémentaire (actuellement ce `README.md`).
- `logs/`: Dossier pour le fichier de log `audit.log`.

## Prérequis

- Python 3.x
- Un système d'exploitation Linux (testé sur Ubuntu Server).
- Apache2 installé et configuré pour l'audit Apache.

## Utilisation

1.  **Cloner le dépôt (ou copier les fichiers) :**

    ```bash
    git clone <URL_DU_DEPOT>
    cd audit_project
    ```
    (Si vous avez reçu un fichier ZIP, décompressez-le et naviguez vers le dossier `audit_project`.)

2.  **Exécuter le script principal :**

    ```bash
    python3 src/main.py
    ```

3.  **Suivre le menu interactif :**

    Le script affichera un menu vous permettant de choisir le type d'audit à exécuter :
    -   Audit système Linux uniquement
    -   Audit Apache uniquement
    -   Les deux audits
    -   Quitter

## Fichiers de Sortie

Après chaque exécution d'audit, les fichiers suivants seront générés dans le dossier `reports/` :

-   `audit_systeme.txt` et `audit_systeme.json`: Contiennent les résultats détaillés de l'audit système Linux.
-   `audit_apache.txt` et `audit_apache.json`: Contiennent les résultats détaillés de l'audit Apache.

Un fichier de log, `audit.log`, sera également créé ou mis à jour dans le dossier `logs/`, retraçant l'exécution du script, les erreurs éventuelles et les modules appelés.

## Contraintes et Limitations

-   **Aucun outil externe :** Le script utilise uniquement des modules Python natifs (`subprocess`, `os`, `json`, `logging`) et des appels système Linux/Apache standards. Aucun outil d'audit tiers (comme Lynis, Nikto, etc.) n'est utilisé.
-   **Interprétation des résultats :** Le script collecte les données de configuration. L'interprétation des résultats et la formulation de recommandations de sécurité basées sur des standards (CIS Benchmarks, ANSSI) doivent être effectuées manuellement après l'exécution du script.
-   **Permissions :** Le script peut nécessiter des permissions élevées (ex: `sudo`) pour accéder à certains fichiers de configuration ou exécuter certaines commandes système. Il est recommandé de l'exécuter avec les privilèges nécessaires.

## Développement

Le code est structuré de manière modulaire et commentée pour faciliter la compréhension et la maintenance.

## Auteur

Manus AI


