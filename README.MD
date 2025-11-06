🔐 Secure Password Manager
Un gestionnaire de mots de passe de bureau, local et chiffré, développé en Python et Tkinter. Il permet de stocker, générer et gérer vos identifiants en toute sécurité sur votre propre machine.

Ce projet met l'accent sur la sécurité hors ligne : vos données ne quittent jamais votre ordinateur et sont chiffrées à l'aide d'une clé dérivée de vos identifiants personnels.

(Pensez à remplacer cette URL par une capture d'écran de votre propre application)

⚠️ Avertissement de Sécurité Important
Ce gestionnaire de mots de passe utilise un double système d'authentification :

Un code personnel (ex: 1234)

Un mot de passe maître (ex: MaPhraseSecrete!)

Ces deux informations sont INDISPENSABLES pour déverrouiller votre coffre-fort.

NE LES PERDEZ PAS. Il n'existe aucune option "Mot de passe oublié". Si vous perdez votre code ou votre mot de passe maître, vos données chiffrées seront irrécupérables de manière permanente.

NE LES PARTAGEZ PAS. Toute personne possédant ces deux informations peut accéder à l'intégralité de vos mots de passe.

STOCKAGE LOCAL : Les fichiers passwords.vault (vos données chiffrées) et master.key (la clé de chiffrement) sont stockés localement dans le même dossier que le script. Sauvegardez-les dans un endroit sûr.

🚀 Fonctionnalités
Chiffrement Fort : Utilise la bibliothèque cryptography (Fernet) pour chiffrer l'intégralité du coffre-fort.

Authentification à Deux Facteurs Locaux : Utilise une combinaison d'un code personnel et d'un mot de passe maître pour générer la clé de déverrouillage.

Interface Multi-onglets :

Consulter : Recherchez et filtrez tous vos enregistrements.

Ajouter : Ajoutez de nouveaux services, noms d'utilisateur et mots de passe.

Générer : Un générateur de mots de passe robuste avec des options de longueur, de chiffres, de caractères spéciaux et d'exclusion.

Gestion Complète : Copiez, Affichez, Modifiez et Supprimez n'importe quel enregistrement.

Import/Export : Importez et exportez facilement vos mots de passe au format CSV non chiffré (à utiliser avec prudence).

Multilingue : L'interface est disponible en Français et en Anglais (sélection au premier lancement).

🛠️ Installation
Ce projet nécessite Python 3 et quelques bibliothèques externes.

Clonez le dépôt :

Bash

git clone https://github.com/VOTRE_NOM/votre-repo-password-manager.git
cd votre-repo-password-manager
Installez les dépendances : Il est fortement recommandé d'utiliser un environnement virtuel.

Bash

# (Optionnel) Créez un environnement virtuel
python -m venv venv
source venv/bin/activate  # Sur Windows: venv\Scripts\activate

# Installez les paquets requis
pip install cryptography pyperclip
🏃 Comment Lancer l'Application
Premier Lancement (Configuration Initiale)
La première fois que vous lancez le script, l'application vous guidera à travers deux étapes :

Choix de la langue : Sélectionnez "Français" ou "English".

Configuration Initiale :

Vous serez sur l'écran "Authentification Requise".

INVENTEZ un "code personnel" (ex: 4582) et un "mot de passe d'accès" (ex: MonSuperMotDePasse!).

MÉMORISEZ-LES.

Cliquez sur le long bouton : "Première configuration...".

Vos identifiants sont maintenant définis et votre coffre-fort est créé.

Lancement Normal
Toutes les fois suivantes, il vous suffira de :

Lancer le script :

Bash

python password_manager.py
(Remplacez password_manager.py par le nom de votre script)

Entrer le code personnel et le mot de passe d'accès que vous avez définis lors de la première configuration.

Cliquer sur "Déverrouiller".