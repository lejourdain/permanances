# Permanences — APK Android + comptes sécurisés (Supabase)

Application de gestion des permanences, astreintes, absences et missions.
Connexion par **compte individuel (pseudo + mot de passe)**, données stockées
dans une base Supabase sécurisée, fonctionnement hors-ligne.

```
www/                    -> l'application (identifiants Supabase déjà intégrés)
.github/workflows/      -> compilation automatique de l'APK (gratuit)
supabase-schema.sql     -> base de données + comptes à installer
package.json / capacitor.config.json
```

## PARTIE 1 — Base de données (déjà créée si le SQL est passé)
Dans Supabase -> SQL Editor -> coller `supabase-schema.sql` -> Run.
Cela crée : la table des comptes (`app_users`, mots de passe hachés bcrypt),
le planning partagé (`services`) et les fonctions sécurisées d'auth et de
données. Script ré-exécutable sans risque.

## PARTIE 2 — Identifiants
URL + clé publique déjà intégrées dans `www/index.html` (bloc CONFIGURATION).
Rien à faire, sauf si vous changez de projet Supabase.

## PARTIE 3 — Fabriquer l'APK (gratuit, sans rien installer)
1. Compte `github.com` (gratuit) -> **New repository** (Public).
2. *Add file -> Upload files* -> glisser tout le contenu du dossier
   (dont `www/` et `.github/`) -> *Commit*.
3. Onglet **Actions -> Build APK** (sinon *Run workflow*).
4. Coche verte (~5 min) -> ouvrir le run -> **Artifacts** ->
   **Permanences-APK** -> décompresser -> `app-debug.apk`.
5. Installer sur le téléphone (autoriser les sources inconnues).

## PARTIE 4 — Comptes
- À la connexion : **identifiant (pseudo)** + **mot de passe**.
- Pseudo inconnu -> l'app propose de **créer le compte**.
- Pseudo connu + mauvais mot de passe -> **« Mot de passe incorrect »** (rien
  n'est créé).
- Tous les comptes du projet partagent **le même planning** (mises à jour
  automatiques, utilisable hors-ligne, resynchro au retour du réseau).
- Le pseudo est insensible à la casse ; mot de passe : 4 caractères minimum
  (choisissez-le robuste).

## Sécurité
- Mots de passe **hachés** (bcrypt) — jamais stockés en clair.
- Mot de passe **vérifié côté serveur à chaque opération** : impossible de
  lire/écrire sans identifiants valides.
- Tables **inaccessibles directement** (RLS sans policy) ; aucune injection SQL
  possible (paramètres liés, zéro SQL dynamique) ; fonctions definer verrouillées.
- L'app conserve les identifiants en local pour rester connectée hors-ligne
  (stockage privé de l'app sur le téléphone).
- Pour aller plus loin (jetons, MFA, réinitialisation par e-mail) : Supabase Auth.

## Couverture du cahier des charges
Comptes (pseudo + mot de passe) · planning mois/semaine/jour · événements
(Permanence, Astreinte, Absence, Stage, CMO, RO/ROPN, TT) · effectifs · missions
(catalogue, création, filtres) · couleurs personnalisables · export Excel/CSV ·
base partagée + hors-ligne · APK Android.
Évolutions : notifications push, gestion véhicules/matériel.
