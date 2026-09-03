# AD_Remediation_Menu.ps1

Script PowerShell à menu pour automatiser les remédiations Active Directory les plus courantes, basé sur les constats récurrents des rapports **PingCastle** (krbtgt jamais changé, NTLMv1/LM, comptes inactifs, délégations Kerberos, mots de passe n'expirant jamais, LAPS absent, etc.).

Le script est volontairement construit pour qu'aucune action ne puisse partir "par accident" : mode simulation actif par défaut, confirmations renforcées sur tout ce qui peut avoir un impact, et vérifications préalables avant les actions les plus sensibles.

---

## Sommaire

- [Prérequis](#prérequis)
- [Démarrage rapide](#démarrage-rapide)
- [Principes de sécurité du script](#principes-de-sécurité-du-script)
- [Menu \[1\] Actions SAFE](#menu-1--actions-safe)
- [Menu \[2\] Actions À VALIDER](#menu-2--actions-à-valider)
- [Menu \[3\] Rapports](#menu-3--rapports)
- [Focus : rotation automatique du mot de passe KRBTGT](#focus--rotation-automatique-du-mot-de-passe-krbtgt)
- [Focus : audit NTLM avant blocage NTLMv1/LM](#focus--audit-ntlm-avant-blocage-ntlmv1lm)
- [Journalisation](#journalisation)
- [Limites connues / points d'attention](#limites-connues--points-dattention)

---

## Prérequis

- PowerShell 5.1 (Windows PowerShell), exécuté depuis un poste avec le module **ActiveDirectory** (RSAT AD DS) installé — idéalement directement sur un contrôleur de domaine.
- Le module **GroupPolicy** (RSAT-GPMC) est nécessaire pour les actions qui créent/modifient des GPO (journalisation PowerShell, NTLMv1, LLMNR).
- Compte d'exécution membre de **Domain Admins** (le script vérifie l'appartenance et avertit si ce n'est pas le cas, mais ne bloque pas).
- Console PowerShell lancée **en tant qu'administrateur**.
- Le **PowerShell Remoting (WinRM)** doit être activé sur les contrôleurs de domaine pour les actions qui s'exécutent à distance dessus (`Invoke-Command`) : audit avancé, audit NTLM, Spooler, signature LDAP, rapport hotfix, rapport NTLMv1/LM, rotation KRBTGT planifiée.

## Démarrage rapide

```powershell
.\AD_Remediation_Menu.ps1
```

Au lancement, le script :
1. Vérifie les prérequis (module AD, connectivité au domaine, appartenance Domain Admins, élévation).
2. Affiche un rappel que le **mode simulation** est actif.
3. Ouvre le menu principal.

```
MENU PRINCIPAL
 [1] Actions SAFE (aucune incidence prod)
 [2] Actions A VALIDER (impact potentiel)
 [3] Rapports (lecture seule)

 [S] Activer le mode REEL (desactiver la simulation)
 [Q] Quitter
```

## Principes de sécurité du script

- **Mode simulation par défaut** : tant que vous n'avez pas basculé en mode réel via `[S]` (et tapé `CONFIRMER`), **aucune action n'est appliquée** — le script affiche uniquement ce qu'il *ferait*.
- **Deux niveaux de confirmation** :
  - Actions SAFE → confirmation simple `O/N`.
  - Actions À VALIDER → il faut taper le mot exact `CONFIRMER` (sensible à la casse), après lecture d'un avertissement dédié.
- **Journal complet** de toute la session dans `Logs\Remediation_AD_<date>.log`, plus des exports CSV horodatés pour chaque rapport/liste de comptes concernés.
- **Vérifications préalables avant action** quand c'est pertinent : ex. détection des imprimantes avant d'arrêter le service Spooler, rappel de consulter le rapport NTLMv1 avant de désactiver NTLMv1.
- **Aucune action irréversible cachée** : les comptes/ordinateurs "inactifs" ne sont jamais supprimés, seulement désactivés et déplacés dans une OU de quarantaine dédiée (`OU_QUARANTAINE_COMPTES_INACTIFS`).
- Les GUID de sous-catégories d'audit (`auditpol`) et les champs d'événements Windows utilisés sont **indépendants de la langue de l'OS** (important sur un DC installé en français, où les noms anglais font échouer les commandes natives).

## Menu [1] : Actions SAFE

Aucune de ces actions ne modifie un comportement fonctionnel existant : elles activent de la journalisation, protègent contre la suppression accidentelle, ou ferment des portes qui ne devraient jamais être ouvertes (compte Invité, mot de passe vide autorisé...).

| # | Action | Effet |
|---|--------|-------|
| 1 | Activer la Corbeille Active Directory | Permet de restaurer un objet supprimé par erreur. |
| 2 | Désactiver le compte Invité (Guest) | Si le compte est actif, le désactive. |
| 3 | Protéger les OU contre la suppression accidentelle | Ajoute l'ACE de refus de suppression sur chaque OU qui ne l'a pas. |
| 4 | Limiter `ms-DS-MachineAccountQuota` à 0 | Empêche les utilisateurs standards de joindre de nouveaux postes au domaine. |
| 5 | Activer l'audit avancé sur les DC (`auditpol`) | Active Succès+Échec sur 16 sous-catégories clés (Kerberos, comptes, DS Access/Changes, logon...), via GUID (indépendant de la langue de l'OS). |
| 6 | Activer la journalisation PowerShell (Script Block Logging) | GPO liée à l'OU Domain Controllers. |
| 7 | Retirer le flag "Mot de passe non requis" | Ne force pas de changement immédiat, retire juste l'exemption pour le prochain changement. |
| 8 | Activer l'audit NTLM | Journalisation uniquement (jamais de blocage) pour détecter qui utilise encore NTLMv1/LM — voir [focus dédié](#focus--audit-ntlm-avant-blocage-ntlmv1lm). |
| 9 | Exécuter TOUTES les actions SAFE | Enchaîne les actions 1 à 8 avec confirmation globale. |

## Menu [2] : Actions À VALIDER

Ces actions peuvent casser l'authentification de matériels/applications legacy (imprimantes réseau, NAS, appliances, comptes de service). Chacune :
- affiche d'abord ce qui va être impacté (comptes, DC, délégations...) ;
- exige de taper `CONFIRMER` ;
- est pensée pour une fenêtre de maintenance.

| # | Action | Point d'attention principal |
|---|--------|------------------------------|
| 1 | Réinitialiser le mot de passe KRBTGT | Nécessite 2 exécutions espacées (voir [focus KRBTGT](#focus--rotation-automatique-du-mot-de-passe-krbtgt)). Propose ensuite de configurer la rotation automatique. |
| 2 | Désactiver NTLMv1/LM (`LmCompatibilityLevel`) | Casse les équipements ne parlant que NTLMv1/LM. Rappelle de consulter le rapport NTLMv1 avant de continuer. |
| 3 | Désactiver DES / forcer AES sur les comptes | Casse les applis Kerberos dépendant de DES ou ne supportant pas AES. |
| 4 | Marquer les comptes à privilèges "non délégables" | Casse les scénarios de délégation Kerberos utilisant ces comptes. |
| 5 | Ajouter les admins dans "Protected Users" | Plus de NTLM/DES/délégation, TGT limité à 4h pour ces comptes. |
| 6 | Rapport des délégations Kerberos | Lecture seule : liste les délégations non contraintes/contraintes/RBCD pour revue au cas par cas. |
| 7 | Nettoyer le groupe Schema Admins | Sélection interactive des comptes à retirer (le groupe doit rester vide en temps normal). |
| 8 | Arrêter/désactiver le Spooler sur les DC | **Vérifie d'abord si des imprimantes sont configurées/partagées sur le DC** et exige une confirmation dédiée (`ARRETER`) si c'est le cas. |
| 9 | Forcer la signature LDAP / channel binding | Casse les clients LDAP ne supportant pas la signature. |
| 10 | Désactiver LLMNR via GPO | Impact large (tout le domaine) ; GPO créée mais non liée automatiquement. |
| 11 | Désactiver les comptes inactifs | **Seuils de jours demandés à chaque exécution** (pas de valeur figée). Déplace en quarantaine + désactive, ne supprime jamais. |
| 12 | Forcer l'expiration des mots de passe admin | Prévenir les propriétaires des comptes concernés avant expiration effective. |
| 13 | Configurer la rotation KRBTGT planifiée | Voir [focus dédié](#focus--rotation-automatique-du-mot-de-passe-krbtgt). |

## Menu [3] : Rapports

Lecture seule, aucune modification. Chaque rapport s'exporte en CSV horodaté dans `Logs\`.

| # | Rapport | Remarque |
|---|---------|----------|
| 1 | Comptes inactifs (utilisateurs/ordinateurs) | Seuils en jours demandés à l'exécution (mêmes valeurs par défaut que l'action de désactivation correspondante). |
| 2 | Comptes avec mot de passe n'expirant jamais | |
| 3 | Membres des groupes à privilèges | Domain/Enterprise/Schema Admins, Administrators, Account/Backup Operators, Protected Users. |
| 4 | Hotfix installés sur les DC | |
| 5 | NTLMv1/LM détecté | Nécessite l'audit NTLM (menu SAFE 8) actif depuis un moment ; peut être **long** à exécuter (lecture du journal Sécurité). |
| 6 | Export global | Regroupe les rapports 1 à 4 (le rapport NTLMv1/LM en est exclu volontairement, car trop coûteux pour un export "tout en un"). |

## Focus : rotation automatique du mot de passe KRBTGT

Un reset krbtgt "à la main" doit être fait **deux fois**, espacé d'un délai supérieur à la durée de vie max des tickets Kerberos + le temps de convergence de la réplication AD. La recommandation Microsoft/ANSSI pour la suite est de **répéter ce reset à intervalle régulier** (typiquement tous les 6 mois) : un reset unique répété avec un intervalle largement supérieur à ce délai offre en continu la même protection que le double-reset manuel.

L'action `[2] > 13` automatise cela avec une architecture à moindre privilège :
- Création d'un **gMSA dédié** (nom par défaut `svc-KrbtgtRotation`) — pas de mot de passe à gérer.
- **Délégation minimale** : uniquement le droit "Reset Password" sur l'objet `krbtgt` (via `dsacls`), jamais de droits Domain Admin accordés à la tâche planifiée.
- Déploiement d'un script autonome sur le DC choisi + création d'une **tâche planifiée récurrente** (intervalle configurable, avertissement si < 30 jours).
- **Garde-fou intégré** : avant chaque exécution automatique, le script vérifie l'état de réplication AD (`repadmin /replsummary`) et **annule** la rotation si un problème est détecté ou si la sortie est inattendue.
- Journalisation locale (`C:\ADHC-Scripts\Krbtgt-Rotation.log`) + Event Log applicatif dédié (`ADHC-KrbtgtRotation`).

## Focus : audit NTLM avant blocage NTLMv1/LM

Avant de forcer `LmCompatibilityLevel=5` (action `[2] > 2`), qui peut casser des équipements legacy sans prévenir, le script propose une démarche en deux temps :

1. **`[1] > 8`** active l'audit NTLM (journalisation uniquement, jamais de blocage) : réception NTLM, émission NTLM, authentification NTLM pass-through au niveau du domaine, et active le journal `Microsoft-Windows-NTLM/Operational`.
2. Laisser tourner **plusieurs jours** (idéalement un cycle métier complet).
3. **`[3] > 5`** lit le journal Sécurité des DC et remonte précisément les comptes/postes utilisant encore NTLMv1 ou LM (champ `LmPackageName` des événements 4624/4625), sans dépendre du texte localisé des messages.

L'action de désactivation NTLMv1 (`[2] > 2`) rappelle explicitement cette étape avant de continuer.

## Journalisation

- `Logs\Remediation_AD_<horodatage>.log` : trace complète de la session (toutes les actions, y compris en simulation).
- `Logs\Rapport_*.csv` : un export par rapport exécuté (comptes inactifs, mots de passe n'expirant jamais, groupes privilégiés, hotfix, NTLMv1/LM, délégations Kerberos).
- `Logs\krbtgt_reset_tracking.log` : horodatage du dernier reset manuel krbtgt, pour planifier le second.
- Sur le DC hébergeant la rotation KRBTGT planifiée : `C:\ADHC-Scripts\Krbtgt-Rotation.log` + journal d'événements `ADHC-KrbtgtRotation`.

## Limites connues / points d'attention

- Les GPO créées pour NTLMv1 et LLMNR sont **volontairement non liées automatiquement** (impact potentiellement large) : à lier manuellement sur un OU pilote après validation.
- Le rapport NTLMv1/LM peut être lent sur un DC avec un gros volume de journal Sécurité ; commencer avec une période courte (ex. 2-3 jours) pour valider le fonctionnement.
- La rotation KRBTGT planifiée nécessite un forest functional level ≥ 2012 (gMSA) et une KDS Root Key ; en environnement mono-DC, le script propose de forcer sa disponibilité immédiate (à éviter en production multi-DC, où il vaut mieux laisser les ~10h de propagation naturelle).
- Ce script couvre les constats **récurrents** observés dans les rapports PingCastle fournis ; il ne remplace pas une revue complète du rapport (certains constats très spécifiques à un client ne sont pas automatisés).
