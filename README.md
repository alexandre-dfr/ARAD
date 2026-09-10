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
- [Menu \[4\] Automatisation](#menu-4--automatisation)
- [Focus : désactivation par date choisie (garde-fous et UO dédiées)](#focus--désactivation-par-date-choisie-garde-fous-et-uo-dédiées)
- [Focus : rotation automatique du mot de passe KRBTGT](#focus--rotation-automatique-du-mot-de-passe-krbtgt)
- [Focus : audit NTLM avant blocage NTLMv1/LM](#focus--audit-ntlm-avant-blocage-ntlmv1lm)
- [Focus : activer WinRM sur les DC quand ils sont injoignables](#focus--activer-winrm-sur-les-dc-quand-ils-sont-injoignables)
- [Dépannage : erreur WinRM](#dépannage--erreur-winrm-la-connexion-au-serveur-distant--a-échoué)
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
 [4] Automatisation (taches planifiees)

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
- **Aucune action irréversible cachée** : les comptes/ordinateurs "inactifs" ne sont jamais supprimés, seulement désactivés et déplacés dans une OU de quarantaine dédiée (`OU_QUARANTAINE_COMPTES_INACTIFS` pour l'action par ancienneté ; `disable_user` / `disable_computer` pour l'action par date choisie et l'automatisation — voir [focus dédié](#focus--désactivation-par-date-choisie-garde-fous-et-uo-dédiées)).
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
| 9 | Activer PowerShell Remoting (WinRM) sur les DC injoignables | Détecte les DC injoignables puis propose une GPO (fonctionne même si WinRM est totalement arrêté, prise en compte différée) et/ou une activation immédiate via WMI/DCOM — voir [focus dédié](#focus--activer-winrm-sur-les-dc-quand-ils-sont-injoignables). |
| 10 | Exécuter TOUTES les actions SAFE | Enchaîne les actions 1 à 9 (WinRM en premier) avec confirmation globale. |

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
| 14 | Désactiver postes/serveurs ET/OU utilisateurs à partir d'une **date choisie** | Déplace vers des UO dédiées `disable_user` / `disable_computer` + désactive. Garde-fous OU/groupes — voir [focus dédié](#focus--désactivation-par-date-choisie-garde-fous-et-uo-dédiées). |

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

## Menu [4] : Automatisation

Permet de faire tourner la désactivation par ancienneté **sans intervention humaine**, tout en gardant les mêmes garde-fous que l'action manuelle.

| # | Action | Remarque |
|---|--------|----------|
| 1 | Configurer la tâche planifiée de désactivation automatique | Reprend les mêmes questions que l'action manuelle (périmètre users/postes, seuils, UO exclues, groupes exclus), plus l'intervalle entre exécutions et le DC hôte. Crée un gMSA dédié, délègue les droits minimaux nécessaires, déploie le script et crée la tâche planifiée. |
| 2 | Afficher l'état de la tâche planifiée existante | Interroge chaque DC : présence de la tâche, dernière/prochaine exécution, dernier résultat. |
| 3 | Supprimer la tâche planifiée | Arrête uniquement l'automatisation ; les comptes déjà désactivés/déplacés ne sont pas restaurés. |

## Focus : désactivation par date choisie (garde-fous et UO dédiées)

L'action `[2] > 14` désactive les comptes utilisateurs et/ou postes/serveurs **inactifs depuis une date précise que vous choisissez** (au lieu d'un seuil en jours glissant comme l'action `[2] > 11`). Les comptes concernés sont **déplacés dans une UO dédiée et créée automatiquement si absente** (jamais supprimés) :
- `disable_user` pour les comptes utilisateurs,
- `disable_computer` pour les postes/serveurs.

**Garde-fous toujours actifs, non désactivables :**
- `krbtgt`, le compte `Administrateur` et le compte `Invité` intégrés (identifiés par leur RID bien connu 500/501/502, donc indépendants du nom si renommés),
- tous les objets ordinateur des **contrôleurs de domaine**,
- le **compte qui exécute le script** (jamais de risque de se désactiver soi-même),
- tout compte déjà présent dans les UO `disable_user` / `disable_computer` (pas de retraitement).

**Garde-fous configurables à chaque exécution :**
- **UO à exclure** (une liste séparée pour les utilisateurs et pour les postes/serveurs) : par exemple les UO de comptes de service, de serveurs applicatifs critiques, de postes VIP.
- **Groupes à exclure** : une liste de groupes à privilèges est exclue **par défaut** (Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account/Backup/Server Operators, Print Operators, Group Policy Creator Owners, Protected Users, DnsAdmins, Cert Publishers), et des groupes supplémentaires (comptes de service, VIP...) peuvent être ajoutés à la volée.

Avant toute désactivation, un export CSV horodaté (`Logs\Desactivation_ParDate_*.csv`) liste **à la fois** les comptes qui seront traités **et** ceux exclus par un garde-fou (avec la raison), pour permettre une revue complète avant confirmation (`CONFIRMER`).

À chaque désactivation (action `[2] > 11` ou `[2] > 14`, manuelle ou automatisée), le script ajoute la mention `Desactive le : jj/mm/aaaa` dans l'attribut **Description** de l'objet AD (sans écraser une description existante, ajoutée à la suite avec un séparateur `|`), pour tracer directement dans l'annuaire quand chaque compte a été désactivé.

À la fin de l'action, le script propose de basculer directement vers la configuration de l'automatisation (menu `[4] > 1`) pour répéter cette désactivation à intervalle régulier.

### Automatisation : architecture

L'action `[4] > 1` déploie, comme pour la rotation KRBTGT, un **script autonome** sur un contrôleur de domaine choisi, exécuté par une tâche planifiée récurrente :
- Un **gMSA dédié** (nom par défaut `svc-ADAutoDisable`) exécute la tâche — pas de mot de passe à gérer.
- **Délégation minimale** via `dsacls`, limitée à la racine de délégation choisie (racine du domaine par défaut, ou une UO précise) : uniquement l'écriture de la propriété `userAccountControl` (désactivation) et la création/suppression d'objets `User`/`Computer` (nécessaire pour un déplacement `Move-ADObject`) — jamais de droit Domain Admin accordé à la tâche.
- Pour une exécution récurrente, le seuil se base sur une **ancienneté glissante** (X jours sans connexion, recalculée à chaque exécution) plutôt qu'une date fixe, qui n'aurait plus de sens d'une exécution à l'autre.
- Les seuils et exclusions choisis sont figés dans le script déployé ; relancer `[4] > 1` régénère et remplace le script et la tâche avec de nouveaux paramètres.
- Journalisation locale (`C:\ADHC-Scripts\Disable-ByDate.log`) + Event Log applicatif dédié (`ADHC-AutoDisable`), sur le DC hébergeant la tâche.

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
- `Logs\Comptes_Inactifs_*.csv` / `Logs\Desactivation_ParDate_*.csv` : liste des comptes traités (et exclus par garde-fou, avec la raison) avant chaque désactivation par ancienneté / par date choisie.
- `Logs\krbtgt_reset_tracking.log` : horodatage du dernier reset manuel krbtgt, pour planifier le second.
- Sur le DC hébergeant la rotation KRBTGT planifiée : `C:\ADHC-Scripts\Krbtgt-Rotation.log` + journal d'événements `ADHC-KrbtgtRotation`.
- Sur le DC hébergeant l'automatisation de désactivation : `C:\ADHC-Scripts\Disable-ByDate.log` + journal d'événements `ADHC-AutoDisable`.

## Focus : activer WinRM sur les DC quand ils sont injoignables

L'action `[1] > 9` permet d'activer PowerShell Remoting directement depuis le script, sans avoir à se connecter manuellement à chaque DC. Deux méthodes, proposées ensemble ou séparément :

- **[1] Via GPO (recommandée)** : crée/lie une GPO `ADHC - Activation WinRM sur les DC` sur l'OU Domain Controllers. Cette méthode fonctionne **même si WinRM est totalement arrêté** sur la cible, car une GPO est récupérée par le client via SYSVOL/LDAP — elle ne dépend donc pas du remoting lui-même (contrairement à `Invoke-Command`). Elle configure :
  - le démarrage automatique du service WinRM (Préférences de stratégie de groupe, registre `HKLM\SYSTEM\CurrentControlSet\Services\WinRM\Start = 2`) ;
  - la stratégie *"Allow remote server management through WinRM"* (`HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service`), qui crée automatiquement le listener HTTP sur toutes les IP au démarrage du service (équivalent de `winrm quickconfig`, sans avoir à l'exécuter sur le DC) ;
  - une règle de pare-feu entrante pour le port 5985 (`Windows Remote Management (HTTP-In)`), poussée directement dans la GPO via le module `NetSecurity` (`Open-NetGPO` / `New-NetFirewallRule -GPOSession` / `Save-NetGPO`) — si ce module est indisponible ou les droits insuffisants, le script avertit et indique comment l'activer manuellement dans la GPO.

  **Prise en compte différée** : au prochain rafraîchissement de GPO sur chaque DC (`gpupdate /force` ou cycle normal), puis un **redémarrage du service WinRM** (ou du serveur) est nécessaire pour que le nouveau listener soit effectivement créé.

- **[2] Immédiate via WMI/DCOM** : pour ne pas attendre un cycle de GPO, active WinRM tout de suite sur les DC choisis en lançant `winrm quickconfig -quiet -force` et l'activation de la règle de pare-feu à distance via WMI/DCOM (`New-CimSession -SessionOption (New-CimSessionOption -Protocol Dcom)` + `Invoke-CimMethod ... Win32_Process Create`). Cette méthode fonctionne dès lors que **WMI/DCOM (RPC)** est lui-même joignable vers le DC — souvent le cas même quand WinRM ne l'est pas, car les règles de pare-feu AD par défaut autorisent WMI entre postes d'administration et DC. Le script revérifie la connectivité WinRM juste après la tentative.

Choisir `[3]` applique les deux méthodes : l'activation immédiate pour un accès tout de suite, et la GPO pour que la configuration survive à un redémarrage/une réinstallation et couvre aussi les futurs DC ajoutés à l'OU.

## Dépannage : erreur WinRM ("La connexion au serveur distant ... a échoué")

Les actions qui s'exécutent sur les contrôleurs de domaine (`auditpol`, audit NTLM, signature LDAP, Spooler, rotation KRBTGT, automatisation...) passent par `Invoke-Command`, qui nécessite le **PowerShell Remoting (WinRM)** activé sur la cible. Avant de lancer ces actions, le script vérifie désormais la joignabilité WinRM de chaque DC (`Test-WSMan`) et **écarte proprement** les DC injoignables plutôt que d'échouer au milieu de l'action, avec un message rappelant les points à vérifier sur le(s) serveur(s) concerné(s).

**Le script peut désormais corriger cela lui-même** via l'action `[1] > 9` (voir [focus dédié](#focus--activer-winrm-sur-les-dc-quand-ils-sont-injoignables)), qui active WinRM par GPO et/ou immédiatement via WMI/DCOM. En dépannage manuel, les points à vérifier sont les mêmes :

- Le service **WinRM** est démarré (`winrm quickconfig` ou `Enable-PSRemoting -Force` sur le serveur cible).
- La règle de pare-feu **"Gestion à distance de Windows (HTTP-In)"** est activée pour le profil réseau utilisé (Domaine/Privé) — le profil **Public** la bloque par défaut, cas fréquent si l'interface réseau du DC est mal catégorisée.
- Le **nom du DC se résout correctement en DNS** depuis le poste qui lance le script.
- Le serveur est bien **allumé et joignable sur le réseau** (pas de règle de pare-feu réseau bloquant le port 5985/5986 entre le poste et le DC).

> Avant cette vérification préalable, une erreur de connexion sur un DC pouvait passer inaperçue : `Invoke-Command` sans `-ErrorAction Stop` traite un échec de connexion comme une erreur non bloquante, affichée en rouge mais n'interrompant pas le script — qui loggait alors à tort "Terminé (OK)" sans que l'action ait réellement été appliquée sur ce DC. Toutes les commandes distantes du script utilisent maintenant `-ErrorAction Stop`, pour que ce type d'échec soit remonté correctement (log `ERROR`) au lieu d'être silencieusement ignoré.

## Limites connues / points d'attention

- Les GPO créées pour NTLMv1 et LLMNR sont **volontairement non liées automatiquement** (impact potentiellement large) : à lier manuellement sur un OU pilote après validation.
- Le rapport NTLMv1/LM peut être lent sur un DC avec un gros volume de journal Sécurité ; commencer avec une période courte (ex. 2-3 jours) pour valider le fonctionnement.
- La rotation KRBTGT planifiée nécessite un forest functional level ≥ 2012 (gMSA) et une KDS Root Key ; en environnement mono-DC, le script propose de forcer sa disponibilité immédiate (à éviter en production multi-DC, où il vaut mieux laisser les ~10h de propagation naturelle).
- Ce script couvre les constats **récurrents** observés dans les rapports PingCastle fournis ; il ne remplace pas une revue complète du rapport (certains constats très spécifiques à un client ne sont pas automatisés).
