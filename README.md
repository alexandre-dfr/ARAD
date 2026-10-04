# AD_Remediation_Menu.ps1

Script PowerShell à menu pour **auditer et remédier** les constats Active Directory les plus fréquents des rapports **PingCastle** (krbtgt, NTLMv1/LM, comptes inactifs, délégations Kerberos, LAPS, Kerberoasting, dSHeuristics, GPO, SMB/LDAP...).

Il est construit pour qu'aucune action ne parte « par accident » : **mode simulation par défaut**, confirmations renforcées sur tout ce qui a un impact, vérifications préalables, et garde-fous non désactivables sur les objets critiques.

> **Version 3.1** — suppression de nouveaux faux positifs (gMSA, AZUREADSSOACC, groupes absents, cycle de vie des OS figé...), 6 nouveaux contrôles (DCSync, propriétaires des DC, groupe principal caché...), **suivi d'évolution** du diagnostic, rapport HTML interactif, interface enrichie et **tests automatisés**. Voir [Nouveautés v3.1](#nouveautés-v31).
>
> **Version 3.0** — refonte complète : corrections de véracité (plusieurs remédiations faisaient l'inverse de l'effet annoncé ou ne tenaient pas dans la durée), suppression des faux positifs, AD francisé pris en charge, interface pilotée par une table unique, diagnostic rapide noté, rapport HTML, une vingtaine de nouvelles actions. Voir [Nouveautés et corrections v3](#nouveautés-et-corrections-v3).

---

## Sommaire

- [Prérequis](#prérequis)
- [Démarrage rapide](#démarrage-rapide)
- [Interface](#interface)
- [Principes de sécurité](#principes-de-sécurité)
- [Diagnostic rapide et rapport HTML](#diagnostic-rapide-et-rapport-html)
- [Catalogue des actions](#catalogue-des-actions)
- [Focus techniques](#focus-techniques)
- [Journalisation et fichiers produits](#journalisation-et-fichiers-produits)
- [Dépannage WinRM](#dépannage-winrm)
- [Tests automatisés](#tests-automatisés)
- [Nouveautés v3.1](#nouveautés-v31)
- [Nouveautés et corrections v3](#nouveautés-et-corrections-v3)
- [Limites connues](#limites-connues)

---

## Prérequis

- **Windows PowerShell 5.1** (PowerShell 7 fonctionne pour la plupart des actions via la couche de compatibilité), console **lancée en tant qu'administrateur**.
- Module **ActiveDirectory** (RSAT AD DS) — idéalement exécution sur/depuis un contrôleur de domaine.
- Module **GroupPolicy** (RSAT-GPMC) pour les actions qui créent/modifient des GPO.
- Module **LAPS** (Windows LAPS, inclus dans Windows Server 2019+/Windows 10-11 à jour depuis avril 2023) pour le thème LAPS.
- Compte membre de **Admins du domaine** (vérifié via le jeton de session, donc imbrication et AD francisé pris en compte ; avertissement seulement — les audits restent utilisables avec moins de droits).
- **PowerShell Remoting (WinRM)** sur les DC pour les actions distantes (auditpol, NTLM, Spooler, LDAP, NTP...). Le script sait l'activer lui-même (action `8.4`). La machine locale est toujours exécutée sans WinRM.

## Démarrage rapide

```powershell
# Mode interactif (simulation active par défaut)
.\AD_Remediation_Menu.ps1

# Diagnostic express non interactif : tableau de bord + rapport HTML, puis sortie
# Code retour : 0 = aucun constat critique, 2 = au moins un constat critique, 1 = prérequis KO
.\AD_Remediation_Menu.ps1 -QuickAudit

# Lancer directement une action (ici 4.2) puis quitter - simulation par défaut
.\AD_Remediation_Menu.ps1 -Action 4.2

# Options
.\AD_Remediation_Menu.ps1 -LogDir D:\Audit\AD -NoClear
```

| Paramètre | Effet |
|-----------|-------|
| `-QuickAudit` | Lance uniquement le diagnostic rapide (lecture seule), génère le rapport HTML et quitte. Utilisable en tâche planifiée pour un suivi régulier. |
| `-LogDir` | Dossier des journaux et rapports (défaut : `.\Logs`). |
| `-NoClear` | N'efface pas l'écran entre deux menus (garde tout l'historique de la session dans la console). |
| `-Action x.y` | Lance directement l'action `x.y` du catalogue puis quitte (code retour 1 si une écriture a échoué). Simulation par défaut ; `-Simulation:$false` demande la confirmation habituelle `CONFIRMER` pour passer en mode réel. |

> **Suivi régulier** : planifiez `-QuickAudit` (tâche hebdomadaire). Chaque diagnostic est archivé dans `Logs\Diagnostics` : le suivant affiche l'**évolution** (contrôles dégradés / améliorés, écart d'indice) et le rapport HTML trace la **courbe** de l'indice.

## Interface

```
==============================================================================
  REMEDIATION ACTIVE DIRECTORY (base PingCastle)  -  v3.0
==============================================================================
  Mode      : SIMULATION (aucune modification appliquee)
  Domaine   : corp.local   (PDC : dc1.corp.local)
  Operateur : CORP\adm-jdupont
  Session   : 3 action(s) [0 ok / 0 echec / 3 simulee(s)], 5 rapport(s)
  Diagnostic: indice 74/100 - 2 critique(s), 2 alerte(s) - 08:58 (actions concernees marquees '!' dans les menus)
==============================================================================
  Legende : [AUDIT] lecture seule  [SAFE] sans impact prod  [A VALIDER] impact potentiel  [OUTIL]

 MENU PRINCIPAL

 -- IDENTITE ET COMPTES --
   1. Comptes a privileges                            10 audit(s),  7 remediation(s)  ! 1 critique(s)
   2. Comptes de service                               3 audit(s),  5 remediation(s)
   3. Mots de passe et authentification                5 audit(s),  4 remediation(s)  ! 1 alerte(s)
   ...
  [D] Diagnostic rapide note (lecture seule)   [H] Rapport HTML de synthese
  [R] Rechercher une action par mot-cle        [x.y] Acces direct (ex : 4.2)
  [P] Relancer la derniere action              [?] Aide (raccourcis, legende)
  [S] Activer le mode REEL (desactiver la simulation)
  [Q] Quitter
```

- **Marqueurs issus du diagnostic** : après un diagnostic, chaque thème affiche son nombre de constats critiques/alertes, et dans les sous-menus les actions de remédiation correspondantes sont précédées d'un **`!`** rouge (critique) ou jaune (alerte). Chaque action affiche aussi son code `[x.y]`.
- **Raccourcis disponibles partout** (menu principal et sous-menus) : `x.y`, `D`, `H`, `R`, `P` (relancer la dernière action), `?` (aide). Chaque action se termine par un bandeau indiquant sa durée et ses éventuels échecs.
- **Accès direct** : tapez `4.2` (ou `4-2`) depuis n'importe quel menu pour lancer directement l'action 2 du thème 4. Les numéros `x.y` sont ceux du [catalogue](#catalogue-des-actions) et de la colonne *Menu* du diagnostic.
- **Recherche** `[R]` : plusieurs mots-clés possibles (tous requis), recherche dans les libellés et les thèmes ; le résultat se **lance directement** en tapant son numéro (avec ses garde-fous habituels).
- **Sous-menus regroupés par nature** : Audit → Remédiation SAFE → Remédiation A VALIDER → Outils, avec un badge coloré par action.
- **Sélections souples** dans toutes les listes : `0,3,7`, plages `2-6`, `tous`, vide = annuler.
- **Sélecteur d'UO avec filtre** par mot-clé (indispensable au-delà de quelques dizaines d'UO), saisie directe d'un DN possible, et prise en compte des conteneurs par défaut `CN=Computers` / `CN=Users` (qui ne sont pas des UO et étaient auparavant impossibles à cibler).
- **Ciblage des machines** (actions sur postes/serveurs) : par UO **ou** par saisie directe de noms (pilote sur 1-2 machines).
- **Synthèse de fin de session** à la sortie, avec proposition de générer le rapport HTML.

## Principes de sécurité

- **Mode simulation par défaut** : rien n'est modifié tant que vous n'avez pas basculé en mode réel via `[S]` + `CONFIRMER`. En simulation, le journal indique précisément ce qui *serait* fait, et les messages de résultat sont requalifiés (`[SIMULATION] En mode reel : ...`) pour ne jamais laisser croire qu'une action a été appliquée.
- **Confirmations graduées** : `[SAFE]` = O/N ; `[A VALIDER]` = saisie exacte de `CONFIRMER` en mode réel (en simulation, un simple `O` suffit pour dérouler le scénario).
- **Pas de faux succès** : toute action d'écriture s'exécute avec `ErrorActionPreference = Stop` ; une erreur *non bloquante* d'une cmdlet est donc comptée comme un échec (auparavant elle était suivie d'un « Terminé » erroné). Les messages de résultat sont remplacés par un avertissement si une étape a échoué.
- **Pas de faux « OK »** : un groupe illisible, un SYSVOL inaccessible ou un DC injoignable produisent un avertissement ou un statut `ERREUR`, jamais un « conforme ».
- **Garde-fous non désactivables** sur les désactivations de comptes : Administrateur/Invité/krbtgt (RID 500/501/502), DC et RODC, compte qui exécute le script, comptes d'approbation (trusts), objets de cluster (CNO/VCO), membres des groupes à privilèges (résolus par SID).
- **Aucune suppression** : les comptes inactifs sont désactivés, annotés (`Desactive le : jj/mm/aaaa (SEC)` dans la description) et déplacés en UO de quarantaine — retour arrière documenté dans le CSV de revue.
- **Sauvegarde avant modification sensible** : la GPO *Default Domain Policy* est sauvegardée automatiquement avant toute modification de la politique de mot de passe ; sauvegarde complète des GPO en un clic (`10.2`).
- **Indépendance de la langue de l'OS** : groupes résolus par SID bien connu, sous-catégories d'audit par GUID, événements lus par champs XML, partages comparés par SID, groupe Administrateurs local par SID `S-1-5-32-544`.
- **Scripts déployés protégés** : les scripts exécutés par les tâches planifiées (dossier `C:\SEC-Scripts` sur le DC) ont un ACL restreint à SYSTEM et aux Administrateurs.
- **Aucune action ne fait quitter le script** : toute erreur inattendue est interceptée, journalisée avec son emplacement, et l'on revient au menu.

## Diagnostic rapide et rapport HTML

`[D]` (ou `16.3`) lance une trentaine de contrôles **en lecture seule, sans WinRM** (LDAP + SYSVOL), classés `CRITIQUE` / `ALERTE` / `INFO` / `OK` / `ERREUR`, chacun avec une recommandation et le numéro de l'action de remédiation correspondante :

krbtgt (âge), corbeille AD, dernière sauvegarde AD (métadonnées `dSASignature`, indépendantes de l'outil de sauvegarde) vs durée de vie des tombstones, nombre de DC, santé de la réplication, niveau fonctionnel, MachineAccountQuota, compte Invité, compte Administrateur intégré, membres Domain Admins / Schema Admins / groupes opérateurs, comptes à privilèges (SPN, délégables, mot de passe > 1 an, hors Protected Users), adminCount orphelins, « Accès compatible pré-Windows 2000 », AS-REP Roasting, délégations (non contrainte hors DC, vers un DC, RBCD sur DC, transition de protocole), comptes Kerberoastables faibles, sIDHistory dangereux, approbations sans filtrage SID, politique de mot de passe, chiffrement réversible / mot de passe non requis / DES, mots de passe GPP (`cpassword`), dSHeuristics (LDAP anonyme, AdminSDExMask), couverture et péremption LAPS, comptes inactifs, OS hors support (dont DC).

Un **indice indicatif d'hygiène** (100 − 10 par critique − 3 par alerte) est affiché ; ce n'est **pas** le score PingCastle.

Contrôles ajoutés en v3.1 : **droits DCSync / contrôle de la racine du domaine** (ACL), **propriétaires des objets DC**, **groupe principal non standard** (appartenance cachée), **comptes à privilèges inactifs ou désactivés**, utilisateurs au mot de passe n'expirant jamais, **mots de passe dans la description/les notes**. Un contrôle qui ne peut pas être réalisé (droits, connectivité, liste des DC illisible...) est toujours `ERREUR`, jamais `OK`.

Après le tableau, un **plan d'action prioritaire** liste les constats critiques puis les alertes avec le numéro d'action à saisir. Si un diagnostic précédent du même domaine existe (`Logs\Diagnostics`), une colonne **ÉVOL.** indique pour chaque contrôle `PIRE` / `MIEUX` / `=` / `NOUV.`, suivie de l'écart d'indice. L'action `16.5` affiche l'historique complet (courbe en mode texte, export CSV).

`[H]` (ou `16.4`) génère un **rapport HTML autonome** (aucune dépendance externe, fonctionne hors ligne, mode sombre automatique, lisible sur mobile, imprimable) : indice et écart avec le diagnostic précédent, indicateurs **cliquables pour filtrer** par statut, **recherche** instantanée, plan d'action, colonne d'évolution, **courbe de l'indice** sur les 30 derniers diagnostics, historique des actions de la session et liste des rapports CSV produits.

## Catalogue des actions

Légende : **Audit** = lecture seule · **SAFE** = sans impact prod (O/N) · **A VALIDER** = impact potentiel (`CONFIRMER`) · **Outil** = documentation/outillage. Le numéro `x.y` est utilisable directement depuis le menu principal.

### 1. Comptes a privileges

| # | Type | Action |
|---|------|--------|
| 1.1 | Audit | Export des membres des groupes a privileges (actifs/desactives, SPN...) |
| 1.2 | Audit | Nombre de membres Domain Admins / Enterprise Admins (vs seuil) |
| 1.3 | Audit | Usage du compte Administrateur integre (RID 500) |
| 1.4 | Audit | Comptes a privileges potentiellement non nominatifs/partages |
| 1.5 | Audit | Risque Kerberoasting sur les comptes a privileges |
| 1.6 | A VALIDER | Marquer les comptes a privileges 'Sensible, ne peut etre delegue' |
| 1.7 | A VALIDER | Ajouter les comptes Domain/Enterprise Admins dans 'Protected Users' |
| 1.8 | A VALIDER | Nettoyer le groupe Schema Admins |
| 1.9 | A VALIDER | Forcer l'expiration des mots de passe des comptes a privileges |
| 1.10 | A VALIDER | Desactiver le compte Administrateur integre (RID 500) |
| 1.11 | A VALIDER | Restreindre les comptes a privileges a des postes dedies (PAW) |
| 1.12 | Audit | Comptes 'adminCount=1' orphelins (anciens administrateurs) |
| 1.13 | Audit | Groupes sensibles : pre-Windows 2000, DnsAdmins, operateurs, GPCO |
| 1.14 | A VALIDER | Nettoyer les comptes 'adminCount=1' orphelins (heritage ACL) |
| 1.15 | Audit | Droits DCSync et controle de la racine du domaine (ACL) *(v3.1)* |
| 1.16 | Audit | Comptes a privileges inactifs ou desactives *(v3.1)* |
| 1.17 | Audit | Groupe principal non standard (appartenance privilegiee cachee) *(v3.1)* |

### 2. Comptes de service

| # | Type | Action |
|---|------|--------|
| 2.1 | Audit | Inventaire des comptes de service (SPN / UO choisies) |
| 2.2 | Audit | Comptes de service en chiffrement faible (RC4/DES, sans cle AES) |
| 2.3 | A VALIDER | Forcer AES sur les comptes selectionnes (AES seul ou AES+RC4) |
| 2.4 | A VALIDER | Interdire la connexion interactive/RDP des comptes selectionnes (GPO) |
| 2.5 | A VALIDER | Retirer les comptes de service des groupes a privileges |
| 2.6 | A VALIDER | Reinitialiser le mot de passe des comptes selectionnes |
| 2.7 | A VALIDER | Assistant de creation d'un compte de service gere (gMSA) |
| 2.8 | Audit | Comptes Kerberoastables (tous comptes avec SPN, priorises) |

### 3. Mots de passe et authentification

| # | Type | Action |
|---|------|--------|
| 3.1 | Audit | Rapport des comptes avec mot de passe n'expirant jamais |
| 3.2 | Audit | Audit de la politique de mot de passe (effective, GPO, FGPP) |
| 3.3 | SAFE | Retirer le flag 'Mot de passe non requis' sur les comptes concernes |
| 3.4 | A VALIDER | Corriger la politique de mot de passe par defaut (GPO + domaine) |
| 3.5 | A VALIDER | Creer une Fine-Grained Password Policy pour les comptes de service |
| 3.6 | Outil | Generer les recommandations MFA / Conditional Access (hybride) |
| 3.7 | Audit | Mots de passe GPP (cpassword) dans SYSVOL |
| 3.8 | Audit | Hygiene des mots de passe (chiffrement reversible, non requis, DES...) |
| 3.9 | A VALIDER | Retirer le chiffrement reversible des mots de passe |
| 3.10 | Audit | Mots de passe stockes dans la description/les notes (heuristique) *(v3.1)* |

### 4. Kerberos et delegations

| # | Type | Action |
|---|------|--------|
| 4.1 | Audit | Rapport des delegations Kerberos (non contrainte/contrainte/RBCD) |
| 4.2 | Audit | Audit AS-REP Roasting (comptes sans pre-authentification) |
| 4.3 | Audit | Audit des approbations (filtrage SID, delegation TGT, chiffrement) |
| 4.4 | A VALIDER | Reinitialiser le mot de passe KRBTGT (1 des 2 executions requises) |
| 4.5 | A VALIDER | Configurer la rotation KRBTGT automatique planifiee |
| 4.6 | A VALIDER | Desactiver DES et forcer AES sur les comptes concernes |
| 4.7 | A VALIDER | Corriger l'exposition AS-REP Roasting |
| 4.8 | A VALIDER | Activer Kerberos Armoring (FAST) |
| 4.9 | Audit | Etat du krbtgt (age, RODC) et de la replication |
| 4.10 | Audit | Comptes porteurs d'un sIDHistory |
| 4.11 | A VALIDER | Supprimer des entrees sIDHistory |
| 4.12 | A VALIDER | Retirer la delegation non contrainte (hors DC) |

### 5. NTLM / LM

| # | Type | Action |
|---|------|--------|
| 5.1 | SAFE | Activer l'audit NTLM (detection avant tout blocage) |
| 5.2 | Audit | Rapport NTLMv1/LM detecte (journal Securite des DC) |
| 5.3 | A VALIDER | Desactiver NTLMv1/LM (LmCompatibilityLevel) via GPO |
| 5.4 | A VALIDER | Restreindre le NTLM sortant des DC (Refuser + exceptions) |
| 5.5 | Audit | Configuration NTLM effective sur les DC |

### 6. SMB, SYSVOL et NETLOGON

| # | Type | Action |
|---|------|--------|
| 6.1 | Audit | Detection de l'usage SMBv1 (clients, par DC) |
| 6.2 | Audit | Etat de la signature SMB (client/serveur) sur les DC |
| 6.3 | Audit | Audit des partages SMB trop ouverts sur des machines choisies |
| 6.4 | A VALIDER | Desactiver SMBv1 (client + serveur) sur les DC |
| 6.5 | A VALIDER | Desactiver SMBv1 sur des postes/serveurs choisis |
| 6.6 | A VALIDER | Forcer la signature SMB (client + serveur) via GPO |
| 6.7 | A VALIDER | Durcir les chemins UNC SYSVOL/NETLOGON (Hardened UNC Paths) |

### 7. LDAP / LDAPS

| # | Type | Action |
|---|------|--------|
| 7.1 | Audit | Audit des certificats LDAPS et negociation TLS sur le port 636 |
| 7.2 | Audit | Binds LDAP non signes / en clair (resume 2887 + clients 2889) |
| 7.3 | A VALIDER | Exiger la signature LDAP / channel binding sur les DC |
| 7.4 | A VALIDER | Desactiver TLS 1.0/1.1 et activer TLS 1.2 (SCHANNEL + .NET) |
| 7.5 | A VALIDER | Interdire les operations LDAP anonymes (dSHeuristics) |
| 7.6 | Audit | dSHeuristics et configuration LDAP des DC |

### 8. Controleurs de domaine

| # | Type | Action |
|---|------|--------|
| 8.1 | Audit | Correctifs installes sur les DC (dernier correctif) |
| 8.2 | Audit | Etat de la synchronisation horaire (NTP) |
| 8.3 | Audit | Roles et fonctionnalites a risque installes sur les DC |
| 8.4 | SAFE | Activer PowerShell Remoting (WinRM) sur les DC injoignables |
| 8.5 | SAFE | Desactiver le compte Invite (Guest) s'il est actif |
| 8.6 | SAFE | Proteger toutes les OU contre la suppression accidentelle |
| 8.7 | SAFE | Limiter le quota de creation d'ordinateurs (MachineAccountQuota = 0) |
| 8.8 | A VALIDER | Arreter/desactiver le service Spooler sur les DC |
| 8.9 | A VALIDER | Configurer la source NTP externe du PDC Emulator |
| 8.10 | A VALIDER | Activer le pare-feu Windows (3 profils) sur les DC |
| 8.11 | Audit | Matrice de durcissement des DC (Spooler, SMB, LDAP, NTLM, pare-feu...) |
| 8.12 | Audit | Sante de la replication, niveaux fonctionnels et roles FSMO |
| 8.13 | Audit | Proprietaires des objets ordinateur des DC *(v3.1)* |

### 9. Windows LAPS

| # | Type | Action |
|---|------|--------|
| 9.1 | Audit | Etat du deploiement LAPS (schema, couverture, mots de passe perimes) |
| 9.2 | Audit | Audit des droits de lecture du mot de passe LAPS |
| 9.3 | A VALIDER | Preparer le schema Active Directory pour Windows LAPS |
| 9.4 | A VALIDER | Deployer la GPO Windows LAPS (+ droit d'ecriture des ordinateurs) |
| 9.5 | A VALIDER | Configurer les droits de lecture/reset LAPS |

### 10. GPO de durcissement (socle GPO-SEC-*)

| # | Type | Action |
|---|------|--------|
| 10.1 | Audit | Etat du socle GPO-SEC-* et des sauvegardes de GPO |
| 10.2 | SAFE | Sauvegarder TOUTES les GPO du domaine |
| 10.3 | SAFE | Creer les GPO manquantes du socle GPO-SEC-* (non liees) |
| 10.4 | Audit | Hygiene des GPO (non liees, vides, modifiables par des non-admins) |

### 11. Postes et serveurs membres

| # | Type | Action |
|---|------|--------|
| 11.1 | Audit | Etat de Microsoft Defender sur des machines choisies |
| 11.2 | Audit | Audit des administrateurs locaux sur des machines choisies |
| 11.3 | A VALIDER | Renforcer Microsoft Defender via GPO (Cloud/Reseau/SmartScreen/ASR) |
| 11.4 | A VALIDER | Restreindre RDP via GPO (NLA, TLS, chiffrement eleve) |
| 11.5 | A VALIDER | Retirer des comptes des administrateurs locaux |
| 11.6 | SAFE | Etendre la journalisation PowerShell aux postes/serveurs choisis |
| 11.7 | A VALIDER | Bloquer les scripts .vbs/.js (Windows Script Host) |
| 11.8 | A VALIDER | Activer le pare-feu Windows (3 profils) |

### 12. Reseau et anti-relay

| # | Type | Action |
|---|------|--------|
| 12.1 | Audit | Audit de la Global Query Block List DNS (WPAD/ISATAP) |
| 12.2 | Audit | Audit des ports/services exposes sur les DC |
| 12.3 | A VALIDER | Desactiver LLMNR (et mDNS) via GPO |
| 12.4 | SAFE | Retablir la Global Query Block List (wpad/isatap) |
| 12.5 | A VALIDER | Desactiver NetBIOS sur TCP/IP sur des machines choisies |
| 12.6 | A VALIDER | Durcir RPC (clients non authentifies) - serveurs membres |
| 12.7 | A VALIDER | Durcir WinRM (authentification Basic desactivee, trafic chiffre) |
| 12.8 | A VALIDER | Restreindre l'enumeration distante SAM/SAMR |

### 13. Sauvegarde et resilience AD

| # | Type | Action |
|---|------|--------|
| 13.1 | Audit | Etat des sauvegardes AD (metadonnees annuaire + Windows Server Backup) |
| 13.2 | SAFE | Activer la Corbeille Active Directory |
| 13.3 | A VALIDER | Planifier une sauvegarde System State quotidienne |
| 13.4 | Outil | Generer les procedures de recuperation (objet / DC / foret) |

### 14. Obsolescence

| # | Type | Action |
|---|------|--------|
| 14.1 | Audit | Inventaire des systemes d'exploitation hors / bientot hors support |
| 14.2 | Audit | Protocoles obsoletes actifs sur des machines choisies (SMBv1, TLS 1.0/1.1) |
| 14.3 | Outil | Generer le plan de traitement de l'obsolescence (consolide) |

### 15. Journalisation et detection

| # | Type | Action |
|---|------|--------|
| 15.1 | Audit | Audit du SACL des objets sensibles (racine, AdminSDHolder, GPO) |
| 15.2 | SAFE | Activer l'audit avance sur les DC (auditpol + taille du journal) |
| 15.3 | SAFE | Activer la journalisation PowerShell (Script Block + modules) |
| 15.4 | A VALIDER | Configurer l'audit SACL sur les objets sensibles |
| 15.5 | A VALIDER | Configurer la redirection des journaux vers un collecteur (WEF/SIEM) |
| 15.6 | Audit | Politique d'audit EFFECTIVE sur les DC |

### 16. Controle final

| # | Type | Action |
|---|------|--------|
| 16.1 | Audit | Lancer le controle final consolide (+ rapport HTML) |
| 16.2 | Outil | Registre des exceptions (consulter / ajouter) |
| 16.3 | Audit | Diagnostic rapide note (tableau de bord, LDAP uniquement) |
| 16.4 | Outil | Generer le rapport HTML de synthese (diagnostic + session) |
| 16.5 | Audit | Historique des diagnostics (evolution de l'indice et des constats) *(v3.1)* |

### 17. Rapports transverses

| # | Type | Action |
|---|------|--------|
| 17.1 | Audit | Export des comptes inactifs (utilisateurs/ordinateurs) |
| 17.2 | Audit | Export global (rapports rapides multi-themes) |
| 17.3 | Outil | Ouvrir le dossier des rapports de la session |

### 18. Hygiene des comptes inactifs et automatisation

| # | Type | Action |
|---|------|--------|
| 18.1 | A VALIDER | Desactiver les comptes inactifs par anciennete (quarantaine) |
| 18.2 | A VALIDER | Desactiver postes/utilisateurs a partir d'une DATE choisie |
| 18.3 | A VALIDER | Configurer la tache planifiee de desactivation automatique |
| 18.4 | Audit | Etat des taches planifiees deployees par le script |
| 18.5 | A VALIDER | Supprimer une tache planifiee deployee par le script |


## Focus techniques

### Groupes et AD francisé
Les noms de groupes intégrés sont **localisés** sur un AD installé en français (« Admins du domaine », « Administrateurs »...). La v2 interrogeait ces groupes par leur nom anglais : sur un AD francisé, les requêtes échouaient silencieusement (groupes vus comme vides, garde-fous d'exclusion inopérants, faux avertissement « n'est pas membre de Domain Admins » au démarrage). Tous les groupes sont désormais résolus par **SID bien connu** (`<domaine>-512`, `<racine>-519`, `S-1-5-32-544`...), les groupes de forêt étant interrogés sur le domaine racine.

### Politique de mot de passe du domaine (`3.4`)
La politique de mot de passe est portée par la GPO **Default Domain Policy** : le PDC réapplique ses valeurs sur l'objet domaine à chaque rafraîchissement. Modifier seulement l'objet domaine (comportement v2) était donc **annulé en quelques minutes à quelques heures**. Le script sauvegarde la GPO, met à jour son modèle de sécurité (`GptTmpl.inf`, édition ligne à ligne qui préserve le reste du fichier, extension côté client *Security* déclarée, numéro de version incrémenté), puis met aussi à jour l'objet domaine pour un effet immédiat. Longueur limitée à 14 (au-delà : FGPP, `3.5`). L'audit `3.2` affiche côte à côte la valeur effective et celle de la GPO.

### Rotation KRBTGT (`4.4`, `4.5`, `4.9`)
- **Reset manuel** : exécuté sur le PDC, précédé d'une vérification de la réplication (cmdlets `Get-ADReplicationPartnerMetadata` / `Get-ADReplicationFailure`, indépendantes de la langue), et **bloqué si le dernier reset date de moins de 10 h** (un second reset trop rapproché invalide tous les tickets en circulation) sauf saisie de `FORCER` (compromission avérée).
- **Rotation planifiée** : la v2 déléguait « Reset Password » sur `krbtgt` à un gMSA. Or `krbtgt` est protégé par **AdminSDHolder** : SDProp réécrit son ACL toutes les 60 minutes et la délégation disparaissait — la tâche aurait échoué à chaque exécution. La v3 exécute la tâche sous **SYSTEM sur un DC inscriptible** (contrôle total sur les objets protégés), dans un dossier à ACL restreinte ; chaque exécution vérifie la réplication et refuse deux resets à moins de 24 h d'écart.

### Désactivation des comptes inactifs (`18.x`, `17.1`)
Logique commune aux actions manuelles, au rapport et au script planifié :
- inclut les comptes **jamais connectés** (auparavant ignorés : `lastLogonTimestamp` vide) sauf s'ils ont été créés après la date seuil ;
- exclut les comptes dont le **mot de passe a changé après la date seuil** (un ordinateur vivant renouvelle son mot de passe tous les 30 jours : supprime les faux positifs de machines simplement peu connectées) ;
- exclut **comptes d'approbation** (désactiver un compte de trust casse l'approbation), **DC/RODC**, **objets de cluster** (CNO/VCO, dont le `lastLogonTimestamp` reste ancien), **comptes de service gérés** (gMSA/MSA/dMSA, renvoyés par `Get-ADComputer`), le compte **`AZUREADSSOACC$`** (Seamless SSO Entra : jamais « connecté » mais indispensable), les comptes `krbtgt*`, comptes système et groupes exclus — y compris dans le script de la tâche planifiée ;
- refuse un seuil < 30 jours (`lastLogonTimestamp` est répliqué avec jusqu'à 14 jours de retard) ;
- CSV de revue listant aussi les **exclus avec leur motif**, sélection partielle possible avant confirmation.

L'automatisation (`18.3`) propose un **mode « rapport seul »** (recommandé les premières semaines), s'exécute par défaut sous **SYSTEM** du DC (option gMSA à moindre privilège, avec délégation étendue à l'écriture de la description — sans laquelle la v2 désactivait le compte sans le déplacer — et rappel du droit « Ouvrir une session en tant que tâche » indispensable au gMSA), crée les UO de quarantaine à la configuration, et **abandonne l'exécution si un groupe d'exclusion est illisible**.

### dSHeuristics (`7.5`, `7.6`)
Le 7e caractère de `dSHeuristics` à **`2` AUTORISE** les opérations LDAP anonymes (KB326690 ; elles sont interdites par défaut depuis Windows Server 2003). La v2 positionnait ce caractère à `2` en pensant les restreindre — elle **ouvrait donc l'accès anonyme**. La v3 remet ce caractère à `0` uniquement s'il vaut `2` (sinon rien à faire), en conservant les autres caractères, et audite aussi `AdminSDExMask` (16e caractère).

### Approbations (`4.3`)
Évaluation à partir des bits `trustAttributes` : intra-forêt = pas de filtrage SID par conception (plus signalé comme anomalie) ; approbation de forêt = risque si `TREAT_AS_EXTERNAL` (SID History accepté — la v2 interprétait ce bit comme « filtrage actif », à l'inverse de sa signification) ; approbation externe = risque si la quarantaine est désactivée ; seules les approbations sortantes/bidirectionnelles exposent le domaine. Délégation TGT et absence d'AES signalées.

### Délégations Kerberos (`4.1`, `4.12`)
Les DC possèdent **normalement** la délégation non contrainte : ils ne sont plus comptés comme risque. Sont distingués : non contrainte hors DC (critique), contrainte avec **transition de protocole**, délégation vers un **service d'un DC** et **RBCD sur un DC/krbtgt** (critiques), avec la liste des principaux autorisés pour la RBCD.

### Chiffrement Kerberos / AES (`2.2`, `2.3`, `4.6`)
Un compte dont le mot de passe est **antérieur à l'introduction d'AES dans le domaine** (approximation : date de création du groupe *Read-only Domain Controllers*, méthode PingCastle) n'a **aucune clé AES** : forcer « AES uniquement » casserait son authentification. Le script le détecte, propose de l'exclure ou de choisir AES+RC4 (valeur 28) comme étape transitoire. `krbtgt` et les comptes d'approbation ne sont plus jamais traités comme comptes de service (ils portent un SPN `kadmin/changepw`).

### Rapport NTLMv1 (`5.1`, `5.2`)
L'audit NTLM utilise désormais `AuditNTLMInDomain = 7` (« activer tout ») : la valeur 1 de la v2 ne couvrait que les comptes du domaine vers les serveurs du domaine. Le rapport **exclut les ouvertures de session anonymes** (`S-1-5-7`), journalisées « NTLM V1 » par Windows sans réel usage NTLMv1 (faux positif classique), distingue « aucun événement » d'une erreur de lecture, et signale un journal Sécurité trop petit pour couvrir la période demandée.

### LDAP (`7.1` à `7.6`)
Test d'une **vraie négociation TLS** sur 636 (et non d'une simple ouverture de port), lecture de l'événement **2889** (détail IP + compte de chaque client non conforme, en plus du résumé 2887), channel binding en deux étapes (« lorsque pris en charge » puis « toujours »), désactivation TLS 1.0/1.1 accompagnée du TLS fort **.NET** (`SchUseStrongCrypto`) pour ne pas casser les applications .NET.

### Postes, serveurs et DC
- **Spooler (`8.8`)** : les imprimantes virtuelles locales (PDF, XPS, OneNote, Fax) ne déclenchent plus l'alerte « serveur d'impression » ; seules les imprimantes partagées/réelles le font.
- **Rôles des DC (`8.3`)** : seuls les rôles hors socle et une liste de fonctionnalités à risque sont signalés (la v2 signalait quasiment toutes les fonctionnalités installées par défaut).
- **Matrice de durcissement (`8.11`)** : une passe sur tous les DC (Spooler, SMBv1, signatures SMB/LDAP, channel binding, LmCompatibilityLevel, pare-feu, taille du journal Sécurité, dernier redémarrage).
- **Kerberos Armoring (`4.8`)** : clés de registre corrigées (`...\Policies\System\KDC\Parameters` + `CbacAndArmorLevel`, `...\Policies\System\Kerberos\Parameters` côté client) — celles de la v2 n'étaient lues par aucun composant.
- **Journalisation PowerShell** : ajout de `ModuleNames = *`, sans lequel la journalisation des modules n'enregistre rien.
- **Audit avancé (`15.2`)** : correction du GUID « Sensitive Privilege Use » (la v2 activait en réalité « Authentication Policy Change »), ajout de *Process Creation* et *Audit Policy Change*, journal Sécurité porté à 1 Go minimum ; nouvel audit de la politique **effective** (`15.6`, via `auditpol /backup`, indépendant de la langue).
- **SACL (`15.1`, `15.4`)** : « Tout le monde » résolu par SID (`S-1-1-0`) — le nom anglais échouait sur un OS français.
- **Windows LAPS (`9.4`)** : accorde aux ordinateurs le droit d'écrire leur mot de passe (`Set-LapsADComputerSelfPermission`), sans lequel aucun mot de passe n'est sauvegardé ; option de chiffrement (niveau 2016+) ; la couverture `9.1` exclut les DC, compte aussi LAPS legacy et détecte les mots de passe expirés (client LAPS en échec).
- **RPC (`12.6`)** : avertissement si la GPO cible les DC (paramètres recommandés pour les serveurs membres uniquement).
- **Sauvegarde (`13.1`)** : date de dernière sauvegarde lue dans l'annuaire (tous outils de sauvegarde), comparée à la durée de vie des tombstones ; le parseur `wbadmin` (dépendant de la langue, qui retenait la *plus ancienne* version) est remplacé par le journal `Microsoft-Windows-Backup`.
- **Obsolescence (`14.1`)** : statut **calculé à la date du jour** à partir d'une table de cycle de vie (`$Script:OsLifecycle`) tenant compte du **numéro de build** (Windows 10 LTSC/IoT, versions de Windows 11) et de l'**édition** (calendrier étendu Entreprise/Éducation de Windows 11) : `EOL`, `BIENTOT` (fin dans moins d'un an), `SUPPORTE`. Le statut ne se périme plus avec le temps.

## Journalisation et fichiers produits

| Emplacement | Contenu |
|-------------|---------|
| `Logs\Remediation_AD_<horodatage>.log` | Journal complet de la session (y compris simulation). |
| `Logs\Rapports_<horodatage>\*.csv` | Tous les rapports de la session (séparateur `;`, UTF-8 BOM : ouverture directe dans Excel FR). |
| `Logs\Rapports_<horodatage>\Synthese_AD_*.html` | Rapport HTML de synthèse. |
| `Logs\Diagnostics\Diagnostic_<domaine>_<horodatage>.json` | Historique des diagnostics (évolution, courbe du rapport HTML, `16.5`). |
| `Logs\GPO_Backups\` | Sauvegardes de GPO (complètes `10.2`, et automatique de la Default Domain Policy avant `3.4`). |
| `Logs\Procedures\` | Procédures de récupération (objet / DC / forêt) et recommandations MFA. |
| `Logs\Registre_Exceptions.csv` | Registre des risques acceptés (`16.2` : consultation, ajout guidé, alerte sur les revues échues). |
| `Logs\krbtgt_reset_tracking.log` | Horodatage et auteur de chaque reset krbtgt manuel. |
| `C:\SEC-Scripts\` (sur le DC) | Scripts des tâches planifiées, journaux `Krbtgt-Rotation.log` / `Disable-ByDate.log`, CSV de chaque exécution automatique. |
| Journal *Application* du DC | Sources `SEC-KrbtgtRotation` (1001 = échec) et `SEC-AutoDisable` (2001 = échec) : à superviser. |

## Dépannage WinRM

Les actions distantes vérifient au préalable la joignabilité WinRM (`Test-WSMan`) et écartent proprement les machines injoignables. L'action `8.4` active WinRM sur les DC :
- **[1] par GPO** (fonctionne même si WinRM est arrêté : service WinRM automatique, listener via « Autoriser la gestion à distance du serveur via WinRM », règle de pare-feu 5985) — effet au prochain `gpupdate` + redémarrage du service WinRM ;
- **[2] immédiatement par WMI/DCOM** (`winrm quickconfig` + règle de pare-feu activée par son **nom interne**, indépendant de la langue), avec attente active de la disponibilité (60 s max).

En dépannage manuel : service WinRM démarré (`Enable-PSRemoting -Force`), règle « Gestion à distance de Windows (HTTP-In) » active sur le profil réseau utilisé (le profil *Public* la bloque), résolution DNS du nom du DC, port 5985 ouvert entre le poste et le DC.

## Tests automatisés

```powershell
.\Tests\Invoke-SelfTest.ps1     # Windows PowerShell 5.1 ou PowerShell 7 (Windows/Linux), sans AD ni Pester
```

Une quarantaine de tests sans dépendance vérifient : syntaxe et encodage (UTF-8 BOM pour PowerShell 5.1), cohérence des menus (chaque entrée pointe vers une fonction existante, pas de doublon), **validité de chaque renvoi `x.y` du diagnostic**, sélections (`0,3`, `2-6`, `tous`), table de cycle de vie des OS à date fixe, extraction GPP, évaluation sIDHistory, distinction gMSA/DC/cluster/SSO, détection de mots de passe sans fuite du secret, indice et évolution du diagnostic, historique JSON, et rapport HTML (contenu échappé, aucune dépendance externe, JavaScript valide si Node.js est présent). Code retour 0 = succès. Le script peut être chargé par dot-sourcing (`. .\AD_Remediation_Menu.ps1`) sans lancer le menu.

## Nouveautés v3.1

**Faux positifs / véracité**
- **gMSA, MSA et dMSA** (qui dérivent de la classe `computer`) n'étaient pas distingués des ordinateurs : comptés « non couverts » par LAPS, proposés à la **désactivation comme inactifs** (y compris par la tâche planifiée) et listés dans l'inventaire des OS → exclus partout.
- **`AZUREADSSOACC$`** (Seamless SSO Entra ID) proposé à la désactivation et compté sans LAPS → exclu (sa désactivation casse l'authentification unique).
- Couverture LAPS : objets de **cluster** et machines **non-Windows** exclus du calcul (affichés à part).
- Groupes **inexistants** (Key Admins avant le niveau 2016, DnsAdmins sans DNS intégré) : n'émettent plus d'avertissement « lecture impossible » et ne font plus passer le contrôle du diagnostic en `ERREUR`.
- Diagnostic : une liste de DC illisible donnait « 0 DC inscriptible » (`ALERTE` erronée) → `ERREUR`.
- **Mots de passe GPP** : le compte du premier élément du fichier était attribué à tous les mots de passe trouvés → compte de chaque élément ; les `cpassword` vides ne sont plus comptés.
- **Cycle de vie des OS** figé dans des libellés (ex. « bientôt » restait affiché après la date) → calculé à la date du jour, avec édition Windows 11 et Windows 10 IoT LTSC.
- **sIDHistory** : le diagnostic et l'audit n'utilisaient pas la même liste de RID privilégiés → règle unique (et RID 526/527 ajoutés).
- Kerberoasting (diagnostic) : comptes sans date de mot de passe comptés à tort.
- `krbtgt_AzureAD` (Entra Kerberos) et krbtgt de RODC orphelins étaient étiquetés « RODC : » vide → libellés exacts.

**Nouveaux contrôles** : `1.15` droits DCSync / Contrôle total / WriteDacl / WriteOwner sur la racine du domaine (les comptes de synchronisation Entra `MSOL_*` / `provAgentgMSA` sont identifiés et signalés en alerte plutôt qu'en critique) ; `1.16` comptes à privilèges inactifs ou désactivés ; `1.17` groupe principal non standard ; `3.10` mots de passe dans description/notes (extrait masqué, jamais le secret) ; `8.13` propriétaires des objets DC ; `16.5` historique des diagnostics. Tous sont aussi intégrés au diagnostic rapide.

**Interface** : marqueurs `!` et compteurs par thème issus du dernier diagnostic, ligne « Diagnostic » dans l'en-tête, code `[x.y]` affiché sur chaque action, raccourcis communs à tous les menus (`P` relancer, `?` aide), écran d'aide, bandeau de fin d'action (durée, échecs), plan d'action prioritaire et colonne d'évolution dans le diagnostic, rapport HTML interactif (filtres, recherche, courbe, mobile, impression), paramètre `-Action`.

**Code** : liste des DC mise en cache pour la session (une requête au lieu d'une par action), raccourcis `D`/`H` résolus par nom de fonction (plus d'index codés en dur), gestion des raccourcis factorisée (une seule fonction pour tous les menus), suppression du code mort (`Select-AccountsInteractive`), script chargeable par dot-sourcing pour les tests.

## Nouveautés et corrections v3

**Corrections de véracité (effet réel ≠ effet annoncé)**
- `dSHeuristics` : l'action « restreindre l'anonyme » **ouvrait** l'accès LDAP anonyme → corrigé.
- Rotation krbtgt planifiée : délégation effacée par AdminSDHolder → exécution sous SYSTEM.
- Politique de mot de passe : modification annulée par la Default Domain Policy → écriture dans la GPO.
- Approbations : bit `TREAT_AS_EXTERNAL` interprété à l'envers ; trusts intra-forêt signalés à tort.
- Kerberos Armoring : clés de registre sans effet → clés de la stratégie officielle.
- Audit avancé : mauvais GUID pour « Sensitive Privilege Use ».
- Audit NTLM : `AuditNTLMInDomain=1` (partiel) → `7`.
- Journalisation des modules PowerShell sans liste de modules (aucun effet) → `ModuleNames=*`.
- Windows LAPS : droit d'écriture des ordinateurs manquant → ajouté.
- Automatisation de la désactivation : délégation sans droit sur la description (compte désactivé mais jamais déplacé) et création d'UO impossible → corrigé.
- Groupes intégrés interrogés par nom anglais (inopérant sur AD francisé) → résolution par SID.
- Sauvegarde : `wbadmin` analysé en anglais et retenant la plus ancienne version → métadonnées AD + journal de sauvegarde.
- Procédures : durée de vie des tombstones « 60 jours » → valeur réelle de la forêt (180 j par défaut depuis 2003 SP1).

**Faux positifs supprimés** : DC dans les délégations non contraintes ; trusts intra-forêt ; imprimantes virtuelles des DC ; fonctionnalités Windows par défaut des DC ; ouvertures de session anonymes dans le rapport NTLMv1 ; comptes inactifs (jamais connectés, mot de passe récent, cluster, trusts) ; comptes non nominatifs (`adm-jdupont` n'est plus signalé) ; ports RPC dynamiques ; partages (comparaison par SID, nom français « Utilisateurs authentifiés » enfin reconnu) ; `krbtgt` vu comme compte de service ; groupes imbriqués vus comme adminCount orphelins.

**Robustesse** : erreurs non bloquantes comptées comme échecs ; messages de succès requalifiés en simulation/échec ; aucune erreur inattendue ne fait quitter le script ; groupes illisibles signalés (jamais « vides ») ; HashSet retourné correctement (la v2 cassait l'action de désactivation par date) ; générateur de mots de passe sans biais modulo ; saisies numériques validées avec bornes ; index hors liste ignorés ; dossier des scripts déployés protégé par ACL.

**Interface** : menus pilotés par une table unique (fin de la désynchronisation possible entre menus et recherche, ~600 lignes de menus dupliqués supprimées), accès direct `x.y`, recherche multi-mots qui lance l'action, badges colorés, sections par nature, filtre d'UO, ciblage par noms de machines, sélection par plages, synthèse de session, rapports regroupés par session.

**Nouvelles actions** (extrait) : diagnostic rapide noté + mode `-QuickAudit`, rapport HTML, adminCount orphelins (audit + nettoyage), groupes sensibles (pré-Windows 2000, DnsAdmins...), Kerberoastables priorisés, mots de passe GPP, hygiène des mots de passe + chiffrement réversible, état krbtgt + réplication, sIDHistory (audit + suppression), retrait de délégation non contrainte, configuration NTLM effective, dSHeuristics/LDAP des DC, matrice de durcissement des DC, réplication/FSMO, hygiène des GPO, politique d'audit effective, registre des exceptions interactif, gestion de toutes les tâches `SEC - *`.

**Nettoyage** : suppression de `diff_output.txt` (artefact de diff) et du journal d'exécution versionné ; `Logs/` ignoré par Git.

## Limites connues

- Les contrôles et dates de fin de support sont **indicatifs** (table `$Script:OsLifecycle` à tenir à jour) : à confirmer (site *Lifecycle* Microsoft, rapport PingCastle complet). Le script ne remplace pas un audit PingCastle ni le jugement humain sur chaque remédiation.
- La date d'introduction d'AES (groupe RODC) est une **approximation** ; en cas de doute, réinitialisez le mot de passe du compte avant de forcer AES uniquement.
- Les paramètres appliqués directement au registre des DC (signature LDAP, audit NTLM, TLS...) sont **écrasés par une GPO** qui définirait les mêmes paramètres : le script le rappelle ; dans ce cas, modifiez la GPO.
- Les droits utilisateur écrits dans une GPO dédiée (`2.4`) ne **fusionnent pas** avec ceux d'autres GPO : seule la GPO de plus haute priorité s'applique pour un même droit.
- La rotation krbtgt planifiée et l'automatisation s'exécutent par défaut sous SYSTEM d'un DC : cohérent avec le niveau de confiance d'un DC (tier 0), le script étant stocké dans un dossier à ACL restreinte.
- Les GPO à impact large (NTLM, LLMNR, Hardened UNC Paths) proposent une liaison sur **UO pilote** ; sans sélection, elles sont créées non liées.
- AD CS/PKI et Microsoft Entra ID (hors recommandations) restent hors périmètre.
