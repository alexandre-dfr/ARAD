# AD_Remediation_Menu.ps1

Script PowerShell à menu pour automatiser les remédiations Active Directory les plus courantes, basé sur les constats récurrents des rapports **PingCastle** (krbtgt jamais changé, NTLMv1/LM, comptes inactifs, délégations Kerberos, mots de passe n'expirant jamais, LAPS absent, etc.).

Le script est volontairement construit pour qu'aucune action ne puisse partir "par accident" : mode simulation actif par défaut, confirmations renforcées sur tout ce qui peut avoir un impact, et vérifications préalables avant les actions les plus sensibles.

---

## Sommaire

- [Prérequis](#prérequis)
- [Démarrage rapide](#démarrage-rapide)
- [Principes de sécurité du script](#principes-de-sécurité-du-script)
- [Organisation du menu par thème](#organisation-du-menu-par-thème)
- [Thème 1 : Comptes à privilèges](#thème-1--comptes-à-privilèges)
- [Thème 2 : Comptes de service](#thème-2--comptes-de-service)
- [Thème 3 : Kerberos et délégations](#thème-3--kerberos-et-délégations)
- [Thème 4 : NTLM / LM](#thème-4--ntlm--lm)
- [Thème 5 : SMB, SYSVOL et NETLOGON](#thème-5--smb-sysvol-et-netlogon)
- [Thème 6 : LDAP / LDAPS](#thème-6--ldap--ldaps)
- [Thème 7 : Contrôleurs de domaine](#thème-7--contrôleurs-de-domaine)
- [Thème 8 : Windows LAPS](#thème-8--windows-laps)
- [Thème 9 : Mots de passe et authentification](#thème-9--mots-de-passe-et-authentification)
- [Thème 10 : GPO de durcissement (socle GPO-SEC-*)](#thème-10--gpo-de-durcissement-socle-gpo-sec-)
- [Thème 11 : Postes et serveurs membres](#thème-11--postes-et-serveurs-membres)
- [Thème 12 : Réseau et anti-relay](#thème-12--réseau-et-anti-relay)
- [Thème 13 : Sauvegarde et résilience AD](#thème-13--sauvegarde-et-résilience-ad)
- [Thème 14 : Obsolescence](#thème-14--obsolescence)
- [Thème 15 : Journalisation et détection](#thème-15--journalisation-et-détection)
- [Thème 16 : Contrôle final](#thème-16--contrôle-final)
- [Thème 17 : Rapports transverses](#thème-17--rapports-transverses)
- [Thème 18 : Hygiène des comptes inactifs et automatisation](#thème-18--hygiène-des-comptes-inactifs-et-automatisation)
- [Focus : désactivation par date choisie (garde-fous et UO dédiées)](#focus--désactivation-par-date-choisie-garde-fous-et-uo-dédiées)
- [Focus : rotation automatique du mot de passe KRBTGT](#focus--rotation-automatique-du-mot-de-passe-krbtgt)
- [Focus : audit NTLM avant blocage NTLMv1/LM](#focus--audit-ntlm-avant-blocage-ntlmv1lm)
- [Focus : activer WinRM sur les DC quand ils sont injoignables](#focus--activer-winrm-sur-les-dc-quand-ils-sont-injoignables)
- [Focus : comptes de service (inventaire et remédiations)](#focus--comptes-de-service-inventaire-et-remédiations)
- [Focus : Windows LAPS](#focus--windows-laps)
- [Focus : SMB/SYSVOL et LDAP/LDAPS](#focus--smbsysvol-et-ldapldaps)
- [Focus : socle GPO-SEC-* et postes/serveurs](#focus--socle-gpo-sec--et-postesserveurs)
- [Focus : sauvegarde, obsolescence, journalisation et contrôle final](#focus--sauvegarde-obsolescence-journalisation-et-contrôle-final)
- [Dépannage : erreur WinRM](#dépannage--erreur-winrm-la-connexion-au-serveur-distant--a-échoué)
- [Journalisation](#journalisation)
- [Limites connues / points d'attention](#limites-connues--points-dattention)

---

## Prérequis

- PowerShell 5.1 (Windows PowerShell), exécuté depuis un poste avec le module **ActiveDirectory** (RSAT AD DS) installé — idéalement directement sur un contrôleur de domaine.
- Le module **GroupPolicy** (RSAT-GPMC) est nécessaire pour les actions qui créent/modifient des GPO (journalisation PowerShell, NTLMv1, LLMNR, Windows LAPS, interdiction de logon interactif des comptes de service).
- Le module **LAPS** (RSAT Windows LAPS moderne, intégré depuis Windows 11 22H2 / Windows Server 2022 à jour) est nécessaire pour les actions du thème Windows LAPS.
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

 -- IDENTITE ET COMPTES --
 1.  Comptes a privileges
 2.  Comptes de service
 9.  Mots de passe et authentification

 -- AUTHENTIFICATION ET PROTOCOLES --
 3.  Kerberos et delegations
 4.  NTLM / LM
 5.  SMB, SYSVOL et NETLOGON
 6.  LDAP / LDAPS

 -- INFRASTRUCTURE --
 7.  Controleurs de domaine
 8.  Windows LAPS
 10. GPO de durcissement (socle GPO-SEC-*)
 11. Postes et serveurs membres
 12. Reseau et anti-relay

 -- RESILIENCE ET PILOTAGE --
 13. Sauvegarde et resilience AD
 14. Obsolescence
 15. Journalisation et detection
 16. Controle final
 17. Rapports transverses (export global)
 18. Hygiene des comptes inactifs et automatisation

 [R] Rechercher une action par mot-cle
 [S] Activer le mode REEL (desactiver la simulation)
 [Q] Quitter
```

Les thèmes gardent leur numérotation 1→18 (celle utilisée dans tout ce README et dans les logs) ; seul l'**affichage** du menu principal les regroupe visuellement par catégorie pour rester lisible avec autant de thèmes.

## Principes de sécurité du script

- **Mode simulation par défaut** : tant que vous n'avez pas basculé en mode réel via `[S]` (et tapé `CONFIRMER`), **aucune action n'est appliquée** — le script affiche uniquement ce qu'il *ferait*.
- **Deux niveaux de confirmation**, indiqués par un tag directement dans le libellé de chaque action **et par sa couleur** (voir légende affichée en haut de chaque écran) :
  - `(SAFE)` en **vert** → aucune incidence sur la production, confirmation simple `O/N`.
  - `(A VALIDER)` en **rouge** → impact potentiel, il faut taper le mot exact `CONFIRMER` (sensible à la casse), après lecture d'un avertissement dédié.
  - Sans tag, en **gris** → audit (lecture seule), navigation, ou outillage (registre des exceptions, génération de procédures...).
- **Recherche par mot-cle** (`[R]` au menu principal) : avec 18 thèmes et une centaine d'actions, retrouvez en un mot-clé (ex. `kerberoasting`, `laps`, `smb1`, `rdp`) dans quel thème et sous quel numéro se trouve une action, sans parcourir chaque sous-menu. La recherche est purement indicative (elle affiche l'emplacement, elle n'exécute jamais l'action à votre place) : vous lancez ensuite l'action vous-même depuis son thème, avec ses garde-fous habituels.
- **Journal complet** de toute la session dans `Logs\Remediation_AD_<date>.log`, plus des exports CSV horodatés pour chaque rapport/liste de comptes concernés.
- **Vérifications préalables avant action** quand c'est pertinent : ex. détection des imprimantes avant d'arrêter le service Spooler, rappel de consulter le rapport NTLMv1 avant de désactiver NTLMv1.
- **Aucune action irréversible cachée** : les comptes/ordinateurs "inactifs" ne sont jamais supprimés, seulement désactivés et déplacés dans une OU de quarantaine dédiée (`OU_QUARANTAINE_COMPTES_INACTIFS` pour l'action par ancienneté ; `disable_user` / `disable_computer` pour l'action par date choisie et l'automatisation — voir [focus dédié](#focus--désactivation-par-date-choisie-garde-fous-et-uo-dédiées)).
- Les GUID de sous-catégories d'audit (`auditpol`) et les champs d'événements Windows utilisés sont **indépendants de la langue de l'OS** (important sur un DC installé en français, où les noms anglais font échouer les commandes natives).

## Organisation du menu par thème

Le menu principal suit désormais le déroulé d'une prestation de sécurisation Active Directory : un point d'entrée par thème, et dans chaque thème d'abord l'**audit** (lecture seule), puis la **remédiation** (avec son garde-fou dédié, tag `(SAFE)` ou `(A VALIDER)`). La numérotation de chaque sous-menu repart de 1 à chaque fois — ce ne sont pas les numéros du cahier des charges client, juste l'ordre d'apparition dans ce sous-menu.

Périmètre actuel : toutes les sections du cahier des charges (§3 à §20) sont désormais couvertes au moins partiellement, à l'exception d'AD CS/PKI (§15) et de Microsoft Entra ID hybride (§16), volontairement hors périmètre. §21 (livrables/comparaison PingCastle avant-après) est traité par un script séparé, et §22 (maintien en condition de sécurité) n'entre pas dans le périmètre d'un script d'exécution ponctuelle.

## Thème 1 : Comptes à privilèges

| # | Action | Effet / point d'attention |
|---|--------|------------------------------|
| 1 | Export des membres des groupes à privilèges | Audit, lecture seule. Domain/Enterprise/Schema Admins, Administrators, Account/Backup/Server/Print Operators, Group Policy Creator Owners, Protected Users. |
| 2 | Nombre de membres Domain Admins / Enterprise Admins | Audit, lecture seule, avec seuil d'alerte ajustable (défaut 5). |
| 3 | Usage du compte Administrateur intégré (RID 500) | Audit, lecture seule. Actif/inactif, dernière connexion. |
| 4 | Comptes à privilèges potentiellement non nominatifs/partagés | Audit, lecture seule. Heuristique : sans Prénom/Nom, ou nom générique (admin, root, service...). |
| 5 | Risque Kerberoasting sur les comptes à privilèges | Audit, lecture seule. Croise appartenance à un groupe à privilèges et présence d'un SPN. |
| 6 | (A VALIDER) Marquer les comptes à privilèges "non délégables" | Casse les scénarios de délégation Kerberos utilisant ces comptes. |
| 7 | (A VALIDER) Ajouter les admins dans "Protected Users" | Plus de NTLM/DES/délégation, TGT limité à 4h pour ces comptes. |
| 8 | (A VALIDER) Nettoyer le groupe Schema Admins | Sélection interactive des comptes à retirer (le groupe doit rester vide en temps normal). |
| 9 | (A VALIDER) Forcer l'expiration des mots de passe admin | Prévenir les propriétaires des comptes concernés avant expiration effective. |
| 10 | (A VALIDER) Désactiver le compte Administrateur intégré (RID 500) | **Garde-fou** : refuse si aucun autre compte Domain Admins actif n'existe. |
| 11 | (A VALIDER) Restreindre les comptes à privilèges à des postes dédiés (PAW) | Positionne l'attribut `LogonWorkstations` — risque de verrouillage hors des postes listés. |

## Thème 2 : Comptes de service

Nouveau thème — voir le [focus dédié](#focus--comptes-de-service-inventaire-et-remédiations) pour le détail de l'heuristique et des remédiations.

| # | Action | Effet / point d'attention |
|---|--------|------------------------------|
| 1 | Inventaire des comptes de service | Audit, lecture seule. Heuristique : SPN + OU choisies. Export CSV avec chiffrement supporté, appartenance à un groupe à privilèges, propriétaire documenté. |
| 2 | Comptes de service en chiffrement faible | Audit, sous-ensemble de l'inventaire filtré sur RC4/DES sans AES. |
| 3 | (A VALIDER) Forcer AES128+AES256 | Casse les applications ne supportant QUE RC4/DES. |
| 4 | (A VALIDER) Interdire la connexion interactive/RDP | Crée un groupe dédié + une GPO ; l'attribution du droit "Refuser l'ouverture de session" reste une **étape manuelle** dans GPMC (non automatisable via le module GroupPolicy). |
| 5 | (A VALIDER) Retirer des groupes à privilèges | Casse l'application si le privilège était réellement nécessaire — à valider avec le propriétaire applicatif. |
| 6 | (A VALIDER) Réinitialiser le mot de passe | L'application doit être reconfigurée avec le nouveau mot de passe avant expiration de la session en cours. |
| 7 | (A VALIDER) Assistant de création d'un gMSA | Crée un nouveau compte de service géré ; ne migre pas automatiquement un compte existant. |

## Thème 3 : Kerberos et délégations

| # | Action | Effet / point d'attention |
|---|--------|------------------------------|
| 1 | Rapport des délégations Kerberos | Audit, lecture seule : non contrainte/contrainte/RBCD, pour revue au cas par cas. |
| 2 | Audit AS-REP Roasting | Audit, lecture seule. Comptes avec `DoesNotRequirePreAuth`. |
| 3 | Audit des relations d'approbation (trusts) et de leur chiffrement | Audit, lecture seule (`Get-ADTrust`). Signale l'absence de filtrage SID. |
| 4 | (A VALIDER) Réinitialiser le mot de passe KRBTGT | Nécessite 2 exécutions espacées (voir [focus KRBTGT](#focus--rotation-automatique-du-mot-de-passe-krbtgt)). |
| 5 | (A VALIDER) Configurer la rotation KRBTGT planifiée | Voir [focus dédié](#focus--rotation-automatique-du-mot-de-passe-krbtgt). |
| 6 | (A VALIDER) Désactiver DES / forcer AES | Casse les applis Kerberos dépendant de DES ou ne supportant pas AES. |
| 7 | (A VALIDER) Corriger l'exposition AS-REP Roasting | Réactive la pré-authentification Kerberos sur les comptes sélectionnés. |
| 8 | (A VALIDER) Activer Kerberos Armoring (FAST) | Mode "Supported" (DC puis clients) ; nécessite niveau fonctionnel ≥ 2012. |

## Thème 4 : NTLM / LM

| # | Action | Effet / point d'attention |
|---|--------|------------------------------|
| 1 | (SAFE) Activer l'audit NTLM | Journalisation uniquement (jamais de blocage) — voir [focus dédié](#focus--audit-ntlm-avant-blocage-ntlmv1lm). |
| 2 | Rapport NTLMv1/LM détecté | Audit, lecture seule. Nécessite l'audit NTLM actif depuis un moment ; peut être **long** à exécuter (lecture du journal Sécurité). |
| 3 | (A VALIDER) Désactiver NTLMv1/LM (`LmCompatibilityLevel`) | Casse les équipements ne parlant que NTLMv1/LM. Rappelle de consulter le rapport avant de continuer. |
| 4 | (A VALIDER) Restriction progressive de NTLM sortant (Deny avec exceptions) | Bloque TOUT NTLM sortant des DC (v1 et v2) sauf serveurs exceptés. Complémentaire à l'action 3. |

## Thème 5 : SMB, SYSVOL et NETLOGON

Nouveau thème — voir le [focus dédié](#focus--smbsysvol-et-ldapldaps) pour le détail.

| # | Action | Effet / point d'attention |
|---|--------|------------------------------|
| 1 | Détection de l'usage SMBv1 | Audit, lecture seule. Propose d'activer l'audit SMBv1 (journalisation uniquement) si besoin, puis lit le journal `Microsoft-Windows-SMBServer/Audit`. |
| 2 | État de la signature SMB (client/serveur) | Audit, lecture seule, sur les DC. |
| 3 | Audit des partages SMB sur des postes/serveurs choisis | Audit, lecture seule. Signale les partages accordant Modification/Contrôle total à Everyone/Authenticated Users. |
| 4 | (A VALIDER) Désactiver SMBv1 (client + serveur) sur les DC | Casse l'accès des NAS/scanners/imprimantes/applications ne parlant QUE SMBv1. Consultez le rapport d'usage avant de continuer. |
| 5 | (A VALIDER) Désactiver SMBv1 sur des postes/serveurs choisis | Complémentaire à l'action 4, sur des machines choisies par OU. |
| 6 | (A VALIDER) Forcer la signature SMB via GPO | GPO liée directement à l'OU Domain Controllers. Casse les clients/serveurs SMB très anciens sans support de la signature. |
| 7 | (A VALIDER) Durcir les chemins UNC SYSVOL/NETLOGON (Hardened UNC Paths) | GPO créée mais **non liée automatiquement** (impact potentiellement domaine entier, postes ET serveurs) ; recommandation Microsoft standard (MS15-011), risque résiduel très faible sur un parc à jour. |

## Thème 6 : LDAP / LDAPS

Nouveau thème — regroupe la signature LDAP déjà existante et de nouvelles actions. Voir le [focus dédié](#focus--smbsysvol-et-ldapldaps).

| # | Action | Effet / point d'attention |
|---|--------|------------------------------|
| 1 | Audit des certificats LDAPS et joignabilité du port 636 | Audit, lecture seule. Vérifie la présence d'un certificat serveur valide sur chaque DC, la validité de la chaîne de certification, et teste TCP/636. |
| 2 | Audit des Simple Binds LDAP non signés | Audit, lecture seule. Active le diagnostic "16 LDAP Interface Events" si besoin, puis lit l'événement 2887 (généré ~1x/24h). |
| 3 | (A VALIDER) Forcer la signature LDAP / channel binding | Casse les clients LDAP ne supportant pas la signature. |
| 4 | (A VALIDER) Désactiver TLS 1.0/1.1, activer TLS 1.2+ (SCHANNEL) | Casse les clients LDAPS/RDP/applicatifs qui ne négocient qu'en TLS 1.0/1.1. |
| 5 | (A VALIDER) Restreindre les opérations LDAP anonymes (`dSHeuristics`) | Modifie le 7e caractère de `dSHeuristics` (KB326690). Casse les applications s'appuyant sciemment sur un accès LDAP anonyme. |

## Thème 7 : Contrôleurs de domaine

| # | Action | Effet / point d'attention |
|---|--------|------------------------------|
| 1 | Rapport des hotfix installés sur les DC | Audit, lecture seule. |
| 2 | État de la synchronisation horaire (NTP) | Audit, lecture seule (`w32tm /query /source`). Signale un PDC Emulator sur horloge locale. |
| 3 | Rôles et fonctionnalités installés sur les DC | Audit, lecture seule. Signale ce qui dépasse le socle DC standard (indicatif, à ajuster). |
| 4 | (SAFE) Activer PowerShell Remoting (WinRM) sur les DC injoignables | Voir [focus dédié](#focus--activer-winrm-sur-les-dc-quand-ils-sont-injoignables). |
| 5 | (SAFE) Désactiver le compte Invité (Guest) | Si le compte est actif, le désactive. |
| 6 | (SAFE) Protéger les OU contre la suppression accidentelle | Ajoute l'ACE de refus de suppression sur chaque OU qui ne l'a pas. |
| 7 | (SAFE) Limiter `ms-DS-MachineAccountQuota` à 0 | Empêche les utilisateurs standards de joindre de nouveaux postes au domaine. |
| 8 | (A VALIDER) Arrêter/désactiver le Spooler sur les DC | **Vérifie d'abord si des imprimantes sont configurées/partagées** et exige une confirmation dédiée (`ARRETER`) si c'est le cas. |
| 9 | (A VALIDER) Configurer la source NTP externe du PDC Emulator | S'applique uniquement au PDC Emulator ; ne touche pas la synchro hiérarchique des autres DC. |
| 10 | (A VALIDER) Activer le pare-feu Windows (3 profils) sur les DC | La restriction d'accès Internet des DC reste une recommandation (pare-feu périmétrique/proxy), non automatisée ici (risque de casser Windows Update/CRL/OCSP). |

> La signature LDAP / channel binding a déménagé dans le thème 6 (LDAP / LDAPS), et l'audit avancé (`auditpol`) / la journalisation PowerShell ont déménagé dans le thème 15 (Journalisation et détection).

## Thème 8 : Windows LAPS

Nouveau thème — voir le [focus dédié](#focus--windows-laps) pour le détail.

| # | Action | Effet / point d'attention |
|---|--------|------------------------------|
| 1 | État du déploiement LAPS | Audit, lecture seule. Vérifie schéma AD, module PowerShell, et calcule le taux de couverture (% de postes/serveurs avec un mot de passe LAPS actif). |
| 2 | Audit des droits de lecture/reset | Audit, lecture seule. Utilise `Find-LapsADExtendedRights` sur les UO choisies. |
| 3 | (A VALIDER) Préparer le schéma AD | `Update-LapsADSchema` — modification du schéma de la forêt, en pratique irréversible. |
| 4 | (A VALIDER) Déployer la GPO Windows LAPS | Longueur/âge du mot de passe, choix de la sauvegarde (Active Directory ou Microsoft Entra ID en hybride). |
| 5 | (A VALIDER) Configurer les droits de lecture/reset | Délègue via `Set-LapsADReadPasswordPermission` / `Set-LapsADResetPasswordPermission` sur les UO choisies. |

## Thème 9 : Mots de passe et authentification

| # | Action | Effet / point d'attention |
|---|--------|------------------------------|
| 1 | Rapport comptes avec mot de passe n'expirant jamais | Audit, lecture seule. |
| 2 | Audit de la politique de mot de passe par défaut du domaine | Audit, lecture seule. Compare longueur/complexité/historique/verrouillage aux recommandations de base. |
| 3 | (SAFE) Retirer le flag "Mot de passe non requis" | Ne force pas de changement immédiat, retire juste l'exemption pour le prochain changement. |
| 4 | (A VALIDER) Corriger la politique de mot de passe par défaut du domaine | Peut forcer un changement plus contraignant pour tous les utilisateurs du domaine. |
| 5 | (A VALIDER) Créer une Fine-Grained Password Policy pour les comptes de service | S'applique uniquement au groupe cible fourni, jamais à tout le domaine. |
| 6 | (SAFE) Générer les recommandations MFA / Conditional Access (hybride) | Documentation uniquement (mise en œuvre réelle hors périmètre technique, côté Entra ID). |

## Thème 10 : GPO de durcissement (socle GPO-SEC-*)

Nouveau thème — voir le [focus dédié](#focus--socle-gpo-sec--et-postesserveurs). Les remédiations des autres thèmes (LAPS, NTLM, SMB, LLMNR, Defender, RDP...) continuent pour l'instant de créer leurs propres GPO `ADHC - ...` dédiées ; ce thème ajoute en complément le socle nommé `GPO-SEC-*` demandé par le cahier des charges (coquilles vides à peupler) et la sauvegarde de toutes les GPO avant changement sensible.

| # | Action | Effet / point d'attention |
|---|--------|------------------------------|
| 1 | État du socle GPO-SEC-* et des sauvegardes | Audit, lecture seule. Liste les 9 GPO du socle (présentes/absentes) et la dernière sauvegarde complète trouvée. |
| 2 | (SAFE) Sauvegarder TOUTES les GPO du domaine | Aucun impact (lecture seule des GPO), écrit uniquement dans `Logs\GPO_Backups\<horodatage>\`. À faire avant tout changement sensible. |
| 3 | (SAFE) Créer les GPO manquantes du socle GPO-SEC-* | Aucun impact : GPO créées sans paramètre ni lien vers une OU. |

## Thème 11 : Postes et serveurs membres

Nouveau thème — voir le [focus dédié](#focus--socle-gpo-sec--et-postesserveurs). Les actions ciblent des machines choisies via sélection d'OU et nécessitent PowerShell Remoting (WinRM) actif sur ces machines (comme pour les DC).

| # | Action | Effet / point d'attention |
|---|--------|------------------------------|
| 1 | État de Microsoft Defender sur des machines choisies | Audit, lecture seule. Protection temps réel/cloud/réseau, nombre de règles ASR définies. |
| 2 | Audit des administrateurs locaux sur des machines choisies | Audit, lecture seule. |
| 3 | (A VALIDER) Renforcer Microsoft Defender via GPO | Cloud Protection, Network Protection, SmartScreen, et 6 règles ASR courantes en mode **Audit par défaut** (choix Audit/Avertir/Bloquer) — déploiement progressif recommandé avant de passer en mode Bloquer. |
| 4 | (A VALIDER) Restreindre RDP via GPO | Impose la Network Level Authentication (NLA) et un chiffrement élevé. Casse les clients RDP très anciens sans support NLA. |
| 5 | (A VALIDER) Retirer des comptes des administrateurs locaux | Casse l'usage si le compte avait réellement besoin de ce privilège local. |
| 6 | (SAFE) Étendre la journalisation PowerShell aux postes/serveurs choisis | Lie/complète la GPO déjà créée pour les DC (thème 15). |
| 7 | (A VALIDER) Bloquer les scripts .vbs/.js (Windows Script Host) | Casse les scripts de connexion/outils internes basés sur WSH. |
| 8 | (A VALIDER) Activer le pare-feu Windows (3 profils) | Casse les flux non couverts par les règles prédéfinies actives. |

## Thème 12 : Réseau et anti-relay

| # | Action | Effet / point d'attention |
|---|--------|------------------------------|
| 1 | Audit de la Global Query Block List DNS (WPAD/ISATAP) | Audit, lecture seule, sur les DC. |
| 2 | Audit des ports/services exposés sur les DC | Audit, lecture seule. Liste les ports TCP en écoute et le processus associé. |
| 3 | (A VALIDER) Désactiver LLMNR via GPO | Impact large (tout le domaine) ; GPO créée mais non liée automatiquement. |
| 4 | (SAFE) Rétablir la Global Query Block List (wpad/isatap) | Restaure une protection **par défaut** de Windows ; sans impact sauf usage intentionnel de WPAD/ISATAP (rare). |
| 5 | (A VALIDER) Désactiver NetBIOS sur TCP/IP sur des machines choisies | Casse la résolution de secours NetBIOS/NBT-NS pour des applications/imprimantes anciennes. |
| 6 | (A VALIDER) Durcir RPC | `RestrictRemoteClients` + `EnableAuthEpResolution` via GPO. Casse les applications RPC dépendant de clients non authentifiés. |
| 7 | (A VALIDER) Durcir WinRM | Désactive l'authentification Basic et le trafic non chiffré (client+serveur). Casse les outils tiers dépendant de ces réglages. |
| 8 | (A VALIDER) Restreindre l'énumération distante SAM/SAMR | Réserve l'énumération des comptes/groupes locaux aux administrateurs locaux. Casse les outils de supervision utilisant un compte non-admin. |

## Thème 13 : Sauvegarde et résilience AD

Voir le [focus dédié](#focus--sauvegarde-obsolescence-journalisation-et-contrôle-final).

| # | Action | Effet / point d'attention |
|---|--------|------------------------------|
| 1 | État des sauvegardes System State sur les DC | Audit, lecture seule (`wbadmin get versions` sur chaque DC). |
| 2 | (SAFE) Activer la Corbeille Active Directory | Permet de restaurer un objet supprimé par erreur. |
| 3 | (A VALIDER) Planifier une sauvegarde System State quotidienne | Installe Windows Server Backup si besoin et crée une tâche planifiée. Recommandation : cible indépendante du domaine si possible. |
| 4 | (SAFE) Générer les procédures de récupération (objet / DC / forêt) | Écrit des fichiers texte de procédure dans `Logs\Procedures\` (aucun impact AD). |

## Thème 14 : Obsolescence

Nouveau thème — voir le [focus dédié](#focus--sauvegarde-obsolescence-journalisation-et-contrôle-final). Les migrations lourdes elles-mêmes restent hors périmètre (projet séparé, comme indiqué par le cahier des charges).

| # | Action | Effet / point d'attention |
|---|--------|------------------------------|
| 1 | Inventaire des OS non/bientôt non supportés | Audit, lecture seule, sur tout l'annuaire (pas de sélection d'OU nécessaire). |
| 2 | Protocoles obsolètes actifs sur des machines choisies (SMBv1, TLS 1.0/1.1) | Audit, lecture seule, nécessite WinRM sur les machines ciblées. |
| 3 | (SAFE) Générer le plan de traitement de l'obsolescence (consolidé) | Réexécute une partie des audits (OS, comptes de service en RC4/DES) en un seul CSV catégorisé. |

## Thème 15 : Journalisation et détection

Nouveau thème — regroupe l'audit avancé et la journalisation PowerShell (déplacés depuis le thème Contrôleurs de domaine) et de nouvelles actions. Voir le [focus dédié](#focus--sauvegarde-obsolescence-journalisation-et-contrôle-final).

| # | Action | Effet / point d'attention |
|---|--------|------------------------------|
| 1 | Audit du SACL sur les objets sensibles (racine du domaine, AdminSDHolder) | Audit, lecture seule. |
| 2 | (SAFE) Activer l'audit avancé sur les DC (`auditpol`) | *(déplacé depuis Contrôleurs de domaine)* Succès+Échec sur 16 sous-catégories clés. |
| 3 | (SAFE) Activer la journalisation PowerShell | *(déplacé depuis Contrôleurs de domaine)* GPO liée à l'OU Domain Controllers. |
| 4 | (A VALIDER) Configurer l'audit SACL sur les objets sensibles | Ajoute une règle d'audit (additive, n'enlève rien d'existant) ; augmente le volume du journal Sécurité. |
| 5 | (A VALIDER) Configurer la redirection des journaux vers un collecteur (WEF/SIEM) | Pousse uniquement le pointage côté DC ; le collecteur doit déjà exister côté client. |

## Thème 16 : Contrôle final

Nouveau thème — voir le [focus dédié](#focus--sauvegarde-obsolescence-journalisation-et-contrôle-final). Ne remplace pas l'outil séparé de comparaison PingCastle avant/après.

| # | Action | Effet / point d'attention |
|---|--------|------------------------------|
| 1 | Lancer le contrôle final consolidé | Audit, lecture seule. Rejoue 7 audits clés (dont SMB et, sur confirmation, NTLMv1/LM) de plusieurs thèmes déjà traités par ce script. |
| 2 | (SAFE) Initialiser/compléter le registre des exceptions | Crée `Logs\Registre_Exceptions.csv` pour documenter tout constat accepté sans correction. |

## Thème 17 : Rapports transverses

Lecture seule, aucune modification. Les rapports spécifiques à un thème (privilèges, délégations, NTLMv1, comptes de service, LAPS, SMB, LDAP, Defender, admins locaux, obsolescence...) sont désormais dans leur menu thématique respectif — ce menu ne garde que les rapports transverses.

| # | Rapport | Remarque |
|---|---------|----------|
| 1 | Comptes inactifs (utilisateurs/ordinateurs) | Seuils en jours demandés à l'exécution. |
| 2 | Export global | Regroupe les rapports rapides multi-thèmes (comptes inactifs, mots de passe n'expirant jamais, groupes à privilèges, hotfix DC). |

## Thème 18 : Hygiène des comptes inactifs et automatisation

Ce thème ne correspond à aucun numéro unique du cahier des charges client (il touche à la fois les comptes à privilèges et l'hygiène générale des comptes) : il reste regroupé à part, comme avant la restructuration.

| # | Action | Remarque |
|---|--------|----------|
| 1 | (A VALIDER) Désactiver les comptes inactifs par ancienneté | **Seuils de jours demandés à chaque exécution** (pas de valeur figée). Déplace en quarantaine + désactive, ne supprime jamais. |
| 2 | (A VALIDER) Désactiver postes/serveurs et/ou utilisateurs à partir d'une **date choisie** | Déplace vers des UO dédiées `disable_user` / `disable_computer` + désactive. Garde-fous OU/groupes — voir [focus dédié](#focus--désactivation-par-date-choisie-garde-fous-et-uo-dédiées). |
| 3 | Configurer la tâche planifiée de désactivation automatique | Reprend les mêmes questions que l'action manuelle, plus l'intervalle entre exécutions et le DC hôte. Crée un gMSA dédié, délègue les droits minimaux nécessaires, déploie le script et crée la tâche planifiée. |
| 4 | Afficher l'état de la tâche planifiée existante | Interroge chaque DC : présence de la tâche, dernière/prochaine exécution, dernier résultat. |
| 5 | Supprimer la tâche planifiée | Arrête uniquement l'automatisation ; les comptes déjà désactivés/déplacés ne sont pas restaurés. |

## Focus : désactivation par date choisie (garde-fous et UO dédiées)

L'action `Theme 13 > 2` désactive les comptes utilisateurs et/ou postes/serveurs **inactifs depuis une date précise que vous choisissez** (au lieu d'un seuil en jours glissant comme l'action `Theme 13 > 1`). Les comptes concernés sont **déplacés dans une UO dédiée et créée automatiquement si absente** (jamais supprimés) :
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

À chaque désactivation (action `Theme 13 > 1` ou `Theme 13 > 2`, manuelle ou automatisée), le script ajoute la mention `Desactive le : jj/mm/aaaa` dans l'attribut **Description** de l'objet AD (sans écraser une description existante, ajoutée à la suite avec un séparateur `|`), pour tracer directement dans l'annuaire quand chaque compte a été désactivé.

À la fin de l'action, le script propose de basculer directement vers la configuration de l'automatisation (menu `Theme 13 > 3`) pour répéter cette désactivation à intervalle régulier.

### Automatisation : architecture

L'action `Theme 13 > 3` déploie, comme pour la rotation KRBTGT, un **script autonome** sur un contrôleur de domaine choisi, exécuté par une tâche planifiée récurrente :
- Un **gMSA dédié** (nom par défaut `svc-ADAutoDisable`) exécute la tâche — pas de mot de passe à gérer.
- **Délégation minimale** via `dsacls`, limitée à la racine de délégation choisie (racine du domaine par défaut, ou une UO précise) : uniquement l'écriture de la propriété `userAccountControl` (désactivation) et la création/suppression d'objets `User`/`Computer` (nécessaire pour un déplacement `Move-ADObject`) — jamais de droit Domain Admin accordé à la tâche.
- Pour une exécution récurrente, le seuil se base sur une **ancienneté glissante** (X jours sans connexion, recalculée à chaque exécution) plutôt qu'une date fixe, qui n'aurait plus de sens d'une exécution à l'autre.
- Les seuils et exclusions choisis sont figés dans le script déployé ; relancer `Theme 13 > 3` régénère et remplace le script et la tâche avec de nouveaux paramètres.
- Journalisation locale (`C:\ADHC-Scripts\Disable-ByDate.log`) + Event Log applicatif dédié (`ADHC-AutoDisable`), sur le DC hébergeant la tâche.

## Focus : rotation automatique du mot de passe KRBTGT

Un reset krbtgt "à la main" doit être fait **deux fois**, espacé d'un délai supérieur à la durée de vie max des tickets Kerberos + le temps de convergence de la réplication AD. La recommandation Microsoft/ANSSI pour la suite est de **répéter ce reset à intervalle régulier** (typiquement tous les 6 mois) : un reset unique répété avec un intervalle largement supérieur à ce délai offre en continu la même protection que le double-reset manuel.

L'action `Theme 3 > 3` automatise cela avec une architecture à moindre privilège :
- Création d'un **gMSA dédié** (nom par défaut `svc-KrbtgtRotation`) — pas de mot de passe à gérer.
- **Délégation minimale** : uniquement le droit "Reset Password" sur l'objet `krbtgt` (via `dsacls`), jamais de droits Domain Admin accordés à la tâche planifiée.
- Déploiement d'un script autonome sur le DC choisi + création d'une **tâche planifiée récurrente** (intervalle configurable, avertissement si < 30 jours).
- **Garde-fou intégré** : avant chaque exécution automatique, le script vérifie l'état de réplication AD (`repadmin /replsummary`) et **annule** la rotation si un problème est détecté ou si la sortie est inattendue.
- Journalisation locale (`C:\ADHC-Scripts\Krbtgt-Rotation.log`) + Event Log applicatif dédié (`ADHC-KrbtgtRotation`).

## Focus : audit NTLM avant blocage NTLMv1/LM

Avant de forcer `LmCompatibilityLevel=5` (action `Theme 4 > 3`), qui peut casser des équipements legacy sans prévenir, le script propose une démarche en deux temps :

1. **`Theme 4 > 1`** active l'audit NTLM (journalisation uniquement, jamais de blocage) : réception NTLM, émission NTLM, authentification NTLM pass-through au niveau du domaine, et active le journal `Microsoft-Windows-NTLM/Operational`.
2. Laisser tourner **plusieurs jours** (idéalement un cycle métier complet).
3. **`Theme 4 > 2`** lit le journal Sécurité des DC et remonte précisément les comptes/postes utilisant encore NTLMv1 ou LM (champ `LmPackageName` des événements 4624/4625), sans dépendre du texte localisé des messages.

L'action de désactivation NTLMv1 (`Theme 4 > 3`) rappelle explicitement cette étape avant de continuer.

## Focus : comptes de service (inventaire et remédiations)

Il n'existe pas de marqueur AD universel "compte de service" : l'inventaire (`Theme 2 > 1`) repose sur une **heuristique** — tout compte porteur d'au moins un SPN, complétée par des OU choisies interactivement (pour les comptes de service sans SPN, repérés par convention de nommage ou emplacement). Cette liste reste **à valider au cas par cas** (propriétaire réel, usage) avant toute remédiation ; elle exclut nativement les gMSA (objet AD d'un type différent, non retourné par `Get-ADUser`).

Toutes les remédiations de ce thème (`Theme 2 > 3` à `7`) partent de cette même liste et laissent choisir précisément les comptes ciblés (numéros, ou `tous`) plutôt que d'agir sur l'inventaire entier sans revue :
- **Forcer AES** (`3`) positionne `msDS-SupportedEncryptionTypes = 24` (AES128+AES256) sur les comptes sélectionnés.
- **Interdire la connexion interactive/RDP** (`4`) crée/complète un groupe AD dédié (`GG-ComptesDeService-NoInteractif` par défaut) et une GPO liée à l'OU choisie. **Étape manuelle obligatoire** : le module PowerShell `GroupPolicy` ne permet pas de modifier l'Attribution des droits utilisateur (`Deny log on locally` / `Deny log on through Remote Desktop Services`) — le script l'indique clairement à la fin de l'action, avec le nom exact du groupe à viser dans GPMC.
- **Retirer des groupes à privilèges** (`5`) croise l'inventaire avec Domain/Enterprise/Schema Admins, Administrators, Account/Backup/Server/Print Operators.
- **Réinitialiser le mot de passe** (`6`) génère un mot de passe aléatoire de 32 caractères, jamais affiché ni journalisé en clair — pensez à mettre à jour l'application avant de lancer l'action.
- **Assistant gMSA** (`7`) crée un nouveau compte de service géré (réutilise la même gestion de KDS Root Key que la rotation KRBTGT) ; il ne migre pas un compte existant, qui doit être reconfigué manuellement pour utiliser le nouveau gMSA.

## Focus : Windows LAPS

Ce thème cible **Windows LAPS moderne** (attributs `msLAPS-*`, intégré depuis Windows 11 22H2 / Windows Server 2022 à jour), pas l'ancien LAPS legacy (`ms-Mcs-AdmPwd`).

1. **`Theme 8 > 1`** (audit) vérifie la présence du schéma AD dédié, la disponibilité du module PowerShell `LAPS`, puis calcule le taux de couverture (ordinateurs avec un mot de passe LAPS actif vs. sans) et exporte le détail en CSV.
2. **`Theme 8 > 2`** (audit) liste, sur les OU choisies, les principaux disposant d'un droit étendu de lecture/reset du mot de passe (via la cmdlet native `Find-LapsADExtendedRights`) — à comparer avec la liste des groupes qui devraient légitimement avoir ce droit.
3. **`Theme 8 > 3`** exécute `Update-LapsADSchema` : modification du **schéma de la forêt**, en pratique irréversible — nécessite Schema Admins.
4. **`Theme 8 > 4`** crée/met à jour une GPO (`ADHC - Windows LAPS`) configurant longueur/âge du mot de passe et le mode de sauvegarde (Active Directory, ou Microsoft Entra ID si l'environnement est hybride), puis la lie aux OU choisies.
5. **`Theme 8 > 5`** délègue la lecture et/ou le reset du mot de passe (`Set-LapsADReadPasswordPermission` / `Set-LapsADResetPasswordPermission`) à un ou deux groupes précis sur les OU choisies — à réserver au strict nécessaire, jamais à un groupe large type "tous les administrateurs".

## Focus : SMB/SYSVOL et LDAP/LDAPS

**SMB/SYSVOL (`Theme 5`)** :
- L'audit SMBv1 (`1`) et l'état de signature (`2`) sont en lecture seule ; l'audit SMBv1 propose d'activer `Set-SmbServerConfiguration -AuditSmb1Access $true` (journalisation uniquement) avant de lire le journal `Microsoft-Windows-SMBServer/Audit` (événement 3000).
- La désactivation SMBv1 (`3`) agit sur les DC via `Set-SmbServerConfiguration -EnableSMB1Protocol $false` + retrait de la fonctionnalité optionnelle Windows.
- La signature SMB obligatoire (`4`) est poussée par GPO **directement liée à l'OU Domain Controllers** (périmètre restreint, contrairement aux GPO à impact domaine entier créées mais non liées ailleurs dans le script).
- Le durcissement des chemins UNC SYSVOL/NETLOGON (`5`, Hardened UNC Paths / MS15-011) est une GPO **créée mais non liée automatiquement**, car elle doit in fine s'appliquer à tous les postes ET serveurs qui accèdent à SYSVOL/NETLOGON (impact domaine entier).

**LDAP/LDAPS (`Theme 6`)** :
- L'audit des certificats LDAPS (`1`) cherche, dans le magasin `Cert:\LocalMachine\My` de chaque DC, un certificat avec l'EKU "Authentification du serveur" correspondant au nom du DC, et teste la joignabilité TCP/636.
- L'audit des Simple Binds (`2`) active si besoin le diagnostic `16 LDAP Interface Events` (registre `NTDS\Diagnostics`, journalisation uniquement) puis lit l'événement 2887 du journal "Directory Service" (généré par le DC environ une fois par 24h) — relancez l'audit le lendemain de l'activation pour un résultat exploitable.
- La restriction des opérations LDAP anonymes (`5`) modifie l'attribut `dSHeuristics` sur l'objet `CN=Directory Service,CN=Windows NT,CN=Services,<config NC>` (technique documentée par Microsoft, KB326690) : seul le 7e caractère est modifié, les autres caractères existants sont préservés.

## Focus : socle GPO-SEC-* et postes/serveurs

**GPO de durcissement (`Theme 10`)** : les remédiations des autres thèmes de ce script créent chacune leur propre GPO nommée `ADHC - ...` (LAPS, NTLM, SMB, LLMNR, Defender, RDP, RPC, WinRM...). Le cahier des charges demande en plus un socle nommé de 9 GPO (`GPO-SEC-DomainControllers`, `GPO-SEC-Servers`, `GPO-SEC-Workstations`, `GPO-SEC-Authentication`, `GPO-SEC-WindowsLAPS`, `GPO-SEC-Audit`, `GPO-SEC-Defender`, `GPO-SEC-RDP`, `GPO-SEC-Network`) : l'action `3` les crée **vides et non liées** si elles n'existent pas encore, comme point de départ à peupler manuellement (ou lors d'une prochaine évolution du script qui pourrait faire converger les GPO `ADHC - ...` thématiques vers ce socle). L'action `2` (`Backup-GPO -All`) sauvegarde l'intégralité des GPO existantes avant toute modification sensible, dans `Logs\GPO_Backups\<horodatage>\` — pour restaurer une GPO : `Import-GPO -BackupId <id> -Path <dossier> -TargetName <nom>`.

**Postes et serveurs (`Theme 11`)** : contrairement aux thèmes DC (qui listent automatiquement tous les contrôleurs de domaine), ce thème demande de **choisir une ou plusieurs OU** à chaque audit/remédiation — il n'y a pas de notion native "tous les postes/serveurs" à interroger sans risquer un impact ou un temps d'exécution excessif sur un grand parc. Les 4 règles ASR proposées par défaut (blocage API Win32 depuis macros Office, scripts obfusqués, protection avancée anti-ransomware, vol d'identifiants LSASS) sont un sous-ensemble volontairement restreint et à faible taux de faux positifs parmi celles disponibles dans Microsoft Defender ; surveillez les événements Defender (ID 1121 en mode Bloquer, 1122 en mode Audit/Avertir) avant de passer au mode supérieur.

## Focus : sauvegarde, obsolescence, journalisation et contrôle final

**Sauvegarde (`Theme 13`)** : la planification (action `3`) installe la fonctionnalité Windows Server Backup si besoin et crée une tâche planifiée exécutant `wbadmin start systemstatebackup`, sous le compte SYSTEM du DC. Une sauvegarde non testée ne constitue pas une garantie de reprise : l'action `4` génère dans `Logs\Procedures\` trois procédures texte (récupération d'un objet via la Corbeille AD, récupération d'un DC via DSRM/`ntdsutil`/restauration authoritative, et un résumé de reconstruction de forêt basé sur l'AD Forest Recovery Guide de Microsoft) — à **tester en conditions réelles au moins une fois**, idéalement en labo.

**Obsolescence (`Theme 14`)** : l'inventaire OS (action `1`) s'appuie sur une liste de référence des systèmes EOL codée dans le script (`$Script:KnownEolOsPatterns`), volontairement large et **à maintenir à jour** — vérifiez la date de fin de support exacte auprès de Microsoft avant d'agir sur un résultat. Le plan de traitement consolidé (action `3`) ne rejoue PAS l'audit des protocoles obsolètes sur les machines (qui nécessite un choix d'OU) : il se concentre sur les constats déjà disponibles sans interaction (OS, comptes de service en RC4/DES).

**Journalisation et détection (`Theme 15`)** : l'audit SACL (actions `1` et `4`) manipule les règles d'audit d'objet AD via `System.DirectoryServices.ActiveDirectoryAuditRule` (la même technique que celle utilisée par l'onglet "Audit" des Paramètres de sécurité avancés dans ADUC) — la remédiation est **additive**, elle n'enlève aucune règle d'audit existante. La redirection vers un collecteur SIEM (action `5`) configure uniquement le registre `EventForwarding\SubscriptionManager` côté DC (paramètre "Configurer le gestionnaire d'abonnements cible") : elle suppose qu'un collecteur Windows Event Forwarding (ou une passerelle SIEM compatible) existe déjà côté client.

**Contrôle final (`Theme 16`)** : le contrôle consolidé (action `1`) enchaîne comptes à privilèges, délégations Kerberos, mots de passe n'expirant jamais, signature SMB, certificats LDAPS, déploiement LAPS et socle GPO-SEC-*, conformément à la demande "validation SMB / NTLM / Kerberos / LDAP / LDAPS / LAPS" du cahier des charges. L'étape NTLMv1/LM (lecture du journal Sécurité, potentiellement longue) est proposée à part avec confirmation dédiée plutôt que lancée automatiquement. Les audits nécessitant un choix d'OU (Defender, partages SMB, protocoles obsolètes, administrateurs locaux...) restent à lancer individuellement depuis leur thème. Le registre des exceptions (action `2`) est un simple CSV à compléter manuellement au fil de la mission, pour documenter tout risque accepté/compensé plutôt que corrigé.

**Comptes à privilèges, Kerberos et postes/serveurs (compléments)** : la restriction à des postes d'administration dédiés (`Theme 1 > 11`) positionne l'attribut natif AD `LogonWorkstations` (aucune limitation GPMC ici, contrairement à l'interdiction de logon interactif des comptes de service) — gardez toujours un accès de secours avant de l'appliquer à un compte. La désactivation du compte Administrateur intégré (`Theme 1 > 10`) refuse d'agir si aucun autre compte Domain Admins actif n'est trouvé. Kerberos Armoring (`Theme 3 > 8`) est déployé en mode "Supported" (jamais "Required" directement) pour rester rétrocompatible le temps de la validation.

## Journalisation

- `Logs\Remediation_AD_<horodatage>.log` : trace complète de la session (toutes les actions, y compris en simulation).
- `Logs\Rapport_*.csv` : un export par rapport exécuté (comptes inactifs, mots de passe n'expirant jamais, groupes privilégiés, hotfix, NTLMv1/LM, délégations Kerberos, comptes de service, couverture/permissions LAPS, usage SMBv1, signature SMB, certificats LDAPS, Simple Binds LDAP, socle GPO-SEC-*, Defender, administrateurs locaux, sauvegardes System State, OS obsolètes, protocoles obsolètes).
- `Logs\GPO_Backups\<horodatage>\` : sauvegarde complète de toutes les GPO du domaine (action `Theme 10 > 2`).
- `Logs\Procedures\` : procédures de récupération générées (objet, DC, forêt — action `Theme 13 > 4`).
- `Logs\Plan_Traitement_Obsolescence_*.csv` : plan de traitement consolidé de l'obsolescence (action `Theme 14 > 3`).
- `Logs\Registre_Exceptions.csv` : registre des exceptions à compléter manuellement (action `Theme 16 > 2`).
- `Logs\Comptes_Inactifs_*.csv` / `Logs\Desactivation_ParDate_*.csv` : liste des comptes traités (et exclus par garde-fou, avec la raison) avant chaque désactivation par ancienneté / par date choisie.
- `Logs\krbtgt_reset_tracking.log` : horodatage du dernier reset manuel krbtgt, pour planifier le second.
- Sur le DC hébergeant la rotation KRBTGT planifiée : `C:\ADHC-Scripts\Krbtgt-Rotation.log` + journal d'événements `ADHC-KrbtgtRotation`.
- Sur le DC hébergeant l'automatisation de désactivation : `C:\ADHC-Scripts\Disable-ByDate.log` + journal d'événements `ADHC-AutoDisable`.

## Focus : activer WinRM sur les DC quand ils sont injoignables

L'action `Theme 7 > 2` permet d'activer PowerShell Remoting directement depuis le script, sans avoir à se connecter manuellement à chaque DC. Deux méthodes, proposées ensemble ou séparément :

- **[1] Via GPO (recommandée)** : crée/lie une GPO `ADHC - Activation WinRM sur les DC` sur l'OU Domain Controllers. Cette méthode fonctionne **même si WinRM est totalement arrêté** sur la cible, car une GPO est récupérée par le client via SYSVOL/LDAP — elle ne dépend donc pas du remoting lui-même (contrairement à `Invoke-Command`). Elle configure :
  - le démarrage automatique du service WinRM (Préférences de stratégie de groupe, registre `HKLM\SYSTEM\CurrentControlSet\Services\WinRM\Start = 2`) ;
  - la stratégie *"Allow remote server management through WinRM"* (`HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service`), qui crée automatiquement le listener HTTP sur toutes les IP au démarrage du service (équivalent de `winrm quickconfig`, sans avoir à l'exécuter sur le DC) ;
  - une règle de pare-feu entrante pour le port 5985 (`Windows Remote Management (HTTP-In)`), poussée directement dans la GPO via le module `NetSecurity` (`Open-NetGPO` / `New-NetFirewallRule -GPOSession` / `Save-NetGPO`) — si ce module est indisponible ou les droits insuffisants, le script avertit et indique comment l'activer manuellement dans la GPO.

  **Prise en compte différée** : au prochain rafraîchissement de GPO sur chaque DC (`gpupdate /force` ou cycle normal), puis un **redémarrage du service WinRM** (ou du serveur) est nécessaire pour que le nouveau listener soit effectivement créé.

- **[2] Immédiate via WMI/DCOM** : pour ne pas attendre un cycle de GPO, active WinRM tout de suite sur les DC choisis en lançant `winrm quickconfig -quiet -force` et l'activation de la règle de pare-feu à distance via WMI/DCOM (`New-CimSession -SessionOption (New-CimSessionOption -Protocol Dcom)` + `Invoke-CimMethod ... Win32_Process Create`). Cette méthode fonctionne dès lors que **WMI/DCOM (RPC)** est lui-même joignable vers le DC — souvent le cas même quand WinRM ne l'est pas, car les règles de pare-feu AD par défaut autorisent WMI entre postes d'administration et DC. Le script revérifie la connectivité WinRM juste après la tentative.

Choisir `[3]` applique les deux méthodes : l'activation immédiate pour un accès tout de suite, et la GPO pour que la configuration survive à un redémarrage/une réinstallation et couvre aussi les futurs DC ajoutés à l'OU.

## Dépannage : erreur WinRM ("La connexion au serveur distant ... a échoué")

Les actions qui s'exécutent sur les contrôleurs de domaine (`auditpol`, audit NTLM, signature LDAP, Spooler, rotation KRBTGT, automatisation...) passent par `Invoke-Command`, qui nécessite le **PowerShell Remoting (WinRM)** activé sur la cible. Avant de lancer ces actions, le script vérifie désormais la joignabilité WinRM de chaque DC (`Test-WSMan`) et **écarte proprement** les DC injoignables plutôt que d'échouer au milieu de l'action, avec un message rappelant les points à vérifier sur le(s) serveur(s) concerné(s).

**Le script peut désormais corriger cela lui-même** via l'action `Theme 7 > 2` (voir [focus dédié](#focus--activer-winrm-sur-les-dc-quand-ils-sont-injoignables)), qui active WinRM par GPO et/ou immédiatement via WMI/DCOM. En dépannage manuel, les points à vérifier sont les mêmes :

- Le service **WinRM** est démarré (`winrm quickconfig` ou `Enable-PSRemoting -Force` sur le serveur cible).
- La règle de pare-feu **"Gestion à distance de Windows (HTTP-In)"** est activée pour le profil réseau utilisé (Domaine/Privé) — le profil **Public** la bloque par défaut, cas fréquent si l'interface réseau du DC est mal catégorisée.
- Le **nom du DC se résout correctement en DNS** depuis le poste qui lance le script.
- Le serveur est bien **allumé et joignable sur le réseau** (pas de règle de pare-feu réseau bloquant le port 5985/5986 entre le poste et le DC).

> Avant cette vérification préalable, une erreur de connexion sur un DC pouvait passer inaperçue : `Invoke-Command` sans `-ErrorAction Stop` traite un échec de connexion comme une erreur non bloquante, affichée en rouge mais n'interrompant pas le script — qui loggait alors à tort "Terminé (OK)" sans que l'action ait réellement été appliquée sur ce DC. Toutes les commandes distantes du script utilisent maintenant `-ErrorAction Stop`, pour que ce type d'échec soit remonté correctement (log `ERROR`) au lieu d'être silencieusement ignoré.

## Limites connues / points d'attention

- L'index de recherche (`[R]` au menu principal) est une liste statique tenue à jour manuellement en parallèle des menus : en cas d'ajout/retrait futur d'une action sans mise à jour de cet index, la recherche peut devenir légèrement incomplète ou afficher un libellé perimé — sans aucun risque fonctionnel, puisqu'elle n'exécute jamais rien elle-même (juste un texte indicatif "Thème X > Y").
- Les GPO créées pour NTLMv1 et LLMNR sont **volontairement non liées automatiquement** (impact potentiellement large) : à lier manuellement sur un OU pilote après validation.
- Le rapport NTLMv1/LM peut être lent sur un DC avec un gros volume de journal Sécurité ; commencer avec une période courte (ex. 2-3 jours) pour valider le fonctionnement.
- La rotation KRBTGT planifiée nécessite un forest functional level ≥ 2012 (gMSA) et une KDS Root Key ; en environnement mono-DC, le script propose de forcer sa disponibilité immédiate (à éviter en production multi-DC, où il vaut mieux laisser les ~10h de propagation naturelle).
- L'interdiction de connexion interactive/RDP des comptes de service (`Theme 2 > 4`) crée le groupe et la GPO, mais l'Attribution des droits utilisateur (`Deny log on locally`/RDP) reste une **étape manuelle dans GPMC** : le module PowerShell `GroupPolicy` ne l'expose pas, et l'éditer par manipulation directe du modèle de sécurité (`GptTmpl.inf`) sans validation en environnement réel présente un risque de corruption de la GPO jugé disproportionné pour cette version.
- L'inventaire des comptes de service repose sur une heuristique (SPN + OU choisies), pas sur un marqueur AD garanti — à valider au cas par cas avant remédiation (voir [focus dédié](#focus--comptes-de-service-inventaire-et-remédiations)).
- Le thème Windows LAPS cible LAPS moderne (`msLAPS-*`) ; un environnement encore sur l'ancien LAPS legacy (`ms-Mcs-AdmPwd`) n'est pas couvert par cet audit.
- Les GPO créées pour le durcissement des chemins UNC SYSVOL/NETLOGON (Hardened UNC Paths) sont, comme NTLMv1/LLMNR, **volontairement non liées automatiquement** : à lier manuellement sur un OU pilote après validation.
- L'audit des Simple Binds LDAP (événement 2887) ne remonte un résultat exploitable qu'environ 24h après l'activation du diagnostic `16 LDAP Interface Events` — un premier passage juste après activation reviendra probablement vide.
- La désactivation SMBv1 et le forçage TLS 1.2 sur les DC peuvent nécessiter un redémarrage pour une prise en compte complète (fonctionnalité optionnelle Windows / paramètres SCHANNEL en cache).
- Le socle `GPO-SEC-*` (`Theme 10 > 3`) crée des GPO **vides** : les remédiations thématiques (LAPS, NTLM, SMB, LLMNR, Defender, RDP, RPC, WinRM...) continuent pour l'instant d'écrire dans leurs propres GPO `ADHC - ...` dédiées plutôt que dans ce socle nommé — une convergence complète nécessiterait de retoucher chacune de ces fonctions déjà testées, jugé plus risqué qu'utile pour cette passe.
- La restriction RDP (`Theme 11 > 4`) et le durcissement Defender/RPC/WinRM sont poussés par GPO **liée aux OU choisies interactivement**, jamais au niveau du domaine entier par défaut.
- Les audits/remédiations du thème "Postes et serveurs" (Defender, administrateurs locaux) nécessitent PowerShell Remoting (WinRM) actif sur les machines ciblées, comme pour les DC ; ils demandent explicitement de choisir une/des OU (pas d'option "tout le parc" pour éviter un impact ou un temps d'exécution incontrôlé).
- La sauvegarde System State planifiée (`Theme 13 > 3`) crée la tâche mais ne teste pas la restauration : une sauvegarde non testée ne constitue pas une garantie de reprise (voir la génération de procédures, `Theme 13 > 4`, à exécuter en conditions réelles au moins une fois).
- La liste des OS considérés obsolètes (`Theme 14`) est codée dans le script (`$Script:KnownEolOsPatterns`) et volontairement large : à vérifier/ajuster selon les dates de fin de support réelles au moment de l'audit.
- L'audit SACL (`Theme 15`) ajoute une règle d'audit pour le principal "Tout le monde" : c'est la pratique standard recommandée par Microsoft pour ce type de suivi, mais cela augmente le volume du journal Sécurité (déjà pris en compte par l'audit avancé, à surveiller si l'espace disque est limité).
- Le contrôle final consolidé (`Theme 16 > 1`) ne remplace pas un nouvel audit PingCastle complet (outil séparé), ni les audits nécessitant un choix d'OU (Defender, partages SMB, protocoles obsolètes, administrateurs locaux), à lancer individuellement.
- La restriction Internet des DC (mentionnée dans le cahier des charges) n'est **pas automatisée** par pare-feu Windows local : elle relève normalement du pare-feu périmétrique/proxy, un blocage sortant local mal calibré cassant souvent Windows Update, la vérification de révocation de certificats (CRL/OCSP) ou la synchronisation horaire externe.
- L'audit "rôles et fonctionnalités installés" sur les DC (`Theme 7 > 3`) compare à une liste indicative de rôles attendus codée dans le script — à ajuster selon votre contexte (certains ajouts sont légitimes).
- La correction de la politique de mot de passe par défaut (`Theme 9 > 4`) s'applique à **tout le domaine** : testez l'impact sur les utilisateurs avant de l'appliquer en production.
- Ce script couvre les constats **récurrents** observés dans les rapports PingCastle fournis, ainsi que l'ensemble des sections du cahier des charges client de sécurisation Active Directory & identité à l'exception d'AD CS/PKI et de Microsoft Entra ID hybride (volontairement hors périmètre). Il ne remplace pas une revue complète du rapport PingCastle (certains constats très spécifiques à un client ne sont pas automatisés), ni un jugement humain sur la pertinence de chaque remédiation dans le contexte du client.
