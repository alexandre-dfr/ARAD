<#
    AD_Remediation_Menu.ps1
    ------------------------------------------------------------------
    Script de remediation Active Directory a menu, base sur les constats
    recurrents releves dans des rapports PingCastle (krbtgt, NTLMv1, LAPS,
    comptes inactifs, delegations, mots de passe n'expirant jamais, etc.)

    Deux familles d'actions :
      [1] SAFE      -> aucune incidence fonctionnelle sur la prod (lecture,
                        activation de fonctionnalites additives, protections
                        qui ne changent aucun comportement existant)
      [2] A VALIDER -> impact potentiel sur des postes/applications/comptes
                        de service legacy. Necessite une fenetre de
                        maintenance, une confirmation tapee explicitement,
                        et le mode simulation est actif par defaut.

    A executer en tant qu'Administrateur du domaine, depuis un poste avec
    le module ActiveDirectory (RSAT), idealement sur/depuis un DC.

    Ce script NE FAIT RIEN tant que le mode simulation n'est pas desactive
    (option [S] du menu principal) ET que l'action n'a pas ete confirmee.
    ------------------------------------------------------------------
#>

[CmdletBinding()]
param()

# ============================================================
#  CONFIGURATION GLOBALE
# ============================================================

$Script:SimulationMode = $true
$Script:LogDir  = Join-Path -Path $PSScriptRoot -ChildPath "Logs"
$Script:LogFile = Join-Path -Path $Script:LogDir -ChildPath ("Remediation_AD_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
$Script:QuarantineOUName = "SEC-OU_QUARANTAINE_COMPTES_INACTIFS"
$Script:DisableUserOUName = "SEC-disable_user"
$Script:DisableComputerOUName = "SEC-disable_computer"
# Groupes a privileges exclus PAR DEFAUT (jamais desactives/deplaces) des actions de
# desactivation par date/anciennete. Des groupes supplementaires (comptes de service,
# VIP...) peuvent etre ajoutes de maniere interactive au moment de l'action.
$Script:DefaultExcludedGroups = @(
    "Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators",
    "Account Operators", "Backup Operators", "Server Operators", "Print Operators",
    "Group Policy Creator Owners", "Protected Users", "DnsAdmins", "Cert Publishers"
)

if (-not (Test-Path $Script:LogDir)) {
    New-Item -Path $Script:LogDir -ItemType Directory -Force | Out-Null
}

# ============================================================
#  FONCTIONS UTILITAIRES
# ============================================================

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("INFO","OK","WARN","ERROR","ACTION","SIMU")][string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[{0}] [{1}] {2}" -f $timestamp, $Level, $Message

    switch ($Level) {
        "OK"     { Write-Host $line -ForegroundColor Green }
        "WARN"   { Write-Host $line -ForegroundColor Yellow }
        "ERROR"  { Write-Host $line -ForegroundColor Red }
        "ACTION" { Write-Host $line -ForegroundColor Cyan }
        "SIMU"   { Write-Host $line -ForegroundColor DarkGray }
        default  { Write-Host $line -ForegroundColor Gray }
    }

    Add-Content -Path $Script:LogFile -Value $line -Encoding UTF8
}

function Show-Banner {
    Clear-Host
    Write-Host "================================================================" -ForegroundColor DarkCyan
    Write-Host "   SCRIPT DE REMEDIATION ACTIVE DIRECTORY - BASE SUR PINGCASTLE " -ForegroundColor DarkCyan
    Write-Host "================================================================" -ForegroundColor DarkCyan
    $modeTxt = if ($Script:SimulationMode) { "SIMULATION (aucune modification appliquee)" } else { "REEL - LES ACTIONS SERONT APPLIQUEES" }
    $modeColor = if ($Script:SimulationMode) { "Yellow" } else { "Red" }
    Write-Host (" Mode actuel : {0}" -f $modeTxt) -ForegroundColor $modeColor
    Write-Host (" Journal     : {0}" -f $Script:LogFile) -ForegroundColor DarkGray
    try {
        $dom = Get-ADDomain -ErrorAction Stop
        Write-Host (" Domaine     : {0}" -f $dom.DNSRoot) -ForegroundColor DarkGray
    } catch { }
    if ($Script:ActionIndex) {
        Write-Host (" {0} actions disponibles sur 18 themes - [R] au menu principal pour rechercher par mot-cle." -f $Script:ActionIndex.Count) -ForegroundColor DarkGray
    }
    Write-Host "================================================================" -ForegroundColor DarkCyan
    Write-Host " Legende : " -ForegroundColor DarkGray -NoNewline
    Write-Host "(SAFE) " -ForegroundColor Green -NoNewline
    Write-Host "sans impact prod   " -ForegroundColor DarkGray -NoNewline
    Write-Host "(A VALIDER) " -ForegroundColor Red -NoNewline
    Write-Host "impact potentiel   " -ForegroundColor DarkGray -NoNewline
    Write-Host "(gris) " -ForegroundColor Gray -NoNewline
    Write-Host "audit/lecture seule/outillage" -ForegroundColor DarkGray
    Write-Host "================================================================" -ForegroundColor DarkCyan
    Write-Host ""
}

function Test-Prerequisites {
    $ok = $true

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Log "Le module ActiveDirectory (RSAT) est introuvable. Installez les RSAT AD DS avant de continuer." -Level ERROR
        $ok = $false
    } else {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    }

    try {
        $null = Get-ADDomain -ErrorAction Stop
    } catch {
        Write-Log "Impossible de contacter le domaine Active Directory. Verifiez la connectivite / les droits." -Level ERROR
        $ok = $false
    }

    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    $isDomainAdmin = $false
    try {
        $daMembers = Get-ADGroupMember -Identity "Domain Admins" -Recursive -ErrorAction Stop | Select-Object -ExpandProperty SID
        $isDomainAdmin = $daMembers -contains $currentUser.User
    } catch { }

    if (-not $isDomainAdmin) {
        Write-Log "Le compte courant ($($currentUser.Name)) ne semble pas etre membre (direct/indirect) de 'Domain Admins'. Certaines actions echoueront." -Level WARN
    }

    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log "La console n'est pas lancee en tant qu'Administrateur local. Relancez PowerShell en 'Executer en tant qu'administrateur'." -Level WARN
    }

    return $ok
}

function Confirm-Action {
    <#
        Confirmation simple (SAFE) : O/N
        Confirmation renforcee (A VALIDER) : l'utilisateur doit taper exactement CONFIRMER
    #>
    param(
        [Parameter(Mandatory)][string]$ActionLabel,
        [switch]$Strong
    )

    if ($Strong) {
        Write-Host ""
        Write-Host "!!! ACTION A IMPACT POTENTIEL !!!" -ForegroundColor Red
        Write-Host ("  -> {0}" -f $ActionLabel) -ForegroundColor Red
        Write-Host "  Cette action peut affecter des postes, comptes de service ou applications legacy." -ForegroundColor Yellow
        Write-Host "  Assurez-vous d'etre dans une fenetre de maintenance et d'avoir une sauvegarde/rollback possible." -ForegroundColor Yellow
        $resp = Read-Host "  Tapez EXACTEMENT 'CONFIRMER' pour executer cette action, ou appuyez sur Entree pour annuler"
        return ($resp -ceq "CONFIRMER")
    } else {
        $resp = Read-Host ("Confirmez-vous : {0} ? (O/N)" -f $ActionLabel)
        return ($resp -match '^[oOyY]')
    }
}

function Invoke-Guarded {
    <#
        Encapsule une action reelle : si SimulationMode est actif, affiche
        seulement ce qui SERAIT fait, sinon execute le scriptblock fourni.
    #>
    param(
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][scriptblock]$Action
    )

    if ($Script:SimulationMode) {
        Write-Log ("[SIMULATION] {0}" -f $Description) -Level SIMU
        return
    }

    try {
        Write-Log ("Execution : {0}" -f $Description) -Level ACTION
        & $Action
        Write-Log ("Termine   : {0}" -f $Description) -Level OK
    } catch {
        Write-Log ("Echec de l'action [{0}] : {1}" -f $Description, $_.Exception.Message) -Level ERROR
    }
}

function Pause-Menu {
    Write-Host ""
    Read-Host "Appuyez sur Entree pour revenir au menu"
}

function Write-MenuItem {
    <#
        Affiche une ligne de menu numerotee (alignee sur 2 caracteres), coloree
        automatiquement selon le tag present dans le libelle : vert pour (SAFE),
        rouge pour (A VALIDER), gris clair sinon (audit/navigation/outillage) -
        pour reperer le niveau de risque d'un item au premier coup d'oeil, sans
        avoir a lire tout le texte. -Color permet de forcer une couleur (utilise
        par le menu principal pour regrouper les themes par categorie).
    #>
    param(
        [Parameter(Mandatory)][string]$Number,
        [Parameter(Mandatory)][string]$Label,
        [string]$Color
    )
    if (-not $Color) {
        $Color = if ($Label -match '^\(SAFE\)') { 'Green' } elseif ($Label -match '^\(A VALIDER\)') { 'Red' } else { 'Gray' }
    }
    Write-Host (" {0,2}. {1}" -f $Number, $Label) -ForegroundColor $Color
}

function Write-MenuCategory {
    param([Parameter(Mandatory)][string]$Text)
    Write-Host ""
    Write-Host (" -- {0} --" -f $Text.ToUpper()) -ForegroundColor DarkYellow
}

function Get-DomainControllersList {
    # @() force un tableau meme s'il n'y a qu'1 seul DC (sinon .Count/foreach se comportent mal
    # sur l'objet unique renvoye par la cmdlet).
    try {
        return @(Get-ADDomainController -Filter * -ErrorAction Stop)
    } catch {
        Write-Log "Impossible de lister les controleurs de domaine : $($_.Exception.Message)" -Level ERROR
        return @()
    }
}

function Test-DCWinRmConnectivity {
    <#
        Verifie que le PowerShell Remoting (WinRM) repond sur chaque serveur AVANT
        de lancer une action a distance dessus. Sans ce controle prealable, un DC
        injoignable produit une erreur de connexion NON BLOQUANTE (Invoke-Command
        sans -ErrorAction Stop) qui s'affiche en rouge mais n'empeche pas le script
        de logguer "Termine (OK)" a tort. Permet d'ecarter proprement les serveurs
        injoignables, avec un message de diagnostic actionnable, plutot que de
        laisser echouer chaque commande distante une par une.
    #>
    param([Parameter(Mandatory)][string[]]$ComputerNames)

    $reachable = @()
    $unreachable = @()
    foreach ($name in $ComputerNames) {
        try {
            Test-WSMan -ComputerName $name -ErrorAction Stop | Out-Null
            $reachable += $name
        } catch {
            $unreachable += $name
        }
    }

    if ($unreachable.Count -gt 0) {
        Write-Log ("PowerShell Remoting (WinRM) injoignable sur : {0}. Ces serveurs seront ignores pour cette action." -f ($unreachable -join ', ')) -Level WARN
        Write-Log "A verifier sur ces serveurs : service WinRM demarre ('winrm quickconfig' ou 'Enable-PSRemoting -Force'), regle de pare-feu 'Gestion a distance de Windows (HTTP-In)' active sur le profil reseau utilise, resolution DNS du nom, et serveur bien allume/joignable sur le reseau." -Level WARN
    }

    return [PSCustomObject]@{ Reachable = $reachable; Unreachable = $unreachable }
}

function Add-DisabledMarkerToDescription {
    <#
        Ajoute (sans ecraser une description existante) la mention "Desactive le :
        <date>" sur un objet utilisateur/ordinateur desactive, pour tracer
        directement dans l'annuaire QUAND l'objet a ete desactive par le script.
    #>
    param([Parameter(Mandatory)][string]$Identity)

    $marker = "Desactive le : {0}" -f (Get-Date -Format "dd/MM/yyyy")
    $obj = Get-ADObject -Identity $Identity -Properties Description
    $newDescription = if ([string]::IsNullOrWhiteSpace($obj.Description)) { $marker } else { "$($obj.Description) | $marker" }
    Set-ADObject -Identity $Identity -Replace @{ Description = $newDescription }
}

function New-RandomComplexPassword {
    param([int]$Length = 32)
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+'
    $bytes = New-Object byte[] $Length
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
}

function Read-InactivityThresholds {
    <#
        Seuils d'inactivite laisses a l'appreciation du technicien (contexte metier :
        conges longue duree, comptes de service peu sollicites, saisonnalite, etc.)
        Reutilise par le rapport ET par l'action de desactivation pour rester coherent.
    #>
    param(
        [int]$DefaultUserDays = 180,
        [int]$DefaultComputerDays = 90
    )

    Write-Host ""
    Write-Host "Seuils d'inactivite : a ajuster selon le contexte du client (ne pas se fier uniquement" -ForegroundColor DarkGray
    Write-Host "aux valeurs par defaut - un compte 'inactif' peut etre un salarie en conge, un compte" -ForegroundColor DarkGray
    Write-Host "de service saisonnier, etc.)." -ForegroundColor DarkGray

    $u = Read-Host ("Seuil d'inactivite UTILISATEURS en jours [defaut {0}]" -f $DefaultUserDays)
    if ([string]::IsNullOrWhiteSpace($u) -or $u -notmatch '^\d+$') { $u = $DefaultUserDays }

    $c = Read-Host ("Seuil d'inactivite ORDINATEURS en jours [defaut {0}]" -f $DefaultComputerDays)
    if ([string]::IsNullOrWhiteSpace($c) -or $c -notmatch '^\d+$') { $c = $DefaultComputerDays }

    return [PSCustomObject]@{
        UserDays     = [int]$u
        ComputerDays = [int]$c
    }
}

# ============================================================
#  GARDE-FOUS PARTAGES (exclusions OU/groupes, comptes systeme proteges)
#  Utilises par les actions de desactivation par date/anciennete, en mode
#  interactif ET dans le script autonome deploye pour l'automatisation.
# ============================================================

function Get-AlwaysProtectedPrincipalSids {
    <#
        Comptes systeme JAMAIS desactivables/deplacables, quels que soient les
        choix de l'utilisateur : krbtgt, Administrateur et Invite integres
        (RID bien connus 500/501/502, valables sur tout domaine AD), et le
        compte qui execute le script lui-meme (pour ne jamais se desactiver soi-meme).
    #>
    $sids = New-Object System.Collections.Generic.HashSet[string]
    try {
        $domainSidStr = (Get-ADDomain).DomainSID.Value
        foreach ($rid in 500, 501, 502) {
            try {
                $obj = Get-ADObject -LDAPFilter "(objectSid=$domainSidStr-$rid)" -ErrorAction SilentlyContinue
                if ($obj) { [void]$sids.Add($obj.ObjectSID.Value) }
            } catch { }
        }
    } catch { }

    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        [void]$sids.Add($currentUser.User.Value)
    } catch { }

    return $sids
}

function Get-ProtectedDCComputerDNs {
    # Les controleurs de domaine ne doivent jamais etre desactives/deplaces.
    $dns = New-Object System.Collections.Generic.HashSet[string]
    foreach ($dc in (Get-DomainControllersList)) {
        try { [void]$dns.Add((Get-ADComputer -Identity $dc.Name).DistinguishedName) } catch { }
    }
    return $dns
}

function Get-ExpandedGroupMemberSids {
    param([string[]]$GroupNames)
    $sids = New-Object System.Collections.Generic.HashSet[string]
    foreach ($g in $GroupNames) {
        if ([string]::IsNullOrWhiteSpace($g)) { continue }
        try {
            Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop | ForEach-Object { [void]$sids.Add($_.SID.Value) }
        } catch {
            Write-Log ("Groupe d'exclusion '{0}' introuvable ou inaccessible - ignore." -f $g) -Level WARN
        }
    }
    return $sids
}

function Select-OUsInteractive {
    <#
        Selecteur d'UO interactif generique et numerote. Reutilise pour choisir des
        UO a EXCLURE (garde-fous de desactivation) ou a CIBLER (perimetre d'une
        action : comptes de service, deploiement LAPS...) - seul le libelle change.
    #>
    param(
        [Parameter(Mandatory)][string]$Label,
        [string]$Verb = "EXCLURE"
    )

    $ous = @(Get-ADOrganizationalUnit -Filter * -ErrorAction SilentlyContinue | Sort-Object DistinguishedName)
    if (-not $ous) { return @() }

    Write-Host ""
    Write-Host ("UO disponibles a {0} pour {1} :" -f $Verb, $Label) -ForegroundColor DarkGray
    for ($i = 0; $i -lt $ous.Count; $i++) { Write-Host ("  [{0}] {1}" -f $i, $ous[$i].DistinguishedName) }
    $sel = Read-Host ("Numeros des UO a {0} pour {1}, separes par une virgule (vide = aucune)" -f $Verb, $Label)
    if ([string]::IsNullOrWhiteSpace($sel)) { return @() }

    $idx = @($sel -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ } | Where-Object { $_ -lt $ous.Count })
    return @($idx | ForEach-Object { $ous[$_].DistinguishedName })
}

function Select-ExclusionOUs {
    param([Parameter(Mandatory)][string]$Label)
    return Select-OUsInteractive -Label $Label -Verb "EXCLURE"
}

function Select-AccountsInteractive {
    <#
        Affiche une liste numerotee de comptes et laisse choisir un sous-ensemble
        (numeros separes par une virgule, 'tous', ou vide pour annuler). Reutilise
        par les remediations du theme "comptes de service" pour cibler precisement
        les comptes traites plutot que d'agir sur la liste entiere sans revue.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Accounts,
        [Parameter(Mandatory)][string]$Prompt
    )

    if ($Accounts.Count -eq 0) { return @() }

    for ($i = 0; $i -lt $Accounts.Count; $i++) {
        Write-Host ("  [{0}] {1}" -f $i, $Accounts[$i].SamAccountName)
    }
    $sel = Read-Host $Prompt
    if ([string]::IsNullOrWhiteSpace($sel)) { return @() }
    if ($sel.Trim() -eq 'tous') { return @($Accounts) }

    $idx = @($sel -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ } | Where-Object { $_ -lt $Accounts.Count })
    return @($idx | ForEach-Object { $Accounts[$_] })
}

function Read-ExtraExclusionGroups {
    <#
        Garde-fou : membres de ces groupes jamais desactives/deplaces (ex : comptes
        admin). Une liste de groupes a privileges est exclue par defaut ; des groupes
        supplementaires (comptes de service, VIP...) peuvent etre ajoutes.
    #>
    Write-Host ""
    Write-Host "Groupes EXCLUS par defaut (jamais desactives/deplaces) :" -ForegroundColor DarkGray
    $Script:DefaultExcludedGroups | ForEach-Object { Write-Host ("  - {0}" -f $_) -ForegroundColor DarkGray }

    $extraInput = Read-Host "Groupes SUPPLEMENTAIRES a exclure, noms separes par une virgule (vide = aucun)"
    $extra = @()
    if (-not [string]::IsNullOrWhiteSpace($extraInput)) {
        $extra = @($extraInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        foreach ($g in $extra) {
            if (-not (Get-ADGroup -Filter "Name -eq '$g'" -ErrorAction SilentlyContinue)) {
                Write-Log ("Groupe '{0}' introuvable dans l'annuaire - il sera ignore lors du filtrage." -f $g) -Level WARN
            }
        }
    }

    return @($Script:DefaultExcludedGroups + $extra | Select-Object -Unique)
}

function Read-DisableCutoffDate {
    param([Parameter(Mandatory)][string]$Label)
    $dateInput = Read-Host ("Desactiver {0} dont la derniere connexion est ANTERIEURE au (format jj/mm/aaaa)" -f $Label)
    $formats = @("dd/MM/yyyy", "d/M/yyyy", "yyyy-MM-dd")
    $parsed = [datetime]::MinValue
    $ok = $false
    foreach ($fmt in $formats) {
        if ([datetime]::TryParseExact($dateInput, $fmt, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$parsed)) {
            $ok = $true
            break
        }
    }
    if (-not $ok) {
        Write-Log ("Date invalide : '{0}'. Format attendu jj/mm/aaaa." -f $dateInput) -Level ERROR
        return $null
    }
    if ($parsed -gt (Get-Date)) {
        Write-Host "Cette date est dans le futur : tous les comptes actifs correspondants seraient concernes." -ForegroundColor Yellow
        if ((Read-Host "Continuer avec cette date future ? (O/N)") -notmatch '^[oOyY]') { return $null }
    }
    return $parsed
}

# ============================================================
#  SECTION 1 - FONCTIONS SANS IMPACT PROD (SAFE)
#  (regroupees par theme dans le menu, cf. Show-*Menu en fin de fichier)
# ============================================================

function Invoke-SafeEnableRecycleBin {
    Write-Host "`n--- Activation de la Corbeille Active Directory (AD Recycle Bin) ---" -ForegroundColor Cyan
    Write-Host "Impact : AUCUN sur l'existant. Permet uniquement de restaurer des objets supprimes par erreur." -ForegroundColor DarkGray
    try {
        $forest = (Get-ADForest).Name
        $feature = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" -ErrorAction Stop
        if ($feature.EnabledScopes.Count -gt 0) {
            Write-Log "La Corbeille AD est deja activee." -Level OK
            return
        }
    } catch {
        Write-Log "Impossible de verifier l'etat de la Corbeille AD : $($_.Exception.Message)" -Level ERROR
        return
    }

    if (Confirm-Action "Activer la Corbeille Active Directory") {
        Invoke-Guarded -Description "Enable-ADOptionalFeature 'Recycle Bin Feature'" -Action {
            Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target $forest -Confirm:$false
        }
    }
}

function Invoke-SafeDisableGuest {
    Write-Host "`n--- Desactivation du compte Invite (Guest) ---" -ForegroundColor Cyan
    Write-Host "Impact : AUCUN si le compte Invite n'est pas utilise en production (cas normal)." -ForegroundColor DarkGray
    try {
        $domainSid = (Get-ADDomain).DomainSID.Value
        $guest = Get-ADUser -Identity "$domainSid-501" -Properties Enabled -ErrorAction Stop
    } catch {
        Write-Log "Compte Invite introuvable ou inaccessible : $($_.Exception.Message)" -Level ERROR
        return
    }

    if (-not $guest.Enabled) {
        Write-Log "Le compte Invite est deja desactive." -Level OK
        return
    }

    Write-Host ("Compte trouve : {0}" -f $guest.SamAccountName) -ForegroundColor Yellow
    if (Confirm-Action "Desactiver le compte Invite (Guest)") {
        Invoke-Guarded -Description "Disable-ADAccount sur le compte Invite" -Action {
            Disable-ADAccount -Identity $guest.DistinguishedName
        }
    }
}

function Invoke-SafeProtectOUs {
    Write-Host "`n--- Protection des OU contre la suppression accidentelle ---" -ForegroundColor Cyan
    Write-Host "Impact : AUCUN. Ajoute uniquement un ACE DENY sur la suppression, ne change aucun droit d'acces existant." -ForegroundColor DarkGray

    $ous = @(Get-ADOrganizationalUnit -Filter * -Properties ProtectedFromAccidentalDeletion |
           Where-Object { -not $_.ProtectedFromAccidentalDeletion })

    if (-not $ous) {
        Write-Log "Toutes les OU sont deja protegees contre la suppression accidentelle." -Level OK
        return
    }

    Write-Host ("{0} OU non protegees trouvees :" -f $ous.Count) -ForegroundColor Yellow
    $ous | ForEach-Object { Write-Host ("  - {0}" -f $_.DistinguishedName) }

    if (Confirm-Action ("Proteger ces {0} OU contre la suppression accidentelle" -f $ous.Count)) {
        foreach ($ou in $ous) {
            Invoke-Guarded -Description ("Protection de l'OU {0}" -f $ou.DistinguishedName) -Action {
                Set-ADObject -Identity $ou.DistinguishedName -ProtectedFromAccidentalDeletion $true
            }
        }
    }
}

function Invoke-SafeSetMachineAccountQuotaZero {
    Write-Host "`n--- Limitation du quota de creation d'ordinateurs (ms-DS-MachineAccountQuota) ---" -ForegroundColor Cyan
    Write-Host "Impact : AUCUN sur les postes/serveurs deja joints au domaine. Empeche seulement les" -ForegroundColor DarkGray
    Write-Host "         utilisateurs standards de joindre eux-memes de NOUVEAUX postes (max 10 par defaut)." -ForegroundColor DarkGray

    try {
        $domainDN = (Get-ADDomain).DistinguishedName
        $current = (Get-ADObject -Identity $domainDN -Properties "ms-DS-MachineAccountQuota")."ms-DS-MachineAccountQuota"
    } catch {
        Write-Log "Impossible de lire ms-DS-MachineAccountQuota : $($_.Exception.Message)" -Level ERROR
        return
    }

    Write-Host ("Valeur actuelle : {0}" -f $current) -ForegroundColor Yellow
    if ($current -eq 0) {
        Write-Log "Le quota est deja a 0." -Level OK
        return
    }

    if (Confirm-Action "Mettre ms-DS-MachineAccountQuota a 0 (jonction au domaine reservee aux comptes autorises)") {
        Invoke-Guarded -Description "Set-ADObject ms-DS-MachineAccountQuota = 0" -Action {
            Set-ADObject -Identity $domainDN -Replace @{ "ms-DS-MachineAccountQuota" = 0 }
        }
    }
}

function Invoke-SafeEnableDCAuditPolicy {
    Write-Host "`n--- Activation de la politique d'audit avancee sur les controleurs de domaine ---" -ForegroundColor Cyan
    Write-Host "Impact : AUCUN sur le fonctionnement (journalisation uniquement). Augmente le volume" -ForegroundColor DarkGray
    Write-Host "         des journaux de securite : pensez a dimensionner la taille du journal Security." -ForegroundColor DarkGray

    $dcs = Get-DomainControllersList
    if (-not $dcs) { return }
    $wr = Test-DCWinRmConnectivity -ComputerNames $dcs.HostName
    $dcs = @($dcs | Where-Object { $wr.Reachable -contains $_.HostName })
    if (-not $dcs) { Write-Log "Aucun DC joignable via PowerShell Remoting (WinRM), action annulee." -Level ERROR; return }

    # Les sous-categories sont ciblees par GUID (identifiant stable, independant de la langue
    # de l'OS). Passer le NOM anglais a auditpol echoue avec l'erreur 0x57 "Parametre incorrect"
    # sur un Windows Server installe en francais (ou toute autre langue non-EN).
    $subcategories = @(
        [PSCustomObject]@{ Name = "Kerberos Authentication Service";    Guid = "{0CCE9242-69AE-11D9-BED3-505054503030}" }
        [PSCustomObject]@{ Name = "Kerberos Service Ticket Operations"; Guid = "{0CCE9240-69AE-11D9-BED3-505054503030}" }
        [PSCustomObject]@{ Name = "Credential Validation";              Guid = "{0CCE923F-69AE-11D9-BED3-505054503030}" }
        [PSCustomObject]@{ Name = "Security Group Management";          Guid = "{0CCE9237-69AE-11D9-BED3-505054503030}" }
        [PSCustomObject]@{ Name = "User Account Management";            Guid = "{0CCE9235-69AE-11D9-BED3-505054503030}" }
        [PSCustomObject]@{ Name = "Computer Account Management";        Guid = "{0CCE9236-69AE-11D9-BED3-505054503030}" }
        [PSCustomObject]@{ Name = "Distribution Group Management";      Guid = "{0CCE9238-69AE-11D9-BED3-505054503030}" }
        [PSCustomObject]@{ Name = "Directory Service Access";           Guid = "{0CCE923B-69AE-11D9-BED3-505054503030}" }
        [PSCustomObject]@{ Name = "Directory Service Changes";          Guid = "{0CCE923C-69AE-11D9-BED3-505054503030}" }
        [PSCustomObject]@{ Name = "Directory Service Replication";      Guid = "{0CCE923D-69AE-11D9-BED3-505054503030}" }
        [PSCustomObject]@{ Name = "Sensitive Privilege Use";            Guid = "{0CCE9230-69AE-11D9-BED3-505054503030}" }
        [PSCustomObject]@{ Name = "Other Account Logon Events";         Guid = "{0CCE9241-69AE-11D9-BED3-505054503030}" }
        [PSCustomObject]@{ Name = "Special Logon";                      Guid = "{0CCE921B-69AE-11D9-BED3-505054503030}" }
        [PSCustomObject]@{ Name = "Logon";                              Guid = "{0CCE9215-69AE-11D9-BED3-505054503030}" }
        [PSCustomObject]@{ Name = "Logoff";                             Guid = "{0CCE9216-69AE-11D9-BED3-505054503030}" }
        [PSCustomObject]@{ Name = "Account Lockout";                    Guid = "{0CCE9217-69AE-11D9-BED3-505054503030}" }
    )

    Write-Host ("Cette action va activer Succes+Echec sur {0} sous-categories d'audit, sur {1} DC :" -f $subcategories.Count, $dcs.Count) -ForegroundColor Yellow
    $dcs | ForEach-Object { Write-Host ("  - {0}" -f $_.HostName) }

    if (-not (Confirm-Action "Activer l'audit avance (auditpol) sur tous les DC")) { return }

    foreach ($dc in $dcs) {
        Invoke-Guarded -Description ("auditpol /set sur {0}" -f $dc.HostName) -Action {
            $results = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                param($cats)
                foreach ($c in $cats) {
                    $null = & auditpol.exe /set /subcategory:"$($c.Guid)" /success:enable /failure:enable 2>&1
                    [PSCustomObject]@{
                        Name    = $c.Name
                        Success = ($LASTEXITCODE -eq 0)
                    }
                }
            } -ArgumentList (,$subcategories) -ErrorAction Stop

            $failed = @($results | Where-Object { -not $_.Success })
            if ($failed.Count -gt 0) {
                foreach ($f in $failed) {
                    Write-Log ("Echec auditpol pour la sous-categorie '{0}' sur {1}." -f $f.Name, $dc.HostName) -Level ERROR
                }
                throw ("{0}/{1} sous-categorie(s) n'ont pas pu etre appliquee(s) sur {2}. Verifiez manuellement avec 'auditpol /get /category:*'." -f $failed.Count, @($results).Count, $dc.HostName)
            }
        }
    }
}

function Invoke-SafeEnableNtlmAudit {
    Write-Host "`n--- Activation de l'audit NTLM (detection NTLMv1/LM avant tout blocage) ---" -ForegroundColor Cyan
    Write-Host "Impact : AUCUN sur le fonctionnement. Active uniquement la JOURNALISATION (mode audit," -ForegroundColor DarkGray
    Write-Host "         jamais de blocage) afin d'identifier QUI utilise encore NTLMv1/LM avant de" -ForegroundColor DarkGray
    Write-Host "         forcer sa desactivation (action A VALIDER : Desactiver NTLMv1/LM)." -ForegroundColor DarkGray
    Write-Host "         Laissez tourner plusieurs jours (couvrant un cycle metier complet), puis" -ForegroundColor DarkGray
    Write-Host "         consultez le rapport dedie dans le menu NTLM / LM (item 2)." -ForegroundColor DarkGray

    $dcs = Get-DomainControllersList
    if (-not $dcs) { return }
    $wr = Test-DCWinRmConnectivity -ComputerNames $dcs.HostName
    $dcs = @($dcs | Where-Object { $wr.Reachable -contains $_.HostName })
    if (-not $dcs) { Write-Log "Aucun DC joignable via PowerShell Remoting (WinRM), action annulee." -Level ERROR; return }
    $dcs | ForEach-Object { Write-Host ("  - {0}" -f $_.HostName) }

    if (-not (Confirm-Action "Activer l'audit NTLM (registre + journal NTLM Operational) sur ces DC")) { return }

    foreach ($dc in $dcs) {
        Invoke-Guarded -Description ("Activation de l'audit NTLM sur {0}" -f $dc.HostName) -Action {
            Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Force -ErrorAction SilentlyContinue | Out-Null
                # AuditReceivingNTLMTraffic = 2 -> journalise le NTLM RECU pour tous les comptes (audit uniquement, jamais bloquant)
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "AuditReceivingNTLMTraffic" -Value 2 -Type DWord
                # RestrictSendingNTLMTraffic = 1 -> journalise le NTLM EMIS vers des serveurs distants (audit uniquement, "Audit All", pas de blocage)
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictSendingNTLMTraffic" -Value 1 -Type DWord

                New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Force -ErrorAction SilentlyContinue | Out-Null
                # AuditNTLMInDomain = 1 -> le DC journalise chaque authentification NTLM pass-through dans le domaine (visibilite centralisee)
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "AuditNTLMInDomain" -Value 1 -Type DWord

                & wevtutil.exe set-log "Microsoft-Windows-NTLM/Operational" /enabled:true /quiet | Out-Null
            } -ErrorAction Stop
        }
    }

    Write-Log "Audit NTLM active (journalisation uniquement, aucun blocage applique)." -Level OK
    Write-Log "Rappel : l'audit du logon (menu Journalisation et detection > 2 'audit avance sur les DC') doit aussi etre actif pour que le rapport NTLMv1/LM (menu NTLM / LM > 2) puisse remonter des resultats." -Level WARN
}

function Invoke-SafeEnablePowerShellLogging {
    Write-Host "`n--- Activation de la journalisation PowerShell (Script Block Logging) via GPO ---" -ForegroundColor Cyan
    Write-Host "Impact : AUCUN fonctionnel. Journalisation uniquement (peut augmenter legerement les logs)." -ForegroundColor DarkGray

    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Log "Le module GroupPolicy (RSAT-GPMC) n'est pas installe sur ce poste." -Level ERROR
        return
    }
    Import-Module GroupPolicy -ErrorAction SilentlyContinue

    $gpoName = "SEC - Audit PowerShell Logging"
    $ouTarget = ((Get-ADDomain).DistinguishedName)
    $ouDCs = "OU=Domain Controllers,$ouTarget"

    Write-Host ("GPO cible : '{0}', lien prevu sur : {1}" -f $gpoName, $ouDCs) -ForegroundColor Yellow
    if (-not (Confirm-Action "Creer/mettre a jour cette GPO et l'activer sur l'OU Domain Controllers")) { return }

    Invoke-Guarded -Description "Creation/MAJ GPO PowerShell Logging" -Action {
        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        if (-not $gpo) { $gpo = New-GPO -Name $gpoName }
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ValueName "EnableScriptBlockLogging" -Type DWord -Value 1
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ValueName "EnableModuleLogging" -Type DWord -Value 1
        try { New-GPLink -Name $gpoName -Target $ouDCs -ErrorAction Stop | Out-Null } catch { }
    }
}

function Invoke-SafeClearPasswordNotRequired {
    Write-Host "`n--- Retrait du flag 'Mot de passe non requis' (PASSWD_NOTREQD) ---" -ForegroundColor Cyan
    Write-Host "Impact : AUCUN immediat. Ne force pas de changement de mot de passe, retire simplement" -ForegroundColor DarkGray
    Write-Host "         l'exemption de politique de mot de passe pour le PROCHAIN changement." -ForegroundColor DarkGray

    $accounts = @(Get-ADUser -Filter 'PasswordNotRequired -eq $true' -Properties PasswordNotRequired, Enabled)

    if ($accounts.Count -eq 0) {
        Write-Log "Aucun compte avec 'Mot de passe non requis' trouve." -Level OK
        return
    }

    Write-Host ("{0} compte(s) concerne(s) :" -f $accounts.Count) -ForegroundColor Yellow
    $accounts | ForEach-Object { Write-Host ("  - {0} (Active : {1})" -f $_.SamAccountName, $_.Enabled) }

    if (Confirm-Action ("Retirer le flag PASSWD_NOTREQD sur ces {0} comptes" -f $accounts.Count)) {
        foreach ($acc in $accounts) {
            Invoke-Guarded -Description ("Retrait PASSWD_NOTREQD sur {0}" -f $acc.SamAccountName) -Action {
                Set-ADUser -Identity $acc.DistinguishedName -PasswordNotRequired $false
            }
        }
    }
}

function Invoke-Audit11DefaultPasswordPolicy {
    Write-Host "`n--- Audit de la politique de mot de passe par defaut du domaine ---" -ForegroundColor Magenta

    try {
        $policy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
    } catch {
        Write-Log ("Impossible de lire la politique de mot de passe : {0}" -f $_.Exception.Message) -Level ERROR
        return
    }

    Write-Host ("Longueur minimale     : {0} (recommande >= 14)" -f $policy.MinPasswordLength) -ForegroundColor Yellow
    Write-Host ("Complexite activee    : {0}" -f $policy.ComplexityEnabled) -ForegroundColor Yellow
    Write-Host ("Historique conserve   : {0} (recommande >= 24)" -f $policy.PasswordHistoryCount) -ForegroundColor Yellow
    Write-Host ("Age maximal (jours)   : {0}" -f $policy.MaxPasswordAge.Days) -ForegroundColor Yellow
    Write-Host ("Seuil de verrouillage : {0} (recommande entre 5 et 10, jamais 0)" -f $policy.LockoutThreshold) -ForegroundColor Yellow
    Write-Host ("Duree de verrouillage : {0}" -f $policy.LockoutDuration) -ForegroundColor Yellow

    $issues = @()
    if ($policy.MinPasswordLength -lt 14) { $issues += "Longueur minimale < 14" }
    if (-not $policy.ComplexityEnabled) { $issues += "Complexite desactivee" }
    if ($policy.PasswordHistoryCount -lt 24) { $issues += "Historique < 24" }
    if ($policy.LockoutThreshold -eq 0) { $issues += "Verrouillage de compte DESACTIVE (LockoutThreshold=0)" }

    if ($issues.Count -gt 0) {
        Write-Log ("Points a corriger : {0}" -f ($issues -join ' ; ')) -Level WARN
    } else {
        Write-Log "Politique de mot de passe par defaut conforme aux recommandations de base." -Level OK
    }
}

function Invoke-Remediate11HardenDefaultPasswordPolicy {
    Write-Host "`n--- Corriger la politique de mot de passe par defaut du domaine ---" -ForegroundColor Red
    Write-Host "Risque : un renforcement de la politique peut forcer un changement de mot de passe" -ForegroundColor DarkGray
    Write-Host "         plus contraignant pour les utilisateurs, ou bloquer des mots de passe faibles" -ForegroundColor DarkGray
    Write-Host "         historiques lors de leur prochain changement." -ForegroundColor DarkGray

    $lengthInput = Read-Host "Longueur minimale du mot de passe [defaut 14]"
    $length = if ($lengthInput -match '^\d+$') { [int]$lengthInput } else { 14 }
    $historyInput = Read-Host "Nombre de mots de passe conserves dans l'historique [defaut 24]"
    $history = if ($historyInput -match '^\d+$') { [int]$historyInput } else { 24 }
    $lockoutInput = Read-Host "Seuil de verrouillage (tentatives echouees) [defaut 10]"
    $lockout = if ($lockoutInput -match '^\d+$') { [int]$lockoutInput } else { 10 }

    if (-not (Confirm-Action ("Appliquer : longueur min={0}, complexite=activee, historique={1}, verrouillage={2} tentatives" -f $length, $history, $lockout) -Strong)) { return }

    Invoke-Guarded -Description "Mise a jour de la politique de mot de passe par defaut" -Action {
        Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName -MinPasswordLength $length -ComplexityEnabled $true -PasswordHistoryCount $history -LockoutThreshold $lockout -LockoutDuration ([TimeSpan]::FromMinutes(15)) -LockoutObservationWindow ([TimeSpan]::FromMinutes(15))
    }
}

function Invoke-Remediate11CreateServiceAccountFGPP {
    Write-Host "`n--- Creer une Fine-Grained Password Policy pour les comptes de service ---" -ForegroundColor Red
    Write-Host "S'applique UNIQUEMENT au groupe cible fourni (jamais a tout le domaine) - permet une" -ForegroundColor DarkGray
    Write-Host "politique plus longue/sans expiration courte, adaptee aux comptes de service, sans" -ForegroundColor DarkGray
    Write-Host "toucher la politique par defaut des comptes utilisateurs." -ForegroundColor DarkGray

    $groupName = Read-Host "Groupe AD cible (comptes de service) - sera cree s'il n'existe pas"
    if ([string]::IsNullOrWhiteSpace($groupName)) { Write-Log "Nom de groupe vide, action annulee." -Level WARN; return }

    $lengthInput = Read-Host "Longueur minimale du mot de passe pour ce groupe [defaut 24]"
    $length = if ($lengthInput -match '^\d+$') { [int]$lengthInput } else { 24 }

    $policyName = "PSO-ComptesDeService"
    if (-not (Confirm-Action ("Creer la FGPP '{0}' (longueur min {1}) et l'appliquer au groupe '{2}'" -f $policyName, $length, $groupName) -Strong)) { return }

    Invoke-Guarded -Description ("Creation du groupe {0} (si absent)" -f $groupName) -Action {
        if (-not (Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue)) {
            New-ADGroup -Name $groupName -GroupScope Global -GroupCategory Security -Description "Comptes de service - FGPP dediee (ADHC)"
        }
    }

    Invoke-Guarded -Description ("Creation de la FGPP {0}" -f $policyName) -Action {
        if (-not (Get-ADFineGrainedPasswordPolicy -Identity $policyName -ErrorAction SilentlyContinue)) {
            New-ADFineGrainedPasswordPolicy -Name $policyName -Precedence 10 -MinPasswordLength $length -ComplexityEnabled $true -PasswordHistoryCount 24 -MaxPasswordAge ([TimeSpan]::FromDays(0)) -LockoutThreshold 0 -Description "FGPP comptes de service - deployee par le script de remediation AD"
        }
        Add-ADFineGrainedPasswordPolicySubject -Identity $policyName -Subjects $groupName
    }
    Write-Log ("FGPP '{0}' appliquee au groupe '{1}'. Ajoutez les comptes de service concernes a ce groupe." -f $policyName, $groupName) -Level OK
}

function Invoke-Remediate11GenerateMfaRecommendations {
    Write-Host "`n--- Generer les recommandations MFA / Conditional Access (environnements hybrides) ---" -ForegroundColor Cyan
    Write-Host "Impact : AUCUN. Ecrit uniquement un fichier de recommandations dans Logs\Procedures." -ForegroundColor DarkGray
    Write-Host "La mise en oeuvre reelle (Entra ID / Conditional Access) est hors perimetre technique" -ForegroundColor DarkGray
    Write-Host "de ce script (base PowerShell/AD on-premises)." -ForegroundColor DarkGray

    if (-not (Confirm-Action "Generer le fichier de recommandations MFA/Conditional Access")) { return }

    $content = @'
RECOMMANDATIONS MFA ET CONDITIONAL ACCESS - ENVIRONNEMENTS HYBRIDES
============================================================
A mettre en oeuvre cote Microsoft Entra ID (hors perimetre technique de ce script) :

1. Activer le MFA pour TOUS les comptes administrateurs cloud (Global Admin, Privileged Role
   Admin...) au minimum, puis progressivement pour l'ensemble des utilisateurs.
2. Deployer une politique d'acces conditionnel bloquant les authentifications "legacy" (Basic
   Auth, protocoles ne supportant pas le MFA - IMAP, POP, SMTP AUTH anciens).
3. Exiger le MFA pour tout acces depuis un reseau non approuve (hors plages IP du siege/VPN).
4. Bloquer ou surveiller etroitement les connexions depuis des pays/regions non pertinents pour
   l'activite de l'organisation.
5. Exiger un appareil conforme (Intune) ou joint a Entra ID pour l'acces aux ressources sensibles.
6. Prevoir des methodes de MFA resistantes au phishing (cle de securite FIDO2, Windows Hello for
   Business) pour les comptes a privileges, plutot que SMS/appel telephonique.
7. Revoir regulierement les exclusions de politique d'acces conditionnel (comptes de service
   cloud, comptes de secours "break glass") : elles doivent rester minimales et documentees.
8. Prevoir 2 comptes "break glass" (acces d'urgence) exclus du MFA courant, avec mot de passe
   tres long, surveilles etroitement (alerte a la moindre connexion), conformement aux
   recommandations Microsoft.
'@

    $dir = Join-Path $Script:LogDir "Procedures"
    Invoke-Guarded -Description "Generation des recommandations MFA/Conditional Access" -Action {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
        Set-Content -Path (Join-Path $dir "Recommandations_MFA_ConditionalAccess.txt") -Value $content -Encoding UTF8
    }
    Write-Log ("Recommandations generees dans {0}." -f (Join-Path $dir "Recommandations_MFA_ConditionalAccess.txt")) -Level OK
}

function Invoke-SafeEnableWinRmViaGPO {
    <#
        Active PowerShell Remoting (WinRM) sur les DC via une GPO liee a l'OU
        Domain Controllers : fonctionne MEME SI WinRM est actuellement desactive
        sur la cible, car une GPO est recuperee par le client via SYSVOL/LDAP au
        prochain rafraichissement, sans dependre du remoting lui-meme (contrairement
        a Invoke-Command, qui necessite que WinRM soit deja actif).
        Prise en compte : au prochain rafraichissement de GPO (gpupdate /force ou
        cycle normal) ET un redemarrage du service WinRM (ou du serveur) pour que
        le nouveau listener HTTP soit cree.
    #>
    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Log "Le module GroupPolicy (RSAT-GPMC) n'est pas installe sur ce poste." -Level ERROR
        return
    }
    Import-Module GroupPolicy -ErrorAction SilentlyContinue

    $gpoName = "SEC - Activation WinRM sur les DC"
    $ouDCs = "OU=Domain Controllers,$((Get-ADDomain).DistinguishedName)"

    if (-not (Confirm-Action ("Creer/lier la GPO '{0}' sur l'OU Domain Controllers (service WinRM + listener + regle de pare-feu)" -f $gpoName))) { return }

    Invoke-Guarded -Description "Creation/MAJ GPO activation WinRM" -Action {
        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        if (-not $gpo) { $gpo = New-GPO -Name $gpoName }

        # Demarrage automatique du service WinRM (Group Policy Preferences - registre)
        Set-GPPrefRegistryValue -Name $gpoName -Context Computer -Key "HKLM\SYSTEM\CurrentControlSet\Services\WinRM" -ValueName "Start" -Type DWord -Value 2 -Action Update | Out-Null

        # Policy "Allow remote server management through WinRM" : cree automatiquement le
        # listener HTTP sur toutes les IP au demarrage du service (equivalent 'winrm quickconfig'
        # sans avoir besoin d'executer la commande localement sur le DC).
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -ValueName "AllowAutoConfig" -Type DWord -Value 1
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -ValueName "IPv4Filter" -Type String -Value "*"
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -ValueName "IPv6Filter" -Type String -Value "*"

        # Regle de pare-feu HTTP-In (5985) poussee directement dans la GPO (module NetSecurity),
        # sans passer par le DC lui-meme.
        try {
            $gpoSession = Open-NetGPO -PolicyStore ("{0}\{1}" -f (Get-ADDomain).DNSRoot, $gpoName) -ErrorAction Stop
            if (-not (Get-NetFirewallRule -GPOSession $gpoSession -Name "ADHC-WINRM-HTTP-In-TCP" -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule -GPOSession $gpoSession -Name "ADHC-WINRM-HTTP-In-TCP" -DisplayName "Windows Remote Management (HTTP-In) - ADHC" -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow -Profile Domain, Private -Enabled True | Out-Null
            }
            Save-NetGPO -GPOSession $gpoSession
        } catch {
            Write-Log ("Regle de pare-feu non creee automatiquement (module NetSecurity indisponible ou droits insuffisants) : {0}. A activer manuellement dans la GPO : Configuration ordinateur > Parametres Windows > Parametres de securite > Pare-feu Windows avec fonctions avancees de securite > Regles de trafic entrant > activer le groupe predefini 'Gestion a distance de Windows'." -f $_.Exception.Message) -Level WARN
        }

        try { New-GPLink -Name $gpoName -Target $ouDCs -ErrorAction Stop | Out-Null } catch { }
    }

    Write-Log "GPO liee sur l'OU Domain Controllers. Prise en compte au prochain rafraichissement de GPO SUR CHAQUE DC (gpupdate /force ou cycle normal), puis un redemarrage du service WinRM (ou du serveur) est necessaire pour que le nouveau listener soit cree." -Level WARN
}

function Invoke-SafeEnableWinRmViaWmi {
    <#
        Active WinRM IMMEDIATEMENT sur les DC indiques, sans attendre un cycle de
        GPO, en executant 'winrm quickconfig' a distance via WMI/DCOM (RPC) plutot
        que via WinRM lui-meme - utile car WMI/DCOM est souvent deja joignable
        (regles de pare-feu AD par defaut) meme quand WinRM ne l'est pas encore.
    #>
    param([Parameter(Mandatory)][string[]]$ComputerNames)

    foreach ($name in $ComputerNames) {
        Invoke-Guarded -Description ("Activation immediate de WinRM sur {0} via WMI/DCOM" -f $name) -Action {
            $cimOption = New-CimSessionOption -Protocol Dcom
            $cim = New-CimSession -ComputerName $name -SessionOption $cimOption -ErrorAction Stop
            try {
                Invoke-CimMethod -CimSession $cim -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = "cmd.exe /c winrm.cmd quickconfig -quiet -force" } -ErrorAction Stop | Out-Null
                Start-Sleep -Seconds 5
                Invoke-CimMethod -CimSession $cim -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = 'netsh advfirewall firewall set rule group="Windows Remote Management" new enable=yes' } -ErrorAction Stop | Out-Null
                Start-Sleep -Seconds 3
            } finally {
                Remove-CimSession -CimSession $cim
            }

            if (-not (Test-WSMan -ComputerName $name -ErrorAction SilentlyContinue)) {
                throw "WinRM reste injoignable sur $name apres la tentative via WMI (la commande a ete lancee, mais son resultat n'a pas pu etre confirme dans le delai imparti - relancez un test de connectivite dans quelques instants)."
            }
        }
    }
}

function Invoke-SafeEnableWinRmOnDCs {
    Write-Host "`n--- Activer PowerShell Remoting (WinRM) sur les controleurs de domaine ---" -ForegroundColor Cyan
    Write-Host "Impact : AUCUN sur l'existant. Active uniquement la gestion a distance, necessaire pour" -ForegroundColor DarkGray
    Write-Host "         toutes les actions distantes de ce script (auditpol, audit NTLM, Spooler," -ForegroundColor DarkGray
    Write-Host "         signature LDAP, rotation KRBTGT, automatisation...)." -ForegroundColor DarkGray

    $dcs = Get-DomainControllersList
    if (-not $dcs) { return }

    $wr = Test-DCWinRmConnectivity -ComputerNames $dcs.HostName
    if ($wr.Unreachable.Count -eq 0) {
        Write-Log "WinRM est deja joignable sur tous les DC." -Level OK
        return
    }

    Write-Host ("DC actuellement INJOIGNABLES en WinRM : {0}" -f ($wr.Unreachable -join ', ')) -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Deux methodes disponibles (non exclusives) :" -ForegroundColor Yellow
    Write-Host "  [1] Via GPO (recommande) : fonctionne meme si WinRM est totalement a l'arret sur la" -ForegroundColor DarkGray
    Write-Host "      cible (pousse par SYSVOL/LDAP, pas par WinRM). Prise en compte DIFFEREE : prochain" -ForegroundColor DarkGray
    Write-Host "      rafraichissement de GPO + redemarrage du service WinRM (ou du serveur)." -ForegroundColor DarkGray
    Write-Host "  [2] Immediate via WMI/DCOM : active WinRM tout de suite sur les DC choisis, mais" -ForegroundColor DarkGray
    Write-Host "      necessite que WMI/DCOM (RPC) soit lui-meme joignable vers ces DC." -ForegroundColor DarkGray
    $method = Read-Host "Methode a utiliser [1=GPO / 2=Immediate WMI / 3=Les deux] (defaut 1)"
    if ([string]::IsNullOrWhiteSpace($method)) { $method = "1" }

    if ($method -eq "1" -or $method -eq "3") {
        Invoke-SafeEnableWinRmViaGPO
    }

    if ($method -eq "2" -or $method -eq "3") {
        if (-not (Confirm-Action ("Tenter l'activation IMMEDIATE de WinRM via WMI/DCOM sur : {0}" -f ($wr.Unreachable -join ', ')))) { return }
        Invoke-SafeEnableWinRmViaWmi -ComputerNames $wr.Unreachable

        Write-Host ""
        Write-Host "Nouvelle verification de connectivite WinRM..." -ForegroundColor DarkGray
        $recheck = Test-DCWinRmConnectivity -ComputerNames $wr.Unreachable
        if ($recheck.Unreachable.Count -eq 0) {
            Write-Log "WinRM est maintenant joignable sur tous les DC precedemment injoignables." -Level OK
        } else {
            Write-Log ("Toujours injoignables apres tentative WMI : {0}. WMI/DCOM peut lui aussi etre bloque par le pare-feu, ou le compte courant manque de droits locaux sur ces DC - verifiez manuellement." -f ($recheck.Unreachable -join ', ')) -Level WARN
        }
    }
}

# ============================================================
#  SECTION 2 - FONCTIONS A IMPACT POTENTIEL
#  (regroupees par theme dans le menu, cf. Show-*Menu en fin de fichier)
# ============================================================

function Invoke-RiskyResetKrbtgt {
    Write-Host "`n--- Reinitialisation du mot de passe KRBTGT ---" -ForegroundColor Red
    Write-Host "Rappel PingCastle : mot de passe krbtgt jamais change = risque Golden Ticket." -ForegroundColor DarkGray
    Write-Host "PROCEDURE OBLIGATOIRE : reinitialiser 2 FOIS, avec un ecart >= duree de vie max des tickets" -ForegroundColor Yellow
    Write-Host "Kerberos (souvent 10h) + delai de convergence de la replication AD entre tous les DC." -ForegroundColor Yellow
    Write-Host "Ne JAMAIS faire les 2 reset le meme jour sans validation du delai de replication." -ForegroundColor Yellow

    try {
        $krbtgt = Get-ADUser -Identity "krbtgt" -Properties PasswordLastSet -ErrorAction Stop
        Write-Host ("Dernier changement du mot de passe krbtgt : {0}" -f $krbtgt.PasswordLastSet)
    } catch {
        Write-Log "Impossible de lire le compte krbtgt : $($_.Exception.Message)" -Level ERROR
        return
    }

    if (-not (Confirm-Action "Reinitialiser le mot de passe KRBTGT MAINTENANT (1 des 2 executions requises)" -Strong)) { return }

    Invoke-Guarded -Description "Reset du mot de passe krbtgt" -Action {
        $newPwd = ConvertTo-SecureString (New-RandomComplexPassword -Length 64) -AsPlainText -Force
        Set-ADAccountPassword -Identity "krbtgt" -Reset -NewPassword $newPwd -Confirm:$false
        $trackFile = Join-Path $Script:LogDir "krbtgt_reset_tracking.log"
        Add-Content -Path $trackFile -Value ("{0} - Reset krbtgt effectue. Programmer le 2e reset au plus tot 10h a 24h plus tard, apres verification de la convergence AD (repadmin /replsummary)." -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
        Write-Log "Reset effectue. Planifiez le 2e reset (voir $trackFile) apres verification de la replication (repadmin /replsummary)." -Level WARN
    }

    Write-Host ""
    if ((Read-Host "Voulez-vous configurer maintenant la rotation KRBTGT automatique et planifiee (recommandation Microsoft/ANSSI) ? (O/N)") -match '^[oOyY]') {
        Invoke-RiskySetupKrbtgtScheduledRotation
    }
}

function Get-OrEnsureKdsRootKey {
    <#
        La rotation planifiee s'appuie sur un gMSA, qui necessite une KDS Root Key
        au niveau de la foret. Cette fonction verifie sa presence et propose de la
        creer si absente (aucune incidence sur l'existant : necessaire uniquement
        pour les futurs gMSA).
    #>
    $existing = Get-KdsRootKey -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Log "KDS Root Key deja presente (necessaire aux comptes de service gMSA)." -Level OK
        return $true
    }

    Write-Host ""
    Write-Host "Aucune KDS Root Key trouvee dans la foret. Elle est necessaire pour utiliser un gMSA." -ForegroundColor Yellow
    Write-Host "En production multi-DC : creez-la normalement et patientez ~10h (propagation naturelle)." -ForegroundColor DarkGray
    Write-Host "En environnement mono-DC / labo, il est courant de forcer sa disponibilite immediate." -ForegroundColor DarkGray
    $forceNow = Read-Host "Forcer la disponibilite immediate de la KDS Root Key (mono-DC/labo uniquement) ? (O/N)"

    if (-not (Confirm-Action "Creer la KDS Root Key de la foret" )) { return $false }

    Invoke-Guarded -Description "Creation de la KDS Root Key" -Action {
        if ($forceNow -match '^[oOyY]') {
            Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))
            Write-Log "KDS Root Key creee avec disponibilite immediate (EffectiveTime -10h)." -Level WARN
        } else {
            Add-KdsRootKey
            Write-Log "KDS Root Key creee. Le gMSA ne sera utilisable que dans environ 10h (propagation)." -Level WARN
        }
    }
    return $true
}

function Grant-KrbtgtResetPermission {
    <#
        Delegue UNIQUEMENT le droit 'Reset Password' sur l'objet krbtgt (et rien
        d'autre) au principal indique. Volontairement etroit (pas de droits
        Domain Admin) pour que la tache planifiee tourne avec le moindre privilege
        necessaire.
    #>
    param(
        [Parameter(Mandatory)][string]$PrincipalSam,
        [Parameter(Mandatory)][string]$TargetDC
    )

    $krbtgtDN = (Get-ADUser -Identity "krbtgt").DistinguishedName
    $domainNetbios = (Get-ADDomain).NetBIOSName

    Invoke-Guarded -Description ("Delegation du droit 'Reset Password' sur krbtgt a {0}" -f $PrincipalSam) -Action {
        Invoke-Command -ComputerName $TargetDC -ScriptBlock {
            param($dn, $account)
            & dsacls.exe "$dn" /G "${account}:CA;Reset Password" | Out-Null
        } -ArgumentList $krbtgtDN, "$domainNetbios\$PrincipalSam" -ErrorAction Stop
    }
}

function Get-KrbtgtRotationScriptContent {
    # Script autonome deploye sur le DC cible et execute par la tache planifiee.
    # Ne depend d'aucune variable/fonction du script menu (execution differee et decouplee).
    return @'
# Reset-KrbtgtScheduled.ps1
# Deploye et execute automatiquement par la tache planifiee "SEC - Rotation KRBTGT".
# Ne PAS executer manuellement sans avoir verifie l'etat de replication AD au prealable.

$logFile = "C:\ADHC-Scripts\Krbtgt-Rotation.log"

function Write-RotLog {
    param([string]$Message)
    $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Add-Content -Path $logFile -Value $line -Encoding UTF8
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("ADHC-KrbtgtRotation")) {
            New-EventLog -LogName Application -Source "ADHC-KrbtgtRotation" -ErrorAction SilentlyContinue
        }
        Write-EventLog -LogName Application -Source "ADHC-KrbtgtRotation" -EventId 1000 -EntryType Information -Message $Message -ErrorAction SilentlyContinue
    } catch { }
}

Import-Module ActiveDirectory -ErrorAction Stop
Write-RotLog "Debut de verification avant rotation KRBTGT planifiee."

# --- Garde-fou : la rotation est annulee si la replication AD n'est pas saine ---
$replOutput = & repadmin.exe /replsummary 2>&1 | Out-String
$unhealthy = $false

if ($replOutput -match '(?im)Source DSA') {
    foreach ($line in ($replOutput -split "`r?`n")) {
        if ($line -match '(\d+)\s*/\s*(\d+)') {
            $fails = [int]$Matches[1]
            if ($fails -gt 0) { $unhealthy = $true }
        }
    }
} else {
    # Sortie inattendue de repadmin -> etat incertain -> on annule par securite
    $unhealthy = $true
}

if ($unhealthy) {
    Write-RotLog "ECHEC/ETAT INCERTAIN DE LA REPLICATION AD DETECTE. Rotation KRBTGT ANNULEE par securite. Verifiez manuellement (repadmin /replsummary) puis relancez la tache si besoin."
    exit 1
}

Write-RotLog "Replication saine. Poursuite de la rotation planifiee du mot de passe KRBTGT."

# --- Generation d'un mot de passe aleatoire complexe (jamais stocke) ---
$chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+'
$bytes = New-Object byte[] 64
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$plain = -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
$newPwd = ConvertTo-SecureString $plain -AsPlainText -Force
Remove-Variable plain

try {
    Set-ADAccountPassword -Identity "krbtgt" -Reset -NewPassword $newPwd -Confirm:$false -ErrorAction Stop
    Write-RotLog "Rotation planifiee du mot de passe KRBTGT effectuee avec succes."
} catch {
    Write-RotLog ("ECHEC de la rotation planifiee KRBTGT : {0}" -f $_.Exception.Message)
    exit 1
}
'@
}

function Invoke-RiskySetupKrbtgtScheduledRotation {
    Write-Host "`n--- Configuration de la rotation KRBTGT automatique et planifiee ---" -ForegroundColor Red
    Write-Host "Principe (recommandation Microsoft/ANSSI) : un reset unique repete a intervalle regulier," -ForegroundColor DarkGray
    Write-Host "des lors que l'intervalle est largement superieur a la duree de vie max des tickets Kerberos" -ForegroundColor DarkGray
    Write-Host "+ le delai de convergence de la replication AD, offre en continu la meme protection que le" -ForegroundColor DarkGray
    Write-Host "'double reset' manuel. Recommandation usuelle : tous les 6 mois (180 jours) au minimum," -ForegroundColor DarkGray
    Write-Host "plus frequemment si le contexte de risque le justifie." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "Architecture mise en place : gMSA dedie avec UNIQUEMENT le droit 'Reset Password' sur le" -ForegroundColor DarkGray
    Write-Host "compte krbtgt (pas de compte Domain Admin, pas de mot de passe stocke dans la tache)." -ForegroundColor DarkGray

    $days = Read-Host "Intervalle de rotation en jours [defaut 180]"
    if ([string]::IsNullOrWhiteSpace($days) -or $days -notmatch '^\d+$') { $days = 180 }
    $days = [int]$days
    if ($days -lt 30) {
        Write-Host "Intervalle inferieur a 30 jours : risque de chevaucher la duree de vie des tickets/la" -ForegroundColor Yellow
        Write-Host "replication si celle-ci est degradee. Deconseille sauf contexte de compromission avere." -ForegroundColor Yellow
        if (-not (Read-Host "Confirmez-vous vouloir continuer avec cet intervalle court ? (O/N)") -match '^[oOyY]') { return }
    }

    $dcs = Get-DomainControllersList
    if (-not $dcs) { return }
    Write-Host "Controleurs de domaine disponibles :"
    for ($i = 0; $i -lt $dcs.Count; $i++) { Write-Host ("  [{0}] {1}" -f $i, $dcs[$i].HostName) }
    $pdc = (Get-ADDomain).PDCEmulator
    $defaultIdx = [array]::IndexOf($dcs.HostName, $pdc)
    if ($defaultIdx -lt 0) { $defaultIdx = 0 }
    $idxInput = Read-Host ("DC qui hebergera la tache planifiee [defaut {0} = {1}]" -f $defaultIdx, $dcs[$defaultIdx].HostName)
    $targetDC = if ($idxInput -match '^\d+$' -and [int]$idxInput -lt $dcs.Count) { $dcs[[int]$idxInput].HostName } else { $dcs[$defaultIdx].HostName }

    $gmsaName = Read-Host "Nom du gMSA dedie a creer [defaut svc-KrbtgtRotation]"
    if ([string]::IsNullOrWhiteSpace($gmsaName)) { $gmsaName = "svc-KrbtgtRotation" }

    if (-not (Confirm-Action ("Creer le gMSA '{0}', deleguer le reset du mot de passe krbtgt, deployer le script et creer la tache planifiee (tous les {1} jours) sur {2}" -f $gmsaName, $days, $targetDC) -Strong)) { return }

    if (-not (Get-OrEnsureKdsRootKey)) { return }

    $domain = Get-ADDomain
    $domainDNS = $domain.DNSRoot
    $domainNetbios = $domain.NetBIOSName

    Invoke-Guarded -Description ("Creation du gMSA {0}" -f $gmsaName) -Action {
        $existingGmsa = Get-ADServiceAccount -Filter "Name -eq '$gmsaName'" -ErrorAction SilentlyContinue
        if (-not $existingGmsa) {
            $dcComputer = Get-ADComputer -Identity $targetDC.Split('.')[0]
            New-ADServiceAccount -Name $gmsaName -DNSHostName "$gmsaName.$domainDNS" -PrincipalsAllowedToRetrieveManagedPassword $dcComputer.DistinguishedName -Enabled $true
        } else {
            Write-Log "Le gMSA existe deja, reutilisation." -Level INFO
        }
    }

    Invoke-Guarded -Description ("Installation/test du gMSA {0} sur {1}" -f $gmsaName, $targetDC) -Action {
        Invoke-Command -ComputerName $targetDC -ScriptBlock {
            param($name)
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            Install-ADServiceAccount -Identity $name -ErrorAction Stop
            if (-not (Test-ADServiceAccount -Identity $name)) {
                throw "Le test du gMSA a echoue (Test-ADServiceAccount)."
            }
        } -ArgumentList $gmsaName -ErrorAction Stop
    }

    Grant-KrbtgtResetPermission -PrincipalSam "$gmsaName$" -TargetDC $targetDC

    Invoke-Guarded -Description "Deploiement du script de rotation sur le DC cible" -Action {
        $scriptContent = Get-KrbtgtRotationScriptContent
        Invoke-Command -ComputerName $targetDC -ScriptBlock {
            param($content)
            $dir = "C:\ADHC-Scripts"
            if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
            Set-Content -Path (Join-Path $dir "Reset-KrbtgtScheduled.ps1") -Value $content -Encoding UTF8
        } -ArgumentList $scriptContent -ErrorAction Stop
    }

    Invoke-Guarded -Description ("Creation de la tache planifiee (tous les {0} jours) sur {1}" -f $days, $targetDC) -Action {
        Invoke-Command -ComputerName $targetDC -ScriptBlock {
            param($gmsaSam, $domainNetbios, $intervalDays)
            $taskName = "SEC - Rotation KRBTGT"
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\ADHC-Scripts\Reset-KrbtgtScheduled.ps1"'
            $trigger = New-ScheduledTaskTrigger -Daily -DaysInterval $intervalDays -At "02:00"
            $principal = New-ScheduledTaskPrincipal -UserId "$domainNetbios\$gmsaSam`$" -LogonType Password -RunLevel Highest
            $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd

            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Rotation automatique du mot de passe KRBTGT - deploye par le script de remediation AD"
        } -ArgumentList $gmsaName, $domainNetbios, $days -ErrorAction Stop
    }

    Write-Log ("Tache planifiee 'SEC - Rotation KRBTGT' creee sur {0}, execution tous les {1} jours a 02:00, sous le compte {2}\{3}$." -f $targetDC, $days, $domainNetbios, $gmsaName) -Level OK
    Write-Log "Journal local sur le DC : C:\ADHC-Scripts\Krbtgt-Rotation.log (+ journal d'evenements Application, source ADHC-KrbtgtRotation)." -Level INFO
    Write-Log "Chaque execution verifie l'etat de la replication AD (repadmin /replsummary) avant d'agir : en cas d'anomalie, la rotation est annulee automatiquement." -Level INFO
}

function Invoke-RiskyDisableNtlmV1 {
    Write-Host "`n--- Desactivation NTLMv1/LM (LmCompatibilityLevel = 5) via GPO ---" -ForegroundColor Red
    Write-Host "Risque : casse l'authentification de materiels/applications tres anciens (vieux NAS," -ForegroundColor DarkGray
    Write-Host "         imprimantes, appliances, applis proprietaires) qui ne savent parler qu'en NTLMv1/LM." -ForegroundColor DarkGray
    Write-Host "Recommandation : appliquer d'abord un niveau intermediaire (3) et surveiller les echecs," -ForegroundColor DarkGray
    Write-Host "         puis passer a 5 apres validation." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "Avant de continuer : avez-vous active l'audit NTLM (menu NTLM / LM > 1) et consulte le" -ForegroundColor Yellow
    Write-Host "rapport 'NTLMv1/LM detecte' (menu NTLM / LM > 2) pour identifier les comptes/postes concernes ?" -ForegroundColor Yellow
    if ((Read-Host "Continuer sans avoir verifie ce rapport est deconseille. Continuer quand meme ? (O/N)") -notmatch '^[oOyY]') { return }

    $level = Read-Host "Niveau LmCompatibilityLevel a appliquer (3=intermediaire recommande pour test, 5=NTLMv2 uniquement) [3/5]"
    if ($level -notin @("3","5")) { Write-Log "Valeur invalide, action annulee." -Level WARN; return }

    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Log "Le module GroupPolicy (RSAT-GPMC) n'est pas installe sur ce poste." -Level ERROR
        return
    }
    Import-Module GroupPolicy -ErrorAction SilentlyContinue

    $gpoName = "SEC - Durcissement NTLM (LmCompatibilityLevel=$level)"
    if (-not (Confirm-Action ("Creer/lier la GPO '{0}' au niveau du domaine" -f $gpoName) -Strong)) { return }

    Invoke-Guarded -Description ("GPO LmCompatibilityLevel=$level") -Action {
        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        if (-not $gpo) { $gpo = New-GPO -Name $gpoName }
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\System\CurrentControlSet\Control\Lsa" -ValueName "LmCompatibilityLevel" -Type DWord -Value ([int]$level)
        Write-Log "GPO creee mais NON liee automatiquement. Liez-la manuellement a un OU pilote avant deploiement large." -Level WARN
    }
}

function Invoke-Remediate6RestrictNtlmOutgoing {
    Write-Host "`n--- Restriction progressive de NTLM sortant (Deny avec exceptions) ---" -ForegroundColor Red
    Write-Host "Complementaire a la desactivation NTLMv1/LM : ce parametre bloque TOUTE authentification" -ForegroundColor DarkGray
    Write-Host "NTLM sortante (v1 ET v2) depuis les DC, sauf vers les serveurs explicitement exceptes." -ForegroundColor DarkGray
    Write-Host "Necessite l'audit NTLM actif depuis un moment (menu NTLM / LM > 1) pour batir la liste" -ForegroundColor DarkGray
    Write-Host "d'exceptions a partir des usages reellement observes." -ForegroundColor DarkGray

    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Log "Le module GroupPolicy (RSAT-GPMC) n'est pas installe sur ce poste." -Level ERROR
        return
    }
    Import-Module GroupPolicy -ErrorAction SilentlyContinue

    $exceptions = Read-Host "Serveurs exceptes (NTLM autorise vers eux), noms separes par une virgule (vide = aucune exception)"
    $exceptionList = @($exceptions -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })

    $gpoName = "SEC - Restriction NTLM sortant (Deny)"
    if (-not (Confirm-Action ("Creer/lier la GPO '{0}' sur l'OU Domain Controllers (NTLM sortant refuse, {1} exception(s))" -f $gpoName, $exceptionList.Count) -Strong)) { return }

    $ouDCs = "OU=Domain Controllers,$((Get-ADDomain).DistinguishedName)"
    Invoke-Guarded -Description ("Creation/MAJ de la GPO {0}" -f $gpoName) -Action {
        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        if (-not $gpo) { $gpo = New-GPO -Name $gpoName }
        $key = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
        # RestrictSendingNTLMTraffic = 2 -> "Deny All" (bloque tout NTLM sortant, sauf exceptions)
        Set-GPRegistryValue -Name $gpoName -Key $key -ValueName "RestrictSendingNTLMTraffic" -Type DWord -Value 2
        if ($exceptionList.Count -gt 0) {
            Set-GPRegistryValue -Name $gpoName -Key $key -ValueName "ClientAllowedNTLMServers" -Type MultiString -Value $exceptionList
        }
        try { New-GPLink -Name $gpoName -Target $ouDCs -ErrorAction Stop | Out-Null } catch { }
    }
    Write-Log "GPO liee sur l'OU Domain Controllers. Verifiez le journal NTLM Operational (audit) pendant plusieurs jours apres application pour detecter des blocages inattendus." -Level WARN
}

function Invoke-RiskyDisableDesForceAes {
    Write-Host "`n--- Desactivation DES / forcage AES sur les comptes concernes ---" -ForegroundColor Red
    Write-Host "Risque : casse l'authentification Kerberos de comptes de service/applications qui" -ForegroundColor DarkGray
    Write-Host "         dependent explicitement de DES ou qui ne supportent pas AES." -ForegroundColor DarkGray

    $desAccounts = @(Get-ADUser -Filter 'UseDESKeyOnly -eq $true' -Properties UseDESKeyOnly)
    $noAesAccounts = @(Get-ADUser -Filter '(msDS-SupportedEncryptionTypes -notlike "*")' -Properties msDS-SupportedEncryptionTypes, ServicePrincipalName |
                      Where-Object { $_.ServicePrincipalName })

    Write-Host ("Comptes avec DES force : {0}" -f $desAccounts.Count) -ForegroundColor Yellow
    $desAccounts | ForEach-Object { Write-Host ("  - {0}" -f $_.SamAccountName) }
    Write-Host ("Comptes de service sans type de chiffrement AES declare : {0}" -f $noAesAccounts.Count) -ForegroundColor Yellow
    $noAesAccounts | Select-Object -First 20 | ForEach-Object { Write-Host ("  - {0}" -f $_.SamAccountName) }
    if ($noAesAccounts.Count -gt 20) { Write-Host "  - ... (liste tronquee, voir le journal)" }

    if (-not (Confirm-Action "Desactiver DES sur les comptes listes et forcer AES128+AES256 sur les comptes de service" -Strong)) { return }

    foreach ($acc in $desAccounts) {
        Invoke-Guarded -Description ("Desactivation DES sur {0}" -f $acc.SamAccountName) -Action {
            Set-ADAccountControl -Identity $acc.DistinguishedName -UseDESKeyOnly $false
        }
    }
    foreach ($acc in $noAesAccounts) {
        Invoke-Guarded -Description ("Forcage AES128+AES256 sur {0}" -f $acc.SamAccountName) -Action {
            Set-ADUser -Identity $acc.DistinguishedName -Replace @{ "msDS-SupportedEncryptionTypes" = 24 }
        }
    }
}

function Invoke-Audit5AsRepRoasting {
    Write-Host "`n--- Audit AS-REP Roasting (comptes sans pre-authentification Kerberos) ---" -ForegroundColor Magenta
    Write-Host "Un compte avec 'Ne pas exiger de pre-authentification Kerberos' permet a un attaquant" -ForegroundColor DarkGray
    Write-Host "de recuperer un paquet AS-REP chiffre avec le hash du mot de passe et de l'attaquer hors ligne." -ForegroundColor DarkGray

    $accounts = @(Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' -Properties DoesNotRequirePreAuth, Enabled, PasswordLastSet)
    if ($accounts.Count -eq 0) { Write-Log "Aucun compte avec pre-authentification Kerberos desactivee." -Level OK; return }

    Write-Host ("{0} compte(s) sans pre-authentification Kerberos :" -f $accounts.Count) -ForegroundColor Red
    $accounts | ForEach-Object { Write-Host ("  - {0} (actif : {1})" -f $_.SamAccountName, $_.Enabled) }

    $path = Join-Path $Script:LogDir ("Rapport_AsRepRoasting_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    $accounts | Select-Object SamAccountName, Enabled, PasswordLastSet | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Write-Log ("Rapport exporte : {0}" -f $path) -Level OK
}

function Invoke-Remediate5FixAsRepRoasting {
    Write-Host "`n--- Corriger l'exposition AS-REP Roasting ---" -ForegroundColor Red
    Write-Host "Reactive la pre-authentification Kerberos sur les comptes selectionnes." -ForegroundColor DarkGray
    Write-Host "Risque : si ce parametre etait positionne intentionnellement pour un usage specifique" -ForegroundColor DarkGray
    Write-Host "         (rare), cet usage cessera de fonctionner." -ForegroundColor DarkGray

    $accounts = @(Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' -Properties DoesNotRequirePreAuth)
    if ($accounts.Count -eq 0) { Write-Log "Aucun compte concerne." -Level OK; return }

    $selected = @(Select-AccountsInteractive -Accounts $accounts -Prompt "Numeros des comptes a corriger, separes par une virgule ('tous' possible, vide = annuler)")
    if ($selected.Count -eq 0) { return }

    if (-not (Confirm-Action ("Reactiver la pre-authentification Kerberos sur {0} compte(s)" -f $selected.Count) -Strong)) { return }

    foreach ($acc in $selected) {
        Invoke-Guarded -Description ("Reactivation pre-authentification sur {0}" -f $acc.SamAccountName) -Action {
            Set-ADAccountControl -Identity $acc.DistinguishedName -DoesNotRequirePreAuth $false
        }
    }
}

function Invoke-Audit5TrustsEncryption {
    Write-Host "`n--- Audit des relations d'approbation (trusts) et de leur chiffrement ---" -ForegroundColor Magenta

    try {
        $trusts = @(Get-ADTrust -Filter * -Properties Direction, TrustType, ForestTransitive, SIDFilteringForestAware, SIDFilteringQuarantined, 'msDS-SupportedEncryptionTypes' -ErrorAction Stop)
    } catch {
        Write-Log ("Impossible de lire les relations d'approbation : {0}" -f $_.Exception.Message) -Level ERROR
        return
    }

    if ($trusts.Count -eq 0) { Write-Log "Aucune relation d'approbation configuree sur ce domaine." -Level OK; return }

    $rows = $trusts | ForEach-Object {
        [PSCustomObject]@{
            Domaine          = $_.Name
            Direction        = $_.Direction
            Type             = $_.TrustType
            TransitiveForet  = $_.ForestTransitive
            FiltrageSIDActif = ($_.SIDFilteringForestAware -or $_.SIDFilteringQuarantined)
            Chiffrement      = Get-SupportedEncryptionTypesLabel -Value $_.'msDS-SupportedEncryptionTypes'
        }
    }

    $rows | ForEach-Object {
        $color = if (-not $_.FiltrageSIDActif) { 'Yellow' } else { 'Green' }
        Write-Host ("  - {0} ({1}, {2}) : filtrage SID actif={3}, chiffrement={4}" -f $_.Domaine, $_.Direction, $_.Type, $_.FiltrageSIDActif, $_.Chiffrement) -ForegroundColor $color
    }

    $path = Join-Path $Script:LogDir ("Rapport_Trusts_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    $rows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Write-Log ("Rapport exporte : {0}. Un trust sans filtrage SID actif (hors relation intra-foret) est un vecteur d'elevation depuis le domaine approuve." -f $path) -Level OK
}

function Invoke-Remediate5EnableKerberosArmoring {
    Write-Host "`n--- Activer Kerberos Armoring (FAST) ---" -ForegroundColor Red
    Write-Host "Necessite un niveau fonctionnel de domaine/foret Windows Server 2012 minimum, et que" -ForegroundColor DarkGray
    Write-Host "TOUS les DC du domaine soient a jour (sinon des postes peuvent echouer a s'authentifier)." -ForegroundColor DarkGray
    Write-Host "Deploiement en 2 temps recommande : DC en mode 'Supported' d'abord, clients ensuite." -ForegroundColor DarkGray

    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Log "Le module GroupPolicy (RSAT-GPMC) n'est pas installe sur ce poste." -Level ERROR
        return
    }
    Import-Module GroupPolicy -ErrorAction SilentlyContinue

    try { $level = (Get-ADDomain).DomainMode } catch { $level = $null }
    if ($level -and $level -match '2000|2003|2008') {
        Write-Log ("Niveau fonctionnel de domaine actuel ({0}) probablement insuffisant pour Kerberos Armoring (2012 minimum recommande)." -f $level) -Level WARN
    }

    $ouDCs = "OU=Domain Controllers,$((Get-ADDomain).DistinguishedName)"
    $targetOUs = @(Select-OUsInteractive -Label "les clients Kerberos Armoring" -Verb "CIBLER (en plus des DC)")

    $gpoNameDc = "SEC - Kerberos Armoring (DC)"
    $gpoNameClient = "SEC - Kerberos Armoring (Clients)"
    if (-not (Confirm-Action ("Creer/lier '{0}' sur l'OU Domain Controllers, et '{1}' sur {2} UO client(s)" -f $gpoNameDc, $gpoNameClient, $targetOUs.Count) -Strong)) { return }

    Invoke-Guarded -Description ("Creation/MAJ de la GPO {0}" -f $gpoNameDc) -Action {
        $gpo = Get-GPO -Name $gpoNameDc -ErrorAction SilentlyContinue
        if (-not $gpo) { $gpo = New-GPO -Name $gpoNameDc }
        # 1 = Supported (le DC accepte le FAST sans l'exiger, etape recommandee avant "Required")
        Set-GPRegistryValue -Name $gpoNameDc -Key "HKLM\SYSTEM\CurrentControlSet\Services\Kdc" -ValueName "EnableCbacAndArmor" -Type DWord -Value 1
        try { New-GPLink -Name $gpoNameDc -Target $ouDCs -ErrorAction Stop | Out-Null } catch { }
    }

    if ($targetOUs.Count -gt 0) {
        Invoke-Guarded -Description ("Creation/MAJ de la GPO {0}" -f $gpoNameClient) -Action {
            $gpo = Get-GPO -Name $gpoNameClient -ErrorAction SilentlyContinue
            if (-not $gpo) { $gpo = New-GPO -Name $gpoNameClient }
            # 1 = Supported cote client egalement
            Set-GPRegistryValue -Name $gpoNameClient -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Kerberos\Parameters" -ValueName "EnableCbacAndArmor" -Type DWord -Value 1
            foreach ($ou in $targetOUs) {
                try { New-GPLink -Name $gpoNameClient -Target $ou -ErrorAction Stop | Out-Null } catch { }
            }
        }
    }
    Write-Log "Kerberos Armoring active en mode 'Supported'. Repassez en mode 'Required' uniquement apres validation que tous les clients concernes le supportent." -Level OK
}

function Invoke-RiskySetPrivilegedNotDelegated {
    Write-Host "`n--- Marquage des comptes a privileges 'Sensible, ne peut etre delegue' ---" -ForegroundColor Red
    Write-Host "Risque : casse les scenarios ou ces comptes sont utilises via une delegation Kerberos" -ForegroundColor DarkGray
    Write-Host "         (ex : compte de service qui delegue l'auth pour un autre systeme)." -ForegroundColor DarkGray

    $groups = @("Domain Admins","Enterprise Admins","Schema Admins","Administrators")
    $accounts = foreach ($g in $groups) {
        try { Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop | Where-Object { $_.objectClass -eq 'user' } } catch { }
    }
    $accounts = @($accounts | Sort-Object -Property SID -Unique | ForEach-Object { Get-ADUser -Identity $_.SID -Properties AccountNotDelegated })
    $toFix = @($accounts | Where-Object { -not $_.AccountNotDelegated })

    if ($toFix.Count -eq 0) { Write-Log "Tous les comptes a privileges sont deja marques non-delegables." -Level OK; return }

    Write-Host ("{0} compte(s) a privileges NON marques 'sensible' :" -f $toFix.Count) -ForegroundColor Yellow
    $toFix | ForEach-Object { Write-Host ("  - {0}" -f $_.SamAccountName) }

    if (-not (Confirm-Action "Appliquer le flag 'compte sensible - ne peut etre delegue' a ces comptes" -Strong)) { return }

    foreach ($acc in $toFix) {
        Invoke-Guarded -Description ("AccountNotDelegated sur {0}" -f $acc.SamAccountName) -Action {
            Set-ADAccountControl -Identity $acc.DistinguishedName -AccountNotDelegated $true
        }
    }
}

function Invoke-RiskyAddToProtectedUsers {
    Write-Host "`n--- Ajout des comptes a privileges dans le groupe 'Protected Users' ---" -ForegroundColor Red
    Write-Host "Risque : ces comptes ne pourront plus s'authentifier en NTLM/DES/RC4, n'auront plus de" -ForegroundColor DarkGray
    Write-Host "         delegation possible, et leur TGT sera limite a 4h. Peut casser des taches" -ForegroundColor DarkGray
    Write-Host "         planifiees, services ou applis legacy utilisant ces comptes." -ForegroundColor DarkGray

    $groups = @("Domain Admins","Enterprise Admins")
    $accounts = foreach ($g in $groups) {
        try { Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop | Where-Object { $_.objectClass -eq 'user' } } catch { }
    }
    $accounts = @($accounts | Sort-Object -Property SID -Unique)

    $puMembers = @((Get-ADGroupMember -Identity "Protected Users" -ErrorAction SilentlyContinue) | Select-Object -ExpandProperty SID)
    $toAdd = @($accounts | Where-Object { $puMembers -notcontains $_.SID })

    if ($toAdd.Count -eq 0) { Write-Log "Tous les comptes Domain/Enterprise Admins sont deja dans Protected Users." -Level OK; return }

    Write-Host ("{0} compte(s) a ajouter dans Protected Users :" -f $toAdd.Count) -ForegroundColor Yellow
    $toAdd | ForEach-Object { Write-Host ("  - {0}" -f $_.SamAccountName) }

    if (-not (Confirm-Action "Ajouter ces comptes au groupe Protected Users" -Strong)) { return }

    foreach ($acc in $toAdd) {
        Invoke-Guarded -Description ("Ajout de {0} a Protected Users" -f $acc.SamAccountName) -Action {
            Add-ADGroupMember -Identity "Protected Users" -Members $acc.SID
        }
    }
}

function Invoke-RiskyReportDelegations {
    Write-Host "`n--- Rapport des delegations Kerberos (non contraintes / contraintes / RBCD) ---" -ForegroundColor Red
    Write-Host "Ceci est un RAPPORT uniquement : la suppression d'une delegation doit etre validee" -ForegroundColor DarkGray
    Write-Host "au cas par cas (elle peut etre necessaire au fonctionnement d'une application)." -ForegroundColor DarkGray

    $unconstrained = @(Get-ADObject -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=524288)" -Properties SamAccountName, objectClass |
                      Where-Object { $_.SamAccountName -ne "krbtgt" })
    $constrained = @(Get-ADObject -LDAPFilter "(msDS-AllowedToDelegateTo=*)" -Properties SamAccountName, msDS-AllowedToDelegateTo)
    $rbcd = @(Get-ADObject -LDAPFilter "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" -Properties SamAccountName)

    Write-Host ("Delegation NON CONTRAINTE (a risque eleve) : {0}" -f $unconstrained.Count) -ForegroundColor Yellow
    $unconstrained | ForEach-Object { Write-Host ("  - {0} ({1})" -f $_.SamAccountName, $_.ObjectClass) }

    Write-Host ("Delegation CONTRAINTE : {0}" -f $constrained.Count) -ForegroundColor Yellow
    $constrained | ForEach-Object { Write-Host ("  - {0} -> {1}" -f $_.SamAccountName, ($_.'msDS-AllowedToDelegateTo' -join ', ')) }

    Write-Host ("Delegation RBCD (resource-based) : {0}" -f $rbcd.Count) -ForegroundColor Yellow
    $rbcd | ForEach-Object { Write-Host ("  - {0}" -f $_.SamAccountName) }

    $exportPath = Join-Path $Script:LogDir ("Delegations_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    @($unconstrained | Select-Object SamAccountName, @{N='Type';E={'NonContrainte'}}) +
    @($constrained | Select-Object SamAccountName, @{N='Type';E={'Contrainte'}}) +
    @($rbcd | Select-Object SamAccountName, @{N='Type';E={'RBCD'}}) |
        Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8

    Write-Log ("Rapport exporte : {0}" -f $exportPath) -Level OK
    Write-Host ""
    Write-Host "Pour retirer une delegation non contraintee sur un compte precis :" -ForegroundColor DarkGray
    Write-Host '  Set-ADAccountControl -Identity <DN> -TrustedForDelegation $false' -ForegroundColor DarkGray
}

function Invoke-RiskyCleanupSchemaAdmins {
    Write-Host "`n--- Nettoyage du groupe Schema Admins ---" -ForegroundColor Red
    Write-Host "Bonne pratique : ce groupe doit rester VIDE en permanence, et n'etre peuple que" -ForegroundColor DarkGray
    Write-Host "temporairement lors d'une modification de schema planifiee." -ForegroundColor DarkGray

    $members = @(Get-ADGroupMember -Identity "Schema Admins" -ErrorAction SilentlyContinue)
    if ($members.Count -eq 0) { Write-Log "Le groupe Schema Admins est deja vide." -Level OK; return }

    Write-Host ("{0} membre(s) actuel(s) de Schema Admins :" -f $members.Count) -ForegroundColor Yellow
    for ($i = 0; $i -lt $members.Count; $i++) { Write-Host ("  [{0}] {1}" -f $i, $members[$i].SamAccountName) }

    $sel = Read-Host "Numeros a retirer separes par une virgule (ou 'tous' / vide pour annuler)"
    if ([string]::IsNullOrWhiteSpace($sel)) { return }

    $targets = @(if ($sel -eq 'tous') { $members } else {
        $idx = @($sel -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ })
        $members[$idx]
    })

    if (-not (Confirm-Action ("Retirer {0} compte(s) de Schema Admins" -f $targets.Count) -Strong)) { return }

    foreach ($m in $targets) {
        Invoke-Guarded -Description ("Retrait de {0} de Schema Admins" -f $m.SamAccountName) -Action {
            Remove-ADGroupMember -Identity "Schema Admins" -Members $m.SID -Confirm:$false
        }
    }
}

function Invoke-RiskyDisableSpoolerOnDCs {
    Write-Host "`n--- Arret et desactivation du service Spooler sur les controleurs de domaine ---" -ForegroundColor Red
    Write-Host "Risque : si un DC est utilise (a tort) comme serveur d'impression partage, les postes" -ForegroundColor DarkGray
    Write-Host "         clients perdront l'acces a ces imprimantes." -ForegroundColor DarkGray

    $dcs = Get-DomainControllersList
    if (-not $dcs) { return }
    $wr = Test-DCWinRmConnectivity -ComputerNames $dcs.HostName
    $dcs = @($dcs | Where-Object { $wr.Reachable -contains $_.HostName })
    if (-not $dcs) { Write-Log "Aucun DC joignable via PowerShell Remoting (WinRM), action annulee." -Level ERROR; return }
    $dcs | ForEach-Object { Write-Host ("  - {0}" -f $_.HostName) }

    Write-Host ""
    Write-Host "Verification prealable : recherche d'imprimantes configurees sur chaque DC..." -ForegroundColor DarkGray

    # On verifie AVANT toute action si le DC sert (a tort) de serveur d'impression : si des
    # imprimantes y sont configurees/partagees, on l'affiche clairement et on exige une
    # confirmation dediee, distincte de la confirmation generale de l'action.
    $printerReport = @{}
    foreach ($dc in $dcs) {
        try {
            $printers = @(Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                Get-Printer -ErrorAction Stop | Select-Object Name, Shared, PortName
            } -ErrorAction Stop)
            $printerReport[$dc.HostName] = @{ Ok = $true; Printers = $printers }
            if ($printers.Count -gt 0) {
                Write-Host ("  {0} : {1} imprimante(s) trouvee(s)" -f $dc.HostName, $printers.Count) -ForegroundColor Yellow
            } else {
                Write-Host ("  {0} : aucune imprimante configuree" -f $dc.HostName) -ForegroundColor DarkGray
            }
        } catch {
            Write-Log ("Impossible de verifier les imprimantes sur {0} : {1}" -f $dc.HostName, $_.Exception.Message) -Level WARN
            $printerReport[$dc.HostName] = @{ Ok = $false; Printers = @() }
        }
    }

    if (-not (Confirm-Action "Arreter et desactiver le service Spooler sur les DC ci-dessus (verification imprimante par DC ci-apres)" -Strong)) { return }

    foreach ($dc in $dcs) {
        $info = $printerReport[$dc.HostName]

        if (-not $info.Ok) {
            Write-Host ""
            Write-Host ("Attention : impossible de verifier si {0} sert aussi de serveur d'impression." -f $dc.HostName) -ForegroundColor Yellow
            if ((Read-Host ("Continuer et arreter quand meme le Spooler sur {0}, sans certitude ? (O/N)" -f $dc.HostName)) -notmatch '^[oOyY]') {
                Write-Log ("Arret du Spooler ignore sur {0} (verification imprimante impossible, non confirme)." -f $dc.HostName) -Level WARN
                continue
            }
        } elseif ($info.Printers.Count -gt 0) {
            $shared = @($info.Printers | Where-Object { $_.Shared })
            Write-Host ""
            Write-Host "!!! IMPRIMANTE(S) DETECTEE(S) SUR CE CONTROLEUR DE DOMAINE !!!" -ForegroundColor Red
            Write-Host ("  Serveur : {0}" -f $dc.HostName) -ForegroundColor Red
            Write-Host ("  {0} imprimante(s) configuree(s), dont {1} partagee(s) sur le reseau :" -f $info.Printers.Count, $shared.Count) -ForegroundColor Yellow
            $info.Printers | ForEach-Object { Write-Host ("    - {0} (partagee : {1}, port : {2})" -f $_.Name, $_.Shared, $_.PortName) }
            Write-Host "  Ce serveur agit donc probablement AUSSI comme serveur d'impression." -ForegroundColor Yellow
            Write-Host "  Arreter le Spooler coupera l'acces a ces imprimantes pour tous les postes clients." -ForegroundColor Yellow
            $resp = Read-Host ("Etes-vous SUR de vouloir arreter le service Spooler sur {0} malgre tout ? Tapez ARRETER pour confirmer" -f $dc.HostName)
            if ($resp -cne "ARRETER") {
                Write-Log ("Arret du Spooler ANNULE sur {0} (imprimante(s) detectee(s), non confirme)." -f $dc.HostName) -Level WARN
                continue
            }
        }

        Invoke-Guarded -Description ("Arret Spooler sur {0}" -f $dc.HostName) -Action {
            Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                Stop-Service -Name Spooler -Force -ErrorAction Stop
                Set-Service -Name Spooler -StartupType Disabled
            } -ErrorAction Stop
        }
    }
}

function Invoke-Audit9TimeSyncStatus {
    Write-Host "`n--- Etat de la synchronisation horaire (NTP) sur les DC ---" -ForegroundColor Magenta
    Write-Host "Le PDC Emulator du domaine racine de la foret doit se synchroniser sur une source" -ForegroundColor DarkGray
    Write-Host "externe fiable ; les autres DC se synchronisent normalement sur la hierarchie du domaine." -ForegroundColor DarkGray

    $dcs = Get-DomainControllersList
    if (-not $dcs) { return }
    $wr = Test-DCWinRmConnectivity -ComputerNames $dcs.HostName
    $dcs = @($dcs | Where-Object { $wr.Reachable -contains $_.HostName })
    if (-not $dcs) { Write-Log "Aucun DC joignable via PowerShell Remoting (WinRM), action annulee." -Level ERROR; return }

    $pdc = (Get-ADDomain).PDCEmulator

    foreach ($dc in $dcs) {
        try {
            $source = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                (& w32tm.exe /query /source 2>&1 | Out-String).Trim()
            } -ErrorAction Stop
            $isPdc = $dc.HostName -eq $pdc
            $label = if ($isPdc) { " (PDC Emulator)" } else { "" }
            Write-Host ("  - {0}{1} : source = {2}" -f $dc.HostName, $label, $source) -ForegroundColor Yellow
            if ($isPdc -and $source -match 'Local CMOS Clock') {
                Write-Log ("Le PDC Emulator {0} se synchronise sur son horloge locale (aucune source externe) : a corriger en priorite." -f $dc.HostName) -Level WARN
            }
        } catch {
            Write-Log ("Impossible d'interroger w32tm sur {0} : {1}" -f $dc.HostName, $_.Exception.Message) -Level WARN
        }
    }
}

function Invoke-Remediate9ConfigurePdcTimeSource {
    Write-Host "`n--- Configurer la source NTP externe du PDC Emulator ---" -ForegroundColor Red
    Write-Host "S'applique uniquement au PDC Emulator (les autres DC se synchronisent sur la hierarchie" -ForegroundColor DarkGray
    Write-Host "du domaine par defaut, ce qui est correct et ne doit pas etre modifie)." -ForegroundColor DarkGray

    $pdc = (Get-ADDomain).PDCEmulator
    $ntpServers = Read-Host "Serveurs NTP externes (separes par une virgule) [defaut pool.ntp.org]"
    if ([string]::IsNullOrWhiteSpace($ntpServers)) { $ntpServers = "pool.ntp.org" }
    $peerList = ($ntpServers -split ',' | ForEach-Object { $_.Trim() }) -join ' '

    if (-not (Confirm-Action ("Configurer {0} (PDC Emulator) pour se synchroniser sur : {1}" -f $pdc, $peerList) -Strong)) { return }

    Invoke-Guarded -Description ("Configuration NTP sur {0}" -f $pdc) -Action {
        Invoke-Command -ComputerName $pdc -ScriptBlock {
            param($peers)
            & w32tm.exe /config /manualpeerlist:"$peers" /syncfromflags:manual /reliable:yes /update | Out-Null
            Restart-Service w32time -Force
        } -ArgumentList $peerList -ErrorAction Stop
    }
    Write-Log "Configuration appliquee. Verifiez apres quelques minutes avec 'w32tm /query /status' sur le PDC." -Level OK
}

function Invoke-Audit9InstalledRoles {
    Write-Host "`n--- Roles et fonctionnalites installes sur les DC ---" -ForegroundColor Magenta
    Write-Host "Lecture seule : signale les roles/fonctionnalites installes en plus du socle DC standard" -ForegroundColor DarkGray
    Write-Host "(AD DS, DNS, outils de gestion). A revoir au cas par cas - certains ajouts sont legitimes." -ForegroundColor DarkGray

    $dcs = Get-DomainControllersList
    if (-not $dcs) { return }
    $wr = Test-DCWinRmConnectivity -ComputerNames $dcs.HostName
    $dcs = @($dcs | Where-Object { $wr.Reachable -contains $_.HostName })
    if (-not $dcs) { Write-Log "Aucun DC joignable via PowerShell Remoting (WinRM), action annulee." -Level ERROR; return }

    $expected = @('AD-Domain-Services','DNS','RSAT-AD-Tools','RSAT-DNS-Server','GPMC','FS-FileServer')
    $rows = foreach ($dc in $dcs) {
        try {
            Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                param($expectedList)
                Get-WindowsFeature | Where-Object { $_.InstallState -eq 'Installed' -and $_.Name -notin $expectedList } |
                    Select-Object @{N='DC';E={$env:COMPUTERNAME}}, Name, DisplayName
            } -ArgumentList (,$expected) -ErrorAction Stop
        } catch {
            Write-Log ("Impossible de lire les roles installes sur {0} : {1}" -f $dc.HostName, $_.Exception.Message) -Level WARN
        }
    }

    $rows = @($rows)
    if ($rows.Count -eq 0) { Write-Log "Aucun role/fonctionnalite hors du socle DC standard detecte." -Level OK; return }

    $rows | ForEach-Object { Write-Host ("  - {0} : {1}" -f $_.DC, $_.DisplayName) -ForegroundColor Yellow }

    $path = Join-Path $Script:LogDir ("Rapport_RolesInstalles_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    $rows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Write-Log ("Rapport exporte : {0}. La liste des roles 'attendus' est indicative - ajustez-la selon votre contexte." -f $path) -Level OK
}

function Invoke-Remediate9EnableFirewallBaseline {
    Write-Host "`n--- Activer le pare-feu Windows (3 profils) sur les DC via GPO ---" -ForegroundColor Red
    Write-Host "Risque : si des flux legitimes ne sont pas couverts par les regles predefinies actives" -ForegroundColor DarkGray
    Write-Host "         (ou par vos regles personnalisees), ils seront bloques. Testez en OU pilote." -ForegroundColor DarkGray
    Write-Host "Rappel (restriction Internet) : la restriction d'acces Internet des DC releve normalement" -ForegroundColor DarkGray
    Write-Host "du pare-feu perimetrique/proxy (pas du pare-feu Windows local) - un blocage sortant local" -ForegroundColor DarkGray
    Write-Host "mal cible casse souvent Windows Update, la verification de revocation de certificats (CRL/" -ForegroundColor DarkGray
    Write-Host "OCSP) ou la synchronisation horaire externe ; non automatise ici pour cette raison." -ForegroundColor DarkGray

    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Log "Le module GroupPolicy (RSAT-GPMC) n'est pas installe sur ce poste." -Level ERROR
        return
    }
    Import-Module GroupPolicy -ErrorAction SilentlyContinue

    $gpoName = "SEC - Pare-feu Windows actif (DC)"
    if (-not (Confirm-Action ("Creer/lier la GPO '{0}' sur l'OU Domain Controllers (pare-feu actif, 3 profils)" -f $gpoName) -Strong)) { return }

    $ouDCs = "OU=Domain Controllers,$((Get-ADDomain).DistinguishedName)"
    Invoke-Guarded -Description ("Creation/MAJ de la GPO {0}" -f $gpoName) -Action {
        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        if (-not $gpo) { $gpo = New-GPO -Name $gpoName }
        foreach ($fwProfile in @('DomainProfile','PrivateProfile','PublicProfile')) {
            $key = "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\$fwProfile"
            Set-GPRegistryValue -Name $gpoName -Key $key -ValueName "EnableFirewall" -Type DWord -Value 1
            Set-GPRegistryValue -Name $gpoName -Key $key -ValueName "DefaultInboundAction" -Type DWord -Value 1
        }
        try { New-GPLink -Name $gpoName -Target $ouDCs -ErrorAction Stop | Out-Null } catch { }
    }
    Write-Log "GPO liee sur l'OU Domain Controllers. Verifiez que les regles predefinies necessaires (AD DS, DNS, DFSR, Netlogon...) sont actives avant un redemarrage des DC." -Level WARN
}

function Invoke-RiskyEnforceLdapSigning {
    Write-Host "`n--- Application de la signature LDAP / channel binding obligatoire sur les DC ---" -ForegroundColor Red
    Write-Host "Risque : casse les clients/appliances LDAP qui ne supportent pas la signature (NAS," -ForegroundColor DarkGray
    Write-Host "         appliances de supervision, vieux annuaires synchronises, etc.)." -ForegroundColor DarkGray
    Write-Host "Recommandation : activer d'abord en mode audit/log, verifier les journaux, puis forcer." -ForegroundColor DarkGray

    $dcs = Get-DomainControllersList
    if (-not $dcs) { return }
    $wr = Test-DCWinRmConnectivity -ComputerNames $dcs.HostName
    $dcs = @($dcs | Where-Object { $wr.Reachable -contains $_.HostName })
    if (-not $dcs) { Write-Log "Aucun DC joignable via PowerShell Remoting (WinRM), action annulee." -Level ERROR; return }

    if (-not (Confirm-Action "Forcer LDAPServerIntegrity=2 (Require signing) et LdapEnforceChannelBinding=2 sur tous les DC" -Strong)) { return }

    foreach ($dc in $dcs) {
        Invoke-Guarded -Description ("LDAP signing/channel binding sur {0}" -f $dc.HostName) -Action {
            Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 2 -Type DWord
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LdapEnforceChannelBinding" -Value 2 -Type DWord
            } -ErrorAction Stop
        }
    }
    Write-Log "Redemarrage du service NTDS (ou du DC) requis pour prise en compte complete." -Level WARN
}

function Invoke-RiskyDisableLLMNR {
    Write-Host "`n--- Desactivation de LLMNR via GPO (domaine entier) ---" -ForegroundColor Red
    Write-Host "Risque : casse la resolution de nom de secours (LLMNR) utilisee par certains" -ForegroundColor DarkGray
    Write-Host "         peripheriques/anciennes applications quand le DNS echoue. Impact large (tous postes)." -ForegroundColor DarkGray

    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Log "Le module GroupPolicy (RSAT-GPMC) n'est pas installe sur ce poste." -Level ERROR
        return
    }
    Import-Module GroupPolicy -ErrorAction SilentlyContinue

    $gpoName = "SEC - Desactivation LLMNR"
    if (-not (Confirm-Action ("Creer la GPO '{0}' (non liee automatiquement)" -f $gpoName) -Strong)) { return }

    Invoke-Guarded -Description "Creation GPO LLMNR" -Action {
        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        if (-not $gpo) { $gpo = New-GPO -Name $gpoName }
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" -ValueName "EnableMulticast" -Type DWord -Value 0
        Write-Log "GPO creee mais NON liee. Testez d'abord sur un OU pilote avant deploiement domaine entier." -Level WARN
    }
}

function Invoke-RiskyDisableInactiveAccounts {
    Write-Host "`n--- Desactivation des comptes utilisateurs/ordinateurs inactifs ---" -ForegroundColor Red
    Write-Host "Risque : un compte 'inactif' peut correspondre a un salarie en conge longue duree," -ForegroundColor DarkGray
    Write-Host "         un compte de service peu utilise, ou un poste eteint temporairement." -ForegroundColor DarkGray
    Write-Host "Les comptes sont DEPLACES vers une OU de quarantaine et DESACTIVES (pas supprimes)." -ForegroundColor DarkGray

    $thresholds = Read-InactivityThresholds -DefaultUserDays 180 -DefaultComputerDays 90
    $daysUsers = $thresholds.UserDays
    $daysComputers = $thresholds.ComputerDays

    $cutoffUsers = (Get-Date).AddDays(-$daysUsers)
    $cutoffComputers = (Get-Date).AddDays(-$daysComputers)

    $inactiveUsers = @(Get-ADUser -Filter { (Enabled -eq $true) -and (LastLogonTimestamp -lt $cutoffUsers) } -Properties LastLogonTimestamp)
    $inactiveComputers = @(Get-ADComputer -Filter { (Enabled -eq $true) -and (LastLogonTimestamp -lt $cutoffComputers) } -Properties LastLogonTimestamp)

    Write-Host ("Utilisateurs inactifs (> {0} j) : {1}" -f $daysUsers, $inactiveUsers.Count) -ForegroundColor Yellow
    Write-Host ("Ordinateurs inactifs (> {0} j)  : {1}" -f $daysComputers, $inactiveComputers.Count) -ForegroundColor Yellow

    $exportPath = Join-Path $Script:LogDir ("Comptes_Inactifs_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    @($inactiveUsers | Select-Object SamAccountName, @{N='Type';E={'User'}}, @{N='DerniereConnexion';E={[DateTime]::FromFileTime($_.LastLogonTimestamp)}}) +
    @($inactiveComputers | Select-Object SamAccountName, @{N='Type';E={'Computer'}}, @{N='DerniereConnexion';E={[DateTime]::FromFileTime($_.LastLogonTimestamp)}}) |
        Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8
    Write-Log ("Liste exportee pour revue avant action : {0}" -f $exportPath) -Level OK

    if (-not (Confirm-Action "Deplacer en quarantaine ET desactiver TOUS les comptes listes ci-dessus" -Strong)) { return }

    $domainDN = (Get-ADDomain).DistinguishedName
    $quarantineDN = "OU=$Script:QuarantineOUName,$domainDN"

    Invoke-Guarded -Description "Creation de l'OU de quarantaine (si absente)" -Action {
        if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$Script:QuarantineOUName'" -SearchBase $domainDN -ErrorAction SilentlyContinue)) {
            New-ADOrganizationalUnit -Name $Script:QuarantineOUName -Path $domainDN -ProtectedFromAccidentalDeletion $true
        }
    }

    foreach ($u in $inactiveUsers) {
        Invoke-Guarded -Description ("Quarantaine + desactivation utilisateur {0}" -f $u.SamAccountName) -Action {
            Disable-ADAccount -Identity $u.DistinguishedName
            Add-DisabledMarkerToDescription -Identity $u.DistinguishedName
            Move-ADObject -Identity $u.DistinguishedName -TargetPath $quarantineDN
        }
    }
    foreach ($c in $inactiveComputers) {
        Invoke-Guarded -Description ("Quarantaine + desactivation ordinateur {0}" -f $c.SamAccountName) -Action {
            Disable-ADAccount -Identity $c.DistinguishedName
            Add-DisabledMarkerToDescription -Identity $c.DistinguishedName
            Move-ADObject -Identity $c.DistinguishedName -TargetPath $quarantineDN
        }
    }
}

function Invoke-RiskyDisableByDate {
    Write-Host "`n--- Desactivation des postes/serveurs ET/OU utilisateurs a partir d'une DATE choisie ---" -ForegroundColor Red
    Write-Host "Comme pour la desactivation par anciennete (option 11), les comptes sont DEPLACES vers" -ForegroundColor DarkGray
    Write-Host ("une UO dediee ('{0}' pour les utilisateurs, '{1}' pour les postes/serveurs) ET DESACTIVES -" -f $Script:DisableUserOUName, $Script:DisableComputerOUName) -ForegroundColor DarkGray
    Write-Host "jamais supprimes." -ForegroundColor DarkGray
    Write-Host "Garde-fous TOUJOURS actifs, non desactivables : krbtgt, comptes Administrateur/Invite" -ForegroundColor DarkGray
    Write-Host "integres, controleurs de domaine, et le compte qui execute ce script." -ForegroundColor DarkGray

    $applyUsers = (Read-Host "Desactiver les UTILISATEURS inactifs depuis cette date ? (O/N)") -match '^[oOyY]'
    $applyComputers = (Read-Host "Desactiver les POSTES/SERVEURS inactifs depuis cette date ? (O/N)") -match '^[oOyY]'
    if (-not $applyUsers -and -not $applyComputers) { Write-Log "Aucun perimetre selectionne, action annulee." -Level WARN; return }

    $cutoffUsers = $null
    $cutoffComputers = $null
    if ($applyUsers) {
        $cutoffUsers = Read-DisableCutoffDate -Label "les UTILISATEURS"
        if (-not $cutoffUsers) { return }
    }
    if ($applyComputers) {
        $cutoffComputers = Read-DisableCutoffDate -Label "les POSTES/SERVEURS"
        if (-not $cutoffComputers) { return }
    }

    $excludedOUsUsers = @()
    $excludedOUsComputers = @()
    if ($applyUsers) { $excludedOUsUsers = @(Select-ExclusionOUs -Label "les UTILISATEURS") }
    if ($applyComputers) { $excludedOUsComputers = @(Select-ExclusionOUs -Label "les POSTES/SERVEURS") }
    $excludedGroups = @(Read-ExtraExclusionGroups)

    $protectedSids = Get-AlwaysProtectedPrincipalSids
    $protectedSids.UnionWith((Get-ExpandedGroupMemberSids -GroupNames $excludedGroups))
    $protectedComputerDNs = Get-ProtectedDCComputerDNs

    $domainDN = (Get-ADDomain).DistinguishedName
    $disableUserOUDN = "OU=$Script:DisableUserOUName,$domainDN"
    $disableComputerOUDN = "OU=$Script:DisableComputerOUName,$domainDN"

    $selectedUsers = @()
    $skippedUsers = @()
    if ($applyUsers) {
        $candidates = @(Get-ADUser -Filter { (Enabled -eq $true) -and (LastLogonTimestamp -lt $cutoffUsers) } -Properties LastLogonTimestamp, SID)
        foreach ($u in $candidates) {
            $reason = $null
            if ($protectedSids.Contains($u.SID.Value)) { $reason = "compte protege (systeme/groupe exclu)" }
            elseif ($excludedOUsUsers | Where-Object { $u.DistinguishedName -like "*,$_" }) { $reason = "UO exclue" }
            elseif ($u.DistinguishedName -like "*,$disableUserOUDN" -or $u.DistinguishedName -like "*,$disableComputerOUDN") { $reason = "deja en quarantaine" }

            if ($reason) { $skippedUsers += [PSCustomObject]@{ SamAccountName = $u.SamAccountName; Type = 'User'; Raison = $reason } }
            else { $selectedUsers += $u }
        }
    }

    $selectedComputers = @()
    $skippedComputers = @()
    if ($applyComputers) {
        $candidates = @(Get-ADComputer -Filter { (Enabled -eq $true) -and (LastLogonTimestamp -lt $cutoffComputers) } -Properties LastLogonTimestamp, SID)
        foreach ($c in $candidates) {
            $reason = $null
            if ($protectedSids.Contains($c.SID.Value)) { $reason = "compte protege (systeme/groupe exclu)" }
            elseif ($protectedComputerDNs.Contains($c.DistinguishedName)) { $reason = "controleur de domaine" }
            elseif ($excludedOUsComputers | Where-Object { $c.DistinguishedName -like "*,$_" }) { $reason = "UO exclue" }
            elseif ($c.DistinguishedName -like "*,$disableUserOUDN" -or $c.DistinguishedName -like "*,$disableComputerOUDN") { $reason = "deja en quarantaine" }

            if ($reason) { $skippedComputers += [PSCustomObject]@{ SamAccountName = $c.SamAccountName; Type = 'Computer'; Raison = $reason } }
            else { $selectedComputers += $c }
        }
    }

    Write-Host ""
    Write-Host ("Utilisateurs a desactiver+deplacer : {0} (dont {1} exclu(s) par garde-fou)" -f $selectedUsers.Count, $skippedUsers.Count) -ForegroundColor Yellow
    Write-Host ("Postes/Serveurs a desactiver+deplacer : {0} (dont {1} exclu(s) par garde-fou)" -f $selectedComputers.Count, $skippedComputers.Count) -ForegroundColor Yellow

    $exportPath = Join-Path $Script:LogDir ("Desactivation_ParDate_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    @($selectedUsers | Select-Object SamAccountName, @{N='Type';E={'User'}}, @{N='Action';E={'Desactive+deplace'}}) +
    @($selectedComputers | Select-Object SamAccountName, @{N='Type';E={'Computer'}}, @{N='Action';E={'Desactive+deplace'}}) +
    @($skippedUsers | Select-Object SamAccountName, Type, @{N='Action';E={"Exclu : $($_.Raison)"}}) +
    @($skippedComputers | Select-Object SamAccountName, Type, @{N='Action';E={"Exclu : $($_.Raison)"}}) |
        Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8
    Write-Log ("Liste (incluant les exclusions, pour audit) exportee : {0}" -f $exportPath) -Level OK

    if ($selectedUsers.Count -eq 0 -and $selectedComputers.Count -eq 0) { Write-Log "Aucun compte a traiter apres application des garde-fous." -Level OK; return }

    if (-not (Confirm-Action "Deplacer en quarantaine ET desactiver tous les comptes listes ci-dessus (hors exclusions)" -Strong)) { return }

    if ($selectedUsers.Count -gt 0) {
        Invoke-Guarded -Description ("Creation de l'UO '{0}' (si absente)" -f $Script:DisableUserOUName) -Action {
            if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$Script:DisableUserOUName'" -SearchBase $domainDN -ErrorAction SilentlyContinue)) {
                New-ADOrganizationalUnit -Name $Script:DisableUserOUName -Path $domainDN -ProtectedFromAccidentalDeletion $true
            }
        }
        foreach ($u in $selectedUsers) {
            Invoke-Guarded -Description ("Quarantaine + desactivation utilisateur {0}" -f $u.SamAccountName) -Action {
                Disable-ADAccount -Identity $u.DistinguishedName
                Add-DisabledMarkerToDescription -Identity $u.DistinguishedName
                Move-ADObject -Identity $u.DistinguishedName -TargetPath $disableUserOUDN
            }
        }
    }

    if ($selectedComputers.Count -gt 0) {
        Invoke-Guarded -Description ("Creation de l'UO '{0}' (si absente)" -f $Script:DisableComputerOUName) -Action {
            if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$Script:DisableComputerOUName'" -SearchBase $domainDN -ErrorAction SilentlyContinue)) {
                New-ADOrganizationalUnit -Name $Script:DisableComputerOUName -Path $domainDN -ProtectedFromAccidentalDeletion $true
            }
        }
        foreach ($c in $selectedComputers) {
            Invoke-Guarded -Description ("Quarantaine + desactivation poste/serveur {0}" -f $c.SamAccountName) -Action {
                Disable-ADAccount -Identity $c.DistinguishedName
                Add-DisabledMarkerToDescription -Identity $c.DistinguishedName
                Move-ADObject -Identity $c.DistinguishedName -TargetPath $disableComputerOUDN
            }
        }
    }

    Write-Host ""
    if ((Read-Host "Voulez-vous automatiser cette desactivation via une tache planifiee recurrente ? (O/N)") -match '^[oOyY]') {
        Invoke-AutomationSetupScheduledTask
    }
}

function Invoke-RiskyForcePasswordExpirationPrivileged {
    Write-Host "`n--- Forcer l'expiration des mots de passe sur les comptes a privileges ---" -ForegroundColor Red
    Write-Host "Risque : des comptes de service 'admin' avec mot de passe n'expirant jamais peuvent" -ForegroundColor DarkGray
    Write-Host "         cesser de fonctionner s'ils ne sont pas reconfigures avant expiration." -ForegroundColor DarkGray

    $groups = @("Domain Admins","Enterprise Admins","Administrators")
    $accounts = foreach ($g in $groups) {
        try { Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop | Where-Object { $_.objectClass -eq 'user' } } catch { }
    }
    $accounts = @($accounts | Sort-Object -Property SID -Unique | ForEach-Object { Get-ADUser -Identity $_.SID -Properties PasswordNeverExpires, PasswordLastSet })
    $toFix = @($accounts | Where-Object { $_.PasswordNeverExpires })

    if ($toFix.Count -eq 0) { Write-Log "Aucun compte a privileges avec mot de passe n'expirant jamais." -Level OK; return }

    Write-Host ("{0} compte(s) concerne(s) :" -f $toFix.Count) -ForegroundColor Yellow
    $toFix | ForEach-Object { Write-Host ("  - {0} (dernier changement : {1})" -f $_.SamAccountName, $_.PasswordLastSet) }

    if (-not (Confirm-Action "Activer l'expiration du mot de passe sur ces comptes (PasswordNeverExpires = false)" -Strong)) { return }

    foreach ($acc in $toFix) {
        Invoke-Guarded -Description ("Activation expiration mdp sur {0}" -f $acc.SamAccountName) -Action {
            Set-ADUser -Identity $acc.DistinguishedName -PasswordNeverExpires $false
        }
    }
    Write-Log "Prevenez les proprietaires de ces comptes AVANT expiration effective du mot de passe." -Level WARN
}

# ============================================================
#  SECTION - COMPTES A PRIVILEGES - COMPLEMENT (theme "Comptes a privileges")
#  Limitation du nombre de Domain Admins, usage du compte Administrateur integre,
#  comptes non nominatifs, risque Kerberoasting, restriction a des postes dedies (PAW).
# ============================================================

function Invoke-Audit3DomainAdminsCount {
    Write-Host "`n--- Nombre de membres Domain Admins / Enterprise Admins ---" -ForegroundColor Magenta
    Write-Host "Recommandation generale : limiter au strict necessaire (quelques comptes nominatifs)." -ForegroundColor DarkGray
    Write-Host "Aucun seuil universel n'existe - ajustez selon la taille de l'organisation." -ForegroundColor DarkGray

    $thresholdInput = Read-Host "Seuil d'alerte pour Domain Admins [defaut 5]"
    $threshold = if ($thresholdInput -match '^\d+$') { [int]$thresholdInput } else { 5 }

    $da = @(Get-ADGroupMember -Identity "Domain Admins" -Recursive -ErrorAction SilentlyContinue)
    $ea = @(Get-ADGroupMember -Identity "Enterprise Admins" -Recursive -ErrorAction SilentlyContinue)

    $colorDa = if ($da.Count -gt $threshold) { 'Red' } else { 'Green' }
    Write-Host ("Domain Admins : {0} membre(s) (seuil {1})" -f $da.Count, $threshold) -ForegroundColor $colorDa
    $da | ForEach-Object { Write-Host ("  - {0}" -f $_.SamAccountName) }
    Write-Host ("Enterprise Admins : {0} membre(s)" -f $ea.Count) -ForegroundColor Yellow
    $ea | ForEach-Object { Write-Host ("  - {0}" -f $_.SamAccountName) }

    if ($da.Count -gt $threshold) {
        Write-Log ("Domain Admins depasse le seuil ({0} > {1}) : revoyez si chaque membre a reellement besoin de ce privilege en permanence." -f $da.Count, $threshold) -Level WARN
    }

    $path = Join-Path $Script:LogDir ("Rapport_DomainAdmins_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    @($da | Select-Object SamAccountName, @{N='Groupe';E={'Domain Admins'}}) + @($ea | Select-Object SamAccountName, @{N='Groupe';E={'Enterprise Admins'}}) |
        Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Write-Log ("Rapport exporte : {0}" -f $path) -Level OK
}

function Invoke-Audit3BuiltinAdministratorStatus {
    Write-Host "`n--- Usage du compte Administrateur integre (RID 500) ---" -ForegroundColor Magenta
    Write-Host "Bonne pratique : ce compte ne doit pas etre utilise au quotidien (comptes nominatifs" -ForegroundColor DarkGray
    Write-Host "dedies a la place), et peut etre desactive s'il existe d'autres comptes Domain Admins actifs." -ForegroundColor DarkGray

    try {
        $domainSid = (Get-ADDomain).DomainSID.Value
        $builtinAdmin = Get-ADUser -Identity "$domainSid-500" -Properties Enabled, LastLogonDate, PasswordLastSet -ErrorAction Stop
    } catch {
        Write-Log ("Impossible de lire le compte Administrateur integre : {0}" -f $_.Exception.Message) -Level ERROR
        return
    }

    Write-Host ("Compte : {0}" -f $builtinAdmin.SamAccountName) -ForegroundColor Yellow
    Write-Host ("  Actif                  : {0}" -f $builtinAdmin.Enabled)
    Write-Host ("  Derniere connexion     : {0}" -f $builtinAdmin.LastLogonDate)
    Write-Host ("  Dernier changement mdp : {0}" -f $builtinAdmin.PasswordLastSet)

    if ($builtinAdmin.Enabled) {
        if ($builtinAdmin.LastLogonDate -and $builtinAdmin.LastLogonDate -gt (Get-Date).AddDays(-30)) {
            Write-Log "Le compte Administrateur integre est ACTIF et a ete utilise dans les 30 derniers jours : signe d'un usage au quotidien a corriger." -Level WARN
        } else {
            Write-Log "Le compte Administrateur integre est actif mais ne semble pas utilise recemment. Envisagez de le desactiver (voir remediation dediee)." -Level WARN
        }
    } else {
        Write-Log "Le compte Administrateur integre est deja desactive." -Level OK
    }
}

function Invoke-Remediate3DisableBuiltinAdministrator {
    Write-Host "`n--- Desactiver le compte Administrateur integre (RID 500) ---" -ForegroundColor Red
    Write-Host "Garde-fou : refuse de continuer si aucun AUTRE compte Domain Admins actif n'existe," -ForegroundColor DarkGray
    Write-Host "pour ne jamais se retrouver sans aucun moyen d'administration du domaine." -ForegroundColor DarkGray

    try {
        $domainSid = (Get-ADDomain).DomainSID.Value
        $builtinAdmin = Get-ADUser -Identity "$domainSid-500" -Properties Enabled -ErrorAction Stop
    } catch {
        Write-Log ("Impossible de lire le compte Administrateur integre : {0}" -f $_.Exception.Message) -Level ERROR
        return
    }

    if (-not $builtinAdmin.Enabled) { Write-Log "Le compte Administrateur integre est deja desactive." -Level OK; return }

    $otherActiveDA = @(Get-ADGroupMember -Identity "Domain Admins" -Recursive -ErrorAction SilentlyContinue |
        Where-Object { $_.SID.Value -ne $builtinAdmin.SID.Value } |
        ForEach-Object { Get-ADUser -Identity $_.SID -Properties Enabled -ErrorAction SilentlyContinue } |
        Where-Object { $_.Enabled })

    if ($otherActiveDA.Count -eq 0) {
        Write-Log "Aucun AUTRE compte Domain Admins actif trouve : desactivation du compte integre REFUSEE (risque de perte totale d'acces administratif)." -Level ERROR
        return
    }

    Write-Host ("{0} autre(s) compte(s) Domain Admins actif(s) confirme(s) :" -f $otherActiveDA.Count) -ForegroundColor Yellow
    $otherActiveDA | ForEach-Object { Write-Host ("  - {0}" -f $_.SamAccountName) }

    if (-not (Confirm-Action "Desactiver le compte Administrateur integre (RID 500)" -Strong)) { return }

    Invoke-Guarded -Description "Desactivation du compte Administrateur integre" -Action {
        Disable-ADAccount -Identity $builtinAdmin.DistinguishedName
    }
}

function Invoke-Audit3NonNominativeAccounts {
    Write-Host "`n--- Comptes a privileges potentiellement non nominatifs/partages ---" -ForegroundColor Magenta
    Write-Host "Heuristique : compte a privileges sans Prenom/Nom renseigne, ou dont le nom correspond" -ForegroundColor DarkGray
    Write-Host "a un motif generique (admin, administrateur, root, service...). A valider au cas par cas :" -ForegroundColor DarkGray
    Write-Host "un compte nominatif prefixe (ex : adm-jdupont) est une bonne pratique, pas une anomalie." -ForegroundColor DarkGray

    $groups = @("Domain Admins","Enterprise Admins","Schema Admins","Administrators")
    $accounts = foreach ($g in $groups) {
        try { Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop | Where-Object { $_.objectClass -eq 'user' } } catch { }
    }
    $accounts = @($accounts | Sort-Object -Property SID -Unique | ForEach-Object { Get-ADUser -Identity $_.SID -Properties GivenName, Surname, Description })

    $genericPatterns = @('admin','administrateur','administrator','root','service','support','helpdesk','test')
    $suspects = @($accounts | Where-Object {
        $acc = $_
        $noName = [string]::IsNullOrWhiteSpace($acc.GivenName) -and [string]::IsNullOrWhiteSpace($acc.Surname)
        $genericName = $false
        foreach ($p in $genericPatterns) { if ($acc.SamAccountName -like "*$p*") { $genericName = $true; break } }
        $noName -or $genericName
    })

    if ($suspects.Count -eq 0) { Write-Log "Aucun compte a privileges suspect (heuristique nom generique/sans Prenom-Nom)." -Level OK; return }

    Write-Host ("{0} compte(s) a valider :" -f $suspects.Count) -ForegroundColor Yellow
    $suspects | ForEach-Object { Write-Host ("  - {0} (Prenom/Nom : '{1} {2}')" -f $_.SamAccountName, $_.GivenName, $_.Surname) }

    $path = Join-Path $Script:LogDir ("Rapport_ComptesNonNominatifs_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    $suspects | Select-Object SamAccountName, GivenName, Surname, Description | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Write-Log ("Rapport exporte : {0}" -f $path) -Level OK
}

function Invoke-Audit3KerberoastingRisk {
    Write-Host "`n--- Risque Kerberoasting sur les comptes a privileges ---" -ForegroundColor Magenta
    Write-Host "Comptes membres d'un groupe a privileges ET porteurs d'un SPN : cible ideale pour du" -ForegroundColor DarkGray
    Write-Host "Kerberoasting (le TGS peut etre demande par n'importe quel compte authentifie puis" -ForegroundColor DarkGray
    Write-Host "attaque hors ligne si le chiffrement est faible)." -ForegroundColor DarkGray

    $privilegedSids = Get-ExpandedGroupMemberSids -GroupNames @("Domain Admins","Enterprise Admins","Schema Admins","Administrators","Account Operators","Backup Operators","Server Operators","Print Operators")
    $spnAccounts = @(Get-ADUser -LDAPFilter "(servicePrincipalName=*)" -Properties ServicePrincipalName, 'msDS-SupportedEncryptionTypes')
    $atRisk = @($spnAccounts | Where-Object { $privilegedSids.Contains($_.SID.Value) })

    if ($atRisk.Count -eq 0) { Write-Log "Aucun compte a privileges porteur d'un SPN detecte." -Level OK; return }

    Write-Host ("{0} compte(s) a privileges avec SPN (cible Kerberoasting) :" -f $atRisk.Count) -ForegroundColor Red
    $atRisk | ForEach-Object { Write-Host ("  - {0} (chiffrement : {1})" -f $_.SamAccountName, (Get-SupportedEncryptionTypesLabel -Value $_.'msDS-SupportedEncryptionTypes')) }

    $path = Join-Path $Script:LogDir ("Rapport_KerberoastingRisk_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    $atRisk | Select-Object SamAccountName, @{N='SPN';E={$_.ServicePrincipalName -join ' | '}}, @{N='Chiffrement';E={ Get-SupportedEncryptionTypesLabel -Value $_.'msDS-SupportedEncryptionTypes' }} |
        Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Write-Log ("Rapport exporte : {0}. Ces comptes devraient etre non-delegables et sans SPN si possible, ou migres en gMSA/Protected Users." -f $path) -Level OK
}

function Invoke-Remediate3RestrictPrivilegedLogonWorkstations {
    Write-Host "`n--- Restreindre les comptes a privileges a des postes d'administration dedies (PAW) ---" -ForegroundColor Red
    Write-Host "Positionne l'attribut 'Log on to' (LogonWorkstations) : le compte selectionne ne pourra" -ForegroundColor DarkGray
    Write-Host "plus ouvrir de session que sur les machines listees. Risque : verrouillage du compte hors" -ForegroundColor DarkGray
    Write-Host "de ces machines - gardez toujours un moyen d'acces de secours (autre compte, console DC)." -ForegroundColor DarkGray

    $groups = @("Domain Admins","Enterprise Admins")
    $accounts = foreach ($g in $groups) {
        try { Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop | Where-Object { $_.objectClass -eq 'user' } } catch { }
    }
    $accounts = @($accounts | Sort-Object -Property SID -Unique | ForEach-Object { Get-ADUser -Identity $_.SID -Properties LogonWorkstations })
    if ($accounts.Count -eq 0) { Write-Log "Aucun compte Domain/Enterprise Admins trouve." -Level OK; return }

    $selected = @(Select-AccountsInteractive -Accounts $accounts -Prompt "Numeros des comptes a restreindre, separes par une virgule (vide = annuler)")
    if ($selected.Count -eq 0) { return }

    $workstations = Read-Host "Noms NetBIOS des postes d'administration dedies autorises, separes par une virgule (ex : PAW01,PAW02)"
    if ([string]::IsNullOrWhiteSpace($workstations)) { Write-Log "Aucun poste fourni, action annulee." -Level WARN; return }
    $wsList = ($workstations -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join ','

    if (-not (Confirm-Action ("Restreindre {0} compte(s) aux postes : {1}" -f $selected.Count, $wsList) -Strong)) { return }

    foreach ($acc in $selected) {
        Invoke-Guarded -Description ("Restriction de connexion de {0} aux postes {1}" -f $acc.SamAccountName, $wsList) -Action {
            Set-ADUser -Identity $acc.DistinguishedName -LogonWorkstations $wsList
        }
    }
}

# ============================================================
#  SECTION - SMB, SYSVOL ET NETLOGON (theme "SMB, SYSVOL et NETLOGON" du menu)
#  Detection/desactivation SMBv1, signature SMB, durcissement des chemins UNC
#  SYSVOL/NETLOGON (Hardened UNC Paths, MS15-011).
# ============================================================

function Invoke-Audit7Smb1Usage {
    Write-Host "`n--- Detection de l'usage SMBv1 ---" -ForegroundColor Magenta
    Write-Host "Propose d'activer l'audit SMBv1 (journalisation uniquement, jamais de blocage) sur les" -ForegroundColor DarkGray
    Write-Host "DC joignables, puis lit le journal Microsoft-Windows-SMBServer/Audit pour lister les" -ForegroundColor DarkGray
    Write-Host "clients qui se sont connectes en SMBv1 depuis l'activation de l'audit." -ForegroundColor DarkGray

    $dcs = Get-DomainControllersList
    if (-not $dcs) { return }
    $wr = Test-DCWinRmConnectivity -ComputerNames $dcs.HostName
    $dcs = @($dcs | Where-Object { $wr.Reachable -contains $_.HostName })
    if (-not $dcs) { Write-Log "Aucun DC joignable via PowerShell Remoting (WinRM), action annulee." -Level ERROR; return }

    if ((Read-Host "Activer/verifier l'audit SMBv1 sur ces DC avant lecture du journal ? (O/N)") -match '^[oOyY]') {
        foreach ($dc in $dcs) {
            Invoke-Guarded -Description ("Activation de l'audit SMBv1 sur {0}" -f $dc.HostName) -Action {
                Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                    Set-SmbServerConfiguration -AuditSmb1Access $true -Confirm:$false
                } -ErrorAction Stop
            }
        }
    }

    $allRows = @()
    foreach ($dc in $dcs) {
        try {
            $rows = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                try {
                    Get-WinEvent -LogName "Microsoft-Windows-SMBServer/Audit" -ErrorAction Stop |
                        Where-Object { $_.Id -eq 3000 } |
                        ForEach-Object {
                            [PSCustomObject]@{
                                DC          = $env:COMPUTERNAME
                                TimeCreated = $_.TimeCreated
                                Message     = $_.Message
                            }
                        }
                } catch { @() }
            } -ErrorAction Stop
            $allRows += @($rows)
        } catch {
            Write-Log ("Impossible de lire le journal SMBServer/Audit sur {0} : {1}" -f $dc.HostName, $_.Exception.Message) -Level WARN
        }
    }

    $allRows = @($allRows)
    if ($allRows.Count -eq 0) {
        Write-Log "Aucune connexion SMBv1 detectee (ou audit non actif depuis assez longtemps)." -Level OK
        return
    }

    $path = Join-Path $Script:LogDir ("Rapport_SMB1_Usage_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    $allRows | Sort-Object TimeCreated -Descending | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Write-Host ("{0} connexion(s) SMBv1 detectee(s)." -f $allRows.Count) -ForegroundColor Yellow
    Write-Log ("Rapport exporte : {0}. Identifiez les postes/equipements concernes AVANT de desactiver SMBv1." -f $path) -Level OK
}

function Invoke-Audit7SmbSigningStatus {
    Write-Host "`n--- Etat de la signature SMB (client/serveur) sur les DC ---" -ForegroundColor Magenta

    $dcs = Get-DomainControllersList
    if (-not $dcs) { return }
    $wr = Test-DCWinRmConnectivity -ComputerNames $dcs.HostName
    $dcs = @($dcs | Where-Object { $wr.Reachable -contains $_.HostName })
    if (-not $dcs) { Write-Log "Aucun DC joignable via PowerShell Remoting (WinRM), action annulee." -Level ERROR; return }

    $rows = foreach ($dc in $dcs) {
        try {
            Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                $srv = Get-SmbServerConfiguration
                $cli = Get-SmbClientConfiguration
                [PSCustomObject]@{
                    DC                      = $env:COMPUTERNAME
                    ServeurSignatureRequise = $srv.RequireSecuritySignature
                    ServeurSignatureActivee = $srv.EnableSecuritySignature
                    ClientSignatureRequise  = $cli.RequireSecuritySignature
                    ClientSignatureActivee  = $cli.EnableSecuritySignature
                    SMB1Actif               = $srv.EnableSMB1Protocol
                }
            } -ErrorAction Stop
        } catch {
            Write-Log ("Impossible de lire la configuration SMB de {0} : {1}" -f $dc.HostName, $_.Exception.Message) -Level WARN
        }
    }

    $rows = @($rows)
    $rows | ForEach-Object { Write-Host ("  - {0} : signature serveur requise={1}, SMBv1 actif={2}" -f $_.DC, $_.ServeurSignatureRequise, $_.SMB1Actif) -ForegroundColor Yellow }

    $path = Join-Path $Script:LogDir ("Rapport_SMB_Signing_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    $rows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Write-Log ("Rapport exporte : {0}" -f $path) -Level OK
}

function Invoke-Remediate7DisableSmb1 {
    Write-Host "`n--- Desactivation de SMBv1 (client et serveur) sur les DC ---" -ForegroundColor Red
    Write-Host "Risque : casse l'acces des vieux NAS/scanners/imprimantes/applications qui ne parlent" -ForegroundColor DarkGray
    Write-Host "         QUE SMBv1. Consultez le rapport d'usage SMBv1 avant de continuer." -ForegroundColor DarkGray
    if ((Read-Host "Continuer sans avoir consulte le rapport d'usage SMBv1 est deconseille. Continuer ? (O/N)") -notmatch '^[oOyY]') { return }

    $dcs = Get-DomainControllersList
    if (-not $dcs) { return }
    $wr = Test-DCWinRmConnectivity -ComputerNames $dcs.HostName
    $dcs = @($dcs | Where-Object { $wr.Reachable -contains $_.HostName })
    if (-not $dcs) { Write-Log "Aucun DC joignable via PowerShell Remoting (WinRM), action annulee." -Level ERROR; return }

    if (-not (Confirm-Action "Desactiver SMBv1 (client + serveur) sur tous les DC listes" -Strong)) { return }

    foreach ($dc in $dcs) {
        Invoke-Guarded -Description ("Desactivation SMBv1 sur {0}" -f $dc.HostName) -Action {
            Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                Set-SmbServerConfiguration -EnableSMB1Protocol $false -Confirm:$false
                Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
            } -ErrorAction Stop
        }
    }
    Write-Log "SMBv1 desactive. Un redemarrage peut etre necessaire pour retirer completement la fonctionnalite optionnelle." -Level WARN
}

function Invoke-Remediate7EnforceSmbSigning {
    Write-Host "`n--- Forcer la signature SMB (client et serveur) via GPO ---" -ForegroundColor Red
    Write-Host "Risque : casse les clients/serveurs SMB tres anciens ne supportant pas la signature" -ForegroundColor DarkGray
    Write-Host "         (rare, mais possible sur des NAS/appliances obsoletes)." -ForegroundColor DarkGray

    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Log "Le module GroupPolicy (RSAT-GPMC) n'est pas installe sur ce poste." -Level ERROR
        return
    }
    Import-Module GroupPolicy -ErrorAction SilentlyContinue

    $gpoName = "SEC - Signature SMB obligatoire"
    if (-not (Confirm-Action ("Creer/lier la GPO '{0}' sur l'OU Domain Controllers (signature client+serveur obligatoire)" -f $gpoName) -Strong)) { return }

    $ouDCs = "OU=Domain Controllers,$((Get-ADDomain).DistinguishedName)"
    Invoke-Guarded -Description ("Creation/MAJ de la GPO {0}" -f $gpoName) -Action {
        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        if (-not $gpo) { $gpo = New-GPO -Name $gpoName }
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "RequireSecuritySignature" -Type DWord -Value 1
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "EnableSecuritySignature" -Type DWord -Value 1
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ValueName "RequireSecuritySignature" -Type DWord -Value 1
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ValueName "EnableSecuritySignature" -Type DWord -Value 1
        try { New-GPLink -Name $gpoName -Target $ouDCs -ErrorAction Stop | Out-Null } catch { }
    }
    Write-Log "GPO liee sur l'OU Domain Controllers uniquement. Etendez-la aux serveurs/postes apres validation sur un OU pilote." -Level WARN
}

function Invoke-Remediate7HardenedUncPaths {
    Write-Host "`n--- Durcissement des chemins UNC SYSVOL et NETLOGON (Hardened UNC Paths) ---" -ForegroundColor Red
    Write-Host "Exige l'integrite et l'authentification mutuelle sur les acces \\*\SYSVOL et \\*\NETLOGON." -ForegroundColor DarkGray
    Write-Host "Impact large (tous les postes/serveurs qui lisent SYSVOL/NETLOGON, donc tout le domaine)." -ForegroundColor DarkGray
    Write-Host "Risque residuel tres faible sur un parc a jour (recommandation Microsoft standard, MS15-011)." -ForegroundColor DarkGray

    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Log "Le module GroupPolicy (RSAT-GPMC) n'est pas installe sur ce poste." -Level ERROR
        return
    }
    Import-Module GroupPolicy -ErrorAction SilentlyContinue

    $gpoName = "SEC - Hardened UNC Paths (SYSVOL-NETLOGON)"
    if (-not (Confirm-Action ("Creer la GPO '{0}' (non liee automatiquement)" -f $gpoName) -Strong)) { return }

    Invoke-Guarded -Description ("Creation/MAJ de la GPO {0}" -f $gpoName) -Action {
        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        if (-not $gpo) { $gpo = New-GPO -Name $gpoName }
        $key = "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
        Set-GPRegistryValue -Name $gpoName -Key $key -ValueName '\\*\SYSVOL' -Type String -Value "RequireMutualAuthentication=1,RequireIntegrity=1"
        Set-GPRegistryValue -Name $gpoName -Key $key -ValueName '\\*\NETLOGON' -Type String -Value "RequireMutualAuthentication=1,RequireIntegrity=1"
        Write-Log "GPO creee mais NON liee. Testez d'abord sur un OU pilote avant deploiement domaine entier (postes ET serveurs)." -Level WARN
    }
}

function Invoke-Audit7SensitiveShares {
    Write-Host "`n--- Audit des partages SMB sur des postes/serveurs choisis ---" -ForegroundColor Magenta
    Write-Host "Signale les partages accordant un acces (hors partages administratifs $ par defaut) a" -ForegroundColor DarkGray
    Write-Host "'Tout le monde' ou 'Utilisateurs authentifies' en modification/controle total." -ForegroundColor DarkGray

    $targetOU = @(Select-OUsInteractive -Label "l'audit des partages SMB" -Verb "CIBLER")
    if ($targetOU.Count -eq 0) { Write-Log "Aucune UO ciblee, action annulee." -Level WARN; return }

    $computers = @(foreach ($ou in $targetOU) { Get-ADComputer -SearchBase $ou -Filter 'Enabled -eq $true' -Properties DNSHostName })
    if ($computers.Count -eq 0) { Write-Log "Aucun ordinateur actif trouve dans les UO ciblees." -Level WARN; return }
    $names = @($computers | ForEach-Object { if ($_.DNSHostName) { $_.DNSHostName } else { $_.Name } })
    $wr = Test-DCWinRmConnectivity -ComputerNames $names
    if ($wr.Reachable.Count -eq 0) { Write-Log "Aucune machine joignable via PowerShell Remoting (WinRM) parmi celles ciblees." -Level ERROR; return }

    $rows = foreach ($name in $wr.Reachable) {
        try {
            Invoke-Command -ComputerName $name -ScriptBlock {
                Get-SmbShare | Where-Object { -not $_.Special } | ForEach-Object {
                    $share = $_
                    Get-SmbShareAccess -Name $share.Name | Where-Object {
                        $_.AccountName -match 'Everyone|Tout le monde|Authenticated Users|Utilisateurs authentifies' -and
                        $_.AccessRight -in @('Full','Change')
                    } | ForEach-Object {
                        [PSCustomObject]@{
                            Machine   = $env:COMPUTERNAME
                            Partage   = $share.Name
                            Chemin    = $share.Path
                            Principal = $_.AccountName
                            Droit     = $_.AccessRight
                        }
                    }
                }
            } -ErrorAction Stop
        } catch {
            Write-Log ("Impossible de lire les partages de {0} : {1}" -f $name, $_.Exception.Message) -Level WARN
        }
    }

    $rows = @($rows)
    if ($rows.Count -eq 0) { Write-Log "Aucun partage a risque (Everyone/Authenticated Users en modification ou controle total) detecte." -Level OK; return }

    $rows | ForEach-Object { Write-Host ("  - {0}\{1} ({2}) : {3} -> {4}" -f $_.Machine, $_.Partage, $_.Chemin, $_.Principal, $_.Droit) -ForegroundColor Red }

    $path = Join-Path $Script:LogDir ("Rapport_PartagesSensibles_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    $rows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Write-Log ("Rapport exporte : {0}" -f $path) -Level OK
}

function Invoke-Remediate7DisableSmb1OnComputers {
    Write-Host "`n--- Desactivation de SMBv1 sur des postes/serveurs choisis ---" -ForegroundColor Red
    Write-Host "Complementaire a la desactivation SMBv1 sur les DC (menu SMB > 3) : cible ici des" -ForegroundColor DarkGray
    Write-Host "postes/serveurs membres. Consultez le rapport d'usage SMBv1 avant de continuer." -ForegroundColor DarkGray

    $targetOU = @(Select-OUsInteractive -Label "la desactivation SMBv1" -Verb "CIBLER")
    if ($targetOU.Count -eq 0) { return }

    $computers = @(foreach ($ou in $targetOU) { Get-ADComputer -SearchBase $ou -Filter 'Enabled -eq $true' -Properties DNSHostName })
    if ($computers.Count -eq 0) { Write-Log "Aucun ordinateur actif trouve dans les UO ciblees." -Level WARN; return }
    $names = @($computers | ForEach-Object { if ($_.DNSHostName) { $_.DNSHostName } else { $_.Name } })
    $wr = Test-DCWinRmConnectivity -ComputerNames $names
    if ($wr.Reachable.Count -eq 0) { Write-Log "Aucune machine joignable via PowerShell Remoting (WinRM) parmi celles ciblees." -Level ERROR; return }

    Write-Host ("Machines ciblees : {0}" -f ($wr.Reachable -join ', ')) -ForegroundColor Yellow
    if (-not (Confirm-Action ("Desactiver SMBv1 (client + serveur) sur {0} machine(s)" -f $wr.Reachable.Count) -Strong)) { return }

    foreach ($name in $wr.Reachable) {
        Invoke-Guarded -Description ("Desactivation SMBv1 sur {0}" -f $name) -Action {
            Invoke-Command -ComputerName $name -ScriptBlock {
                Set-SmbServerConfiguration -EnableSMB1Protocol $false -Confirm:$false
                Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
            } -ErrorAction Stop
        }
    }
    Write-Log "SMBv1 desactive sur les machines ciblees. Un redemarrage peut etre necessaire." -Level WARN
}

# ============================================================
#  SECTION - LDAP / LDAPS (theme "LDAP / LDAPS" du menu)
#  Signature/channel binding, diagnostics simple binds, certificats LDAPS,
#  durcissement TLS, restriction des connexions LDAP anonymes.
# ============================================================

function Invoke-Audit8LdapsCertificates {
    Write-Host "`n--- Audit des certificats LDAPS sur les DC ---" -ForegroundColor Magenta
    Write-Host "Verifie la presence d'un certificat de serveur valide (Authentification serveur," -ForegroundColor DarkGray
    Write-Host "correspondant au nom du DC) dans le magasin Ordinateur local de chaque DC, et teste" -ForegroundColor DarkGray
    Write-Host "la joignabilite du port LDAPS (TCP/636)." -ForegroundColor DarkGray

    $dcs = Get-DomainControllersList
    if (-not $dcs) { return }
    $wr = Test-DCWinRmConnectivity -ComputerNames $dcs.HostName
    $dcs = @($dcs | Where-Object { $wr.Reachable -contains $_.HostName })
    if (-not $dcs) { Write-Log "Aucun DC joignable via PowerShell Remoting (WinRM), action annulee." -Level ERROR; return }

    $rows = foreach ($dc in $dcs) {
        $port636 = $false
        try { $port636 = (Test-NetConnection -ComputerName $dc.HostName -Port 636 -WarningAction SilentlyContinue).TcpTestSucceeded } catch { }

        $certInfo = $null
        try {
            $certInfo = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                param($fqdn)
                $certs = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {
                    $_.EnhancedKeyUsageList.ObjectId -contains '1.3.6.1.5.5.7.3.1' -and
                    ($_.Subject -match [regex]::Escape($fqdn) -or $_.DnsNameList.Unicode -contains $fqdn)
                }
                if (-not $certs) { return $null }
                $best = $certs | Sort-Object NotAfter -Descending | Select-Object -First 1
                # Validation de la chaine de certification (jusqu'a une racine de confiance),
                # hors verification de revocation (peut echouer si le DC n'a pas d'acces Internet
                # vers la CRL/OCSP d'une CA publique - non pertinent pour une CA d'entreprise interne).
                $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
                $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
                $chaineValide = $chain.Build($best)
                [PSCustomObject]@{
                    Sujet         = $best.Subject
                    Expiration    = $best.NotAfter
                    ExpireBientot = ($best.NotAfter -lt (Get-Date).AddDays(60))
                    ChaineValide  = $chaineValide
                }
            } -ArgumentList $dc.HostName -ErrorAction Stop
        } catch { }

        [PSCustomObject]@{
            DC               = $dc.HostName
            Port636Joignable = $port636
            CertificatTrouve = [bool]$certInfo
            Sujet            = if ($certInfo) { $certInfo.Sujet } else { $null }
            Expiration       = if ($certInfo) { $certInfo.Expiration } else { $null }
            ExpireSous60j    = if ($certInfo) { $certInfo.ExpireBientot } else { $null }
            ChaineValide     = if ($certInfo) { $certInfo.ChaineValide } else { $null }
        }
    }

    $rows | ForEach-Object {
        $color = if (-not $_.CertificatTrouve -or -not $_.Port636Joignable -or $_.ChaineValide -eq $false) { 'Red' } elseif ($_.ExpireSous60j) { 'Yellow' } else { 'Green' }
        Write-Host ("  - {0} : LDAPS joignable={1}, certificat trouve={2}, chaine valide={3}, expiration={4}" -f $_.DC, $_.Port636Joignable, $_.CertificatTrouve, $_.ChaineValide, $_.Expiration) -ForegroundColor $color
    }

    $path = Join-Path $Script:LogDir ("Rapport_LDAPS_Certificats_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    $rows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Write-Log ("Rapport exporte : {0}" -f $path) -Level OK
}

function Invoke-Audit8LdapSimpleBinds {
    Write-Host "`n--- Audit des Simple Binds LDAP non signes ---" -ForegroundColor Magenta
    Write-Host "Active le diagnostic '16 LDAP Interface Events' (journalisation uniquement) puis lit" -ForegroundColor DarkGray
    Write-Host "l'evenement 2887 (resume du nombre de binds simples/non signes recus depuis le dernier" -ForegroundColor DarkGray
    Write-Host "redemarrage), genere par le DC environ une fois toutes les 24h." -ForegroundColor DarkGray

    $dcs = Get-DomainControllersList
    if (-not $dcs) { return }
    $wr = Test-DCWinRmConnectivity -ComputerNames $dcs.HostName
    $dcs = @($dcs | Where-Object { $wr.Reachable -contains $_.HostName })
    if (-not $dcs) { Write-Log "Aucun DC joignable via PowerShell Remoting (WinRM), action annulee." -Level ERROR; return }

    if ((Read-Host "Activer/verifier le diagnostic LDAP Interface Events sur ces DC avant lecture ? (O/N)") -match '^[oOyY]') {
        foreach ($dc in $dcs) {
            Invoke-Guarded -Description ("Activation du diagnostic LDAP Interface Events sur {0}" -f $dc.HostName) -Action {
                Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" -Name "16 LDAP Interface Events" -Value 2 -Type DWord
                } -ErrorAction Stop
            }
        }
        Write-Log "Diagnostic active. L'evenement 2887 se genere environ toutes les 24h : relancez cet audit demain pour un resultat exploitable." -Level WARN
    }

    $rows = foreach ($dc in $dcs) {
        try {
            Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                $evt = Get-WinEvent -FilterHashtable @{ LogName = 'Directory Service'; Id = 2887 } -MaxEvents 1 -ErrorAction Stop
                [PSCustomObject]@{
                    DC          = $env:COMPUTERNAME
                    TimeCreated = $evt.TimeCreated
                    Message     = $evt.Message
                }
            } -ErrorAction Stop
        } catch {
            Write-Log ("Aucun evenement 2887 trouve sur {0} (diagnostic pas encore actif depuis 24h, ou aucun bind non signe/simple detecte)." -f $dc.HostName) -Level INFO
        }
    }

    $rows = @($rows)
    if ($rows.Count -eq 0) { return }
    $path = Join-Path $Script:LogDir ("Rapport_LDAP_SimpleBinds_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    $rows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Write-Log ("Rapport exporte : {0}. Le detail chiffre est dans le texte du message de l'evenement 2887." -f $path) -Level OK
}

function Invoke-Remediate8DisableWeakTls {
    Write-Host "`n--- Desactivation TLS 1.0/1.1 et activation TLS 1.2+ sur les DC (SCHANNEL) ---" -ForegroundColor Red
    Write-Host "Risque : casse les clients LDAPS/RDP/applicatifs qui ne negocient qu'en TLS 1.0/1.1" -ForegroundColor DarkGray
    Write-Host "         (rare sur un parc a jour, frequent sur des appliances tres anciennes)." -ForegroundColor DarkGray

    $dcs = Get-DomainControllersList
    if (-not $dcs) { return }
    $wr = Test-DCWinRmConnectivity -ComputerNames $dcs.HostName
    $dcs = @($dcs | Where-Object { $wr.Reachable -contains $_.HostName })
    if (-not $dcs) { Write-Log "Aucun DC joignable via PowerShell Remoting (WinRM), action annulee." -Level ERROR; return }

    if (-not (Confirm-Action "Desactiver TLS 1.0 et TLS 1.1 (client+serveur) et activer TLS 1.2, sur tous les DC" -Strong)) { return }

    foreach ($dc in $dcs) {
        Invoke-Guarded -Description ("Durcissement SCHANNEL (TLS) sur {0}" -f $dc.HostName) -Action {
            Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                $base = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
                foreach ($proto in @('TLS 1.0','TLS 1.1')) {
                    foreach ($role in @('Client','Server')) {
                        $path = Join-Path $base "$proto\$role"
                        New-Item -Path $path -Force | Out-Null
                        Set-ItemProperty -Path $path -Name "Enabled" -Value 0 -Type DWord
                        Set-ItemProperty -Path $path -Name "DisabledByDefault" -Value 1 -Type DWord
                    }
                }
                foreach ($role in @('Client','Server')) {
                    $path = Join-Path $base "TLS 1.2\$role"
                    New-Item -Path $path -Force | Out-Null
                    Set-ItemProperty -Path $path -Name "Enabled" -Value 1 -Type DWord
                    Set-ItemProperty -Path $path -Name "DisabledByDefault" -Value 0 -Type DWord
                }
            } -ErrorAction Stop
        }
    }
    Write-Log "Redemarrage des DC requis pour prise en compte complete des parametres SCHANNEL." -Level WARN
}

function Invoke-Remediate8RestrictAnonymousLdap {
    Write-Host "`n--- Restriction des operations LDAP anonymes (dSHeuristics) ---" -ForegroundColor Red
    Write-Host "Modifie le 7e caractere de l'attribut dSHeuristics (KB326690) pour interdire les" -ForegroundColor DarkGray
    Write-Host "operations LDAP anonymes autres que le bind/la recherche sur le rootDSE." -ForegroundColor DarkGray
    Write-Host "Risque : casse les applications qui s'appuient sciemment sur un acces LDAP anonyme" -ForegroundColor DarkGray
    Write-Host "         (rare et deconseille, mais a verifier au prealable)." -ForegroundColor DarkGray

    try {
        $configNC = (Get-ADRootDSE).configurationNamingContext
        $dsHeuristicsDN = "CN=Directory Service,CN=Windows NT,CN=Services,$configNC"
        $current = (Get-ADObject -Identity $dsHeuristicsDN -Properties dSHeuristics).dSHeuristics
    } catch {
        Write-Log ("Impossible de lire dSHeuristics : {0}" -f $_.Exception.Message) -Level ERROR
        return
    }

    $currentDisplay = if ([string]::IsNullOrEmpty($current)) { "(vide - valeurs par defaut)" } else { $current }
    Write-Host ("Valeur actuelle de dSHeuristics : {0}" -f $currentDisplay) -ForegroundColor Yellow

    $chars = @()
    if ($current) { $chars = @($current.ToCharArray()) }
    while ($chars.Count -lt 7) { $chars += '0' }
    if ($chars[6] -eq '2') {
        Write-Log "Les operations LDAP anonymes sont deja restreintes (7e caractere = 2)." -Level OK
        return
    }
    $chars[6] = '2'
    $newValue = -join $chars

    if (-not (Confirm-Action ("Positionner dSHeuristics = '{0}' (restriction des operations LDAP anonymes)" -f $newValue) -Strong)) { return }

    Invoke-Guarded -Description "Mise a jour de dSHeuristics" -Action {
        Set-ADObject -Identity $dsHeuristicsDN -Replace @{ dSHeuristics = $newValue }
    }
    Write-Log "Propagation vers tous les DC de la foret par la replication AD standard." -Level INFO
}

# ============================================================
#  SECTION - COMPTES DE SERVICE (theme "Comptes de service" du menu)
#  Inventaire, reduction des privileges, rotation des secrets, migration vers
#  gMSA, interdiction de connexion interactive, chiffrement AES128/AES256.
# ============================================================

function Get-SupportedEncryptionTypesLabel {
    param([Nullable[int]]$Value)
    if (-not $Value) { return "Non defini (heritage des parametres par defaut du domaine)" }
    $labels = @()
    if ($Value -band 0x1)  { $labels += "DES-CBC-CRC" }
    if ($Value -band 0x2)  { $labels += "DES-CBC-MD5" }
    if ($Value -band 0x4)  { $labels += "RC4-HMAC" }
    if ($Value -band 0x8)  { $labels += "AES128" }
    if ($Value -band 0x10) { $labels += "AES256" }
    if ($labels.Count -eq 0) { return ("Valeur non standard ({0})" -f $Value) }
    return ($labels -join '+')
}

function Get-ServiceAccountCandidates {
    <#
        Identifie les comptes "candidats compte de service" : porteurs d'au moins
        un SPN (heuristique principale, independante de toute convention de
        nommage), completes par une/des OU choisies interactivement (comptes de
        service sans SPN, reperes par convention/emplacement). Reste une
        heuristique : a valider au cas par cas avant toute remediation. Ne
        retourne jamais de gMSA (objectClass different, non vus par Get-ADUser).
    #>
    $bySpn = @(Get-ADUser -LDAPFilter "(servicePrincipalName=*)" -Properties ServicePrincipalName, PasswordLastSet, PasswordNeverExpires, LastLogonDate, Enabled, Description, 'msDS-SupportedEncryptionTypes')
    Write-Host ("{0} compte(s) porteur(s) d'au moins un SPN (heuristique principale)." -f $bySpn.Count) -ForegroundColor DarkGray

    $extraOUs = @(Select-OUsInteractive -Label "des comptes de service SANS SPN (par convention/emplacement)" -Verb "AJOUTER (en plus des comptes avec SPN)")
    $byOU = @()
    foreach ($ou in $extraOUs) {
        $byOU += @(Get-ADUser -SearchBase $ou -Filter * -Properties ServicePrincipalName, PasswordLastSet, PasswordNeverExpires, LastLogonDate, Enabled, Description, 'msDS-SupportedEncryptionTypes')
    }

    return @($bySpn + $byOU | Sort-Object -Property SID -Unique)
}

function Invoke-Audit4ServiceAccountsInventory {
    Write-Host "`n--- Inventaire des comptes de service ---" -ForegroundColor Magenta
    Write-Host "Heuristique : comptes porteurs d'un SPN, completes par des OU choisies." -ForegroundColor DarkGray
    Write-Host "Pas de marqueur AD universel 'compte de service' : ce rapport reste une aide," -ForegroundColor DarkGray
    Write-Host "a valider au cas par cas (proprietaire, usage reel)." -ForegroundColor DarkGray

    $accounts = @(Get-ServiceAccountCandidates)
    if ($accounts.Count -eq 0) { Write-Log "Aucun compte de service candidat trouve." -Level OK; return }

    $privilegedSids = Get-ExpandedGroupMemberSids -GroupNames $Script:DefaultExcludedGroups

    $rows = $accounts | ForEach-Object {
        [PSCustomObject]@{
            SamAccountName         = $_.SamAccountName
            Enabled                = $_.Enabled
            LastLogonDate          = $_.LastLogonDate
            PasswordLastSet        = $_.PasswordLastSet
            PasswordNeverExpires   = $_.PasswordNeverExpires
            SPNCount               = @($_.ServicePrincipalName).Count
            SPN                    = ($_.ServicePrincipalName -join ' | ')
            ChiffrementSupporte    = Get-SupportedEncryptionTypesLabel -Value $_.'msDS-SupportedEncryptionTypes'
            MembreGroupePrivilegie = $privilegedSids.Contains($_.SID.Value)
            Description            = $_.Description
        }
    }

    $path = Join-Path $Script:LogDir ("Rapport_ComptesDeService_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    $rows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Write-Log ("Rapport exporte : {0} ({1} compte(s))" -f $path, $rows.Count) -Level OK

    $noOwner = @($rows | Where-Object { [string]::IsNullOrWhiteSpace($_.Description) })
    if ($noOwner.Count -gt 0) {
        Write-Log ("{0} compte(s) de service sans proprietaire documente dans la Description - a documenter." -f $noOwner.Count) -Level WARN
    }
    $inPriv = @($rows | Where-Object { $_.MembreGroupePrivilegie })
    if ($inPriv.Count -gt 0) {
        Write-Log ("{0} compte(s) de service membre(s) d'un groupe a privileges (voir remediation dediee)." -f $inPriv.Count) -Level WARN
    }
}

function Invoke-Audit4WeakEncryption {
    Write-Host "`n--- Comptes de service en chiffrement Kerberos faible (sans AES) ---" -ForegroundColor Magenta
    $accounts = @(Get-ServiceAccountCandidates)
    $weak = @($accounts | Where-Object {
        $val = $_.'msDS-SupportedEncryptionTypes'
        -not $val -or (-not ($val -band 0x8) -and -not ($val -band 0x10))
    })

    if ($weak.Count -eq 0) { Write-Log "Tous les comptes de service candidats supportent deja AES." -Level OK; return }

    Write-Host ("{0} compte(s) sans AES active (RC4/DES uniquement ou valeur non definie) :" -f $weak.Count) -ForegroundColor Yellow
    $weak | ForEach-Object { Write-Host ("  - {0} ({1})" -f $_.SamAccountName, (Get-SupportedEncryptionTypesLabel -Value $_.'msDS-SupportedEncryptionTypes')) }

    $path = Join-Path $Script:LogDir ("Rapport_ComptesDeService_ChiffrementFaible_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    $weak | Select-Object SamAccountName, @{N='Chiffrement';E={ Get-SupportedEncryptionTypesLabel -Value $_.'msDS-SupportedEncryptionTypes' }} |
        Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Write-Log ("Rapport exporte : {0}" -f $path) -Level OK
}

function Invoke-Remediate4EnableAesOnServiceAccounts {
    Write-Host "`n--- Forcer AES128+AES256 sur des comptes de service selectionnes ---" -ForegroundColor Red
    Write-Host "Risque : casse l'authentification Kerberos des applications qui ne supportent QUE" -ForegroundColor DarkGray
    Write-Host "         RC4/DES (rare mais existe sur des applis tres anciennes)." -ForegroundColor DarkGray

    $accounts = @(Get-ServiceAccountCandidates | Where-Object {
        $val = $_.'msDS-SupportedEncryptionTypes'
        -not $val -or (-not ($val -band 0x8) -and -not ($val -band 0x10))
    })
    if ($accounts.Count -eq 0) { Write-Log "Aucun compte de service sans AES a corriger." -Level OK; return }

    Write-Host "Comptes sans AES active :" -ForegroundColor Yellow
    $selected = @(Select-AccountsInteractive -Accounts $accounts -Prompt "Numeros a corriger, separes par une virgule ('tous' possible, vide = annuler)")
    if ($selected.Count -eq 0) { return }

    if (-not (Confirm-Action ("Forcer AES128+AES256 sur {0} compte(s) de service" -f $selected.Count) -Strong)) { return }

    foreach ($acc in $selected) {
        Invoke-Guarded -Description ("Forcage AES128+AES256 sur {0}" -f $acc.SamAccountName) -Action {
            Set-ADUser -Identity $acc.DistinguishedName -Replace @{ "msDS-SupportedEncryptionTypes" = 24 }
        }
    }
}

function Invoke-Remediate4DenyInteractiveLogon {
    Write-Host "`n--- Interdire la connexion interactive / RDP des comptes de service ---" -ForegroundColor Red
    Write-Host "Risque : si un compte selectionne sert aussi a une maintenance manuelle occasionnelle" -ForegroundColor DarkGray
    Write-Host "         en session interactive, cet acces sera coupe." -ForegroundColor DarkGray

    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Log "Le module GroupPolicy (RSAT-GPMC) n'est pas installe sur ce poste." -Level ERROR
        return
    }
    Import-Module GroupPolicy -ErrorAction SilentlyContinue

    $accounts = @(Get-ServiceAccountCandidates)
    if ($accounts.Count -eq 0) { return }
    $selected = @(Select-AccountsInteractive -Accounts $accounts -Prompt "Numeros des comptes a restreindre, separes par une virgule ('tous' possible, vide = annuler)")
    if ($selected.Count -eq 0) { return }

    $groupName = Read-Host "Nom du groupe AD dedie a creer/completer [defaut GG-ComptesDeService-NoInteractif]"
    if ([string]::IsNullOrWhiteSpace($groupName)) { $groupName = "GG-ComptesDeService-NoInteractif" }
    $targetOU = @(Select-OUsInteractive -Label "la GPO d'interdiction de connexion interactive/RDP" -Verb "CIBLER (lien de la GPO)")
    if ($targetOU.Count -eq 0) { Write-Log "Aucune UO ciblee, action annulee (la GPO ne serait liee nulle part)." -Level WARN; return }

    if (-not (Confirm-Action ("Creer/completer le groupe '{0}' avec {1} compte(s), et creer/lier une GPO dediee sur {2} UO" -f $groupName, $selected.Count, $targetOU.Count) -Strong)) { return }

    Invoke-Guarded -Description ("Creation/verification du groupe {0}" -f $groupName) -Action {
        if (-not (Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue)) {
            New-ADGroup -Name $groupName -GroupScope Global -GroupCategory Security -Description "Comptes de service - connexion interactive/RDP interdite (ADHC)"
        }
        Add-ADGroupMember -Identity $groupName -Members ($selected | Select-Object -ExpandProperty SID) -ErrorAction SilentlyContinue
    }

    $gpoName = "SEC - Comptes de service - Interdiction logon interactif"
    Invoke-Guarded -Description ("Creation/lien de la GPO '{0}'" -f $gpoName) -Action {
        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        if (-not $gpo) { $gpo = New-GPO -Name $gpoName }
        foreach ($ou in $targetOU) {
            try { New-GPLink -Name $gpoName -Target $ou -ErrorAction Stop | Out-Null } catch { }
        }
    }

    Write-Log ("GPO '{0}' creee et liee, groupe '{1}' peuple. ETAPE MANUELLE OBLIGATOIRE : le module GroupPolicy ne permet pas de modifier l'Attribution des droits utilisateur - editez cette GPO dans la console GPMC (Configuration ordinateur > Parametres Windows > Parametres de securite > Strategies locales > Attribution des droits utilisateur) et ajoutez le groupe '{1}' a 'Refuser l'ouverture de session locale' ET 'Refuser l'ouverture de session par les services Bureau a distance'." -f $gpoName, $groupName) -Level WARN
}

function Invoke-Remediate4RemoveFromPrivilegedGroups {
    Write-Host "`n--- Retirer les comptes de service des groupes a privileges ---" -ForegroundColor Red
    Write-Host "Risque : si le compte de service a reellement besoin de ce privilege pour fonctionner," -ForegroundColor DarkGray
    Write-Host "         le retirer cassera l'application concernee. A valider avec le proprietaire applicatif." -ForegroundColor DarkGray

    $accounts = @(Get-ServiceAccountCandidates)
    if ($accounts.Count -eq 0) { return }
    $groups = @("Domain Admins","Enterprise Admins","Schema Admins","Administrators","Account Operators","Backup Operators","Server Operators","Print Operators")
    $hits = @()
    foreach ($g in $groups) {
        try {
            $members = @(Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop | Select-Object -ExpandProperty SID)
            foreach ($acc in $accounts) {
                if ($members -contains $acc.SID) { $hits += [PSCustomObject]@{ Account = $acc; Group = $g } }
            }
        } catch { }
    }

    if ($hits.Count -eq 0) { Write-Log "Aucun compte de service detecte dans un groupe a privileges." -Level OK; return }

    Write-Host ("{0} appartenance(s) compte de service / groupe a privileges detectee(s) :" -f $hits.Count) -ForegroundColor Yellow
    for ($i = 0; $i -lt $hits.Count; $i++) { Write-Host ("  [{0}] {1} -> {2}" -f $i, $hits[$i].Account.SamAccountName, $hits[$i].Group) }

    $sel = Read-Host "Numeros a retirer, separes par une virgule ('tous' possible, vide = annuler)"
    if ([string]::IsNullOrWhiteSpace($sel)) { return }
    $targets = @(if ($sel.Trim() -eq 'tous') { $hits } else {
        $idx = @($sel -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ } | Where-Object { $_ -lt $hits.Count })
        $hits[$idx]
    })
    if ($targets.Count -eq 0) { return }

    if (-not (Confirm-Action ("Retirer {0} appartenance(s) a un groupe a privileges" -f $targets.Count) -Strong)) { return }

    foreach ($t in $targets) {
        Invoke-Guarded -Description ("Retrait de {0} du groupe {1}" -f $t.Account.SamAccountName, $t.Group) -Action {
            Remove-ADGroupMember -Identity $t.Group -Members $t.Account.SID -Confirm:$false
        }
    }
}

function Invoke-Remediate4RotatePassword {
    Write-Host "`n--- Reinitialiser le mot de passe de comptes de service selectionnes ---" -ForegroundColor Red
    Write-Host "ATTENTION : l'application/le service utilisant ce compte doit etre reconfigure(e) avec" -ForegroundColor Yellow
    Write-Host "le nouveau mot de passe AVANT expiration de la session en cours, sous peine d'interruption." -ForegroundColor Yellow
    Write-Host "Les gMSA (mot de passe gere automatiquement) ne sont jamais retournes par cet inventaire." -ForegroundColor DarkGray

    $accounts = @(Get-ServiceAccountCandidates)
    if ($accounts.Count -eq 0) { return }
    $selected = @(Select-AccountsInteractive -Accounts $accounts -Prompt "Numeros des comptes a reinitialiser, separes par une virgule (vide = annuler ; 'tous' deconseille sur ce type d'action)")
    if ($selected.Count -eq 0) { return }

    if (-not (Confirm-Action ("Reinitialiser le mot de passe de {0} compte(s) de service (mettez a jour l'application AVANT de continuer)" -f $selected.Count) -Strong)) { return }

    foreach ($acc in $selected) {
        Invoke-Guarded -Description ("Reinitialisation du mot de passe de {0}" -f $acc.SamAccountName) -Action {
            $newPwd = ConvertTo-SecureString (New-RandomComplexPassword -Length 32) -AsPlainText -Force
            Set-ADAccountPassword -Identity $acc.DistinguishedName -Reset -NewPassword $newPwd -Confirm:$false
        }
    }
    Write-Log "Mots de passe reinitialises (jamais affiches/journalises en clair)." -Level WARN
}

function Invoke-Remediate4CreateGmsa {
    Write-Host "`n--- Assistant de creation d'un compte de service gere (gMSA) ---" -ForegroundColor Red
    Write-Host "Cree un NOUVEAU gMSA : ne migre pas automatiquement un compte de service existant." -ForegroundColor DarkGray
    Write-Host "Pour remplacer un compte existant, reconfigurez ensuite l'application pour utiliser ce" -ForegroundColor DarkGray
    Write-Host "nouveau compte (le gMSA gere lui-meme la rotation de son mot de passe, sans intervention)." -ForegroundColor DarkGray

    $gmsaName = Read-Host "Nom du gMSA a creer (max 15 caracteres, sans espace)"
    if ([string]::IsNullOrWhiteSpace($gmsaName) -or $gmsaName.Length -gt 15 -or $gmsaName -match '\s') {
        Write-Log "Nom invalide (vide, plus de 15 caracteres, ou contient un espace)." -Level ERROR
        return
    }
    if (Get-ADServiceAccount -Filter "Name -eq '$gmsaName'" -ErrorAction SilentlyContinue) {
        Write-Log ("Un gMSA nomme '{0}' existe deja." -f $gmsaName) -Level ERROR
        return
    }

    $hostGroupName = Read-Host "Groupe AD des serveurs/postes autorises a recuperer le mot de passe du gMSA"
    $hostGroup = Get-ADGroup -Filter "Name -eq '$hostGroupName'" -ErrorAction SilentlyContinue
    if (-not $hostGroup) {
        Write-Log ("Groupe '{0}' introuvable. Creez-le au prealable (avec les serveurs/postes hebergeant le service) et relancez." -f $hostGroupName) -Level ERROR
        return
    }

    if (-not (Confirm-Action ("Creer le gMSA '{0}', accessible aux membres du groupe '{1}'" -f $gmsaName, $hostGroupName) -Strong)) { return }

    if (-not (Get-OrEnsureKdsRootKey)) { return }

    $domainDNS = (Get-ADDomain).DNSRoot
    Invoke-Guarded -Description ("Creation du gMSA {0}" -f $gmsaName) -Action {
        New-ADServiceAccount -Name $gmsaName -DNSHostName "$gmsaName.$domainDNS" -PrincipalsAllowedToRetrieveManagedPassword $hostGroup.DistinguishedName -Enabled $true
    }

    Write-Log ("gMSA '{0}$' cree. Sur chaque serveur/poste membre de '{1}' : Install-ADServiceAccount -Identity {0} puis Test-ADServiceAccount -Identity {0}." -f $gmsaName, $hostGroupName) -Level OK
    Write-Log "Configurez ensuite le service/l'application pour s'executer sous ce compte (pas de mot de passe a saisir, gere automatiquement par AD)." -Level INFO
}

# ============================================================
#  SECTION - WINDOWS LAPS (theme "Windows LAPS" du menu)
#  Necessite le module PowerShell "LAPS" (Windows LAPS moderne, integre depuis
#  Windows 11 22H2 / Windows Server 2022 a jour). Cible les attributs msLAPS-*,
#  pas l'ancien LAPS legacy (ms-Mcs-AdmPwd).
# ============================================================

function Test-LapsModuleAvailable {
    if (-not (Get-Module -ListAvailable -Name LAPS)) {
        Write-Log "Le module PowerShell 'LAPS' (Windows LAPS) n'est pas installe sur ce poste. Installez la fonctionnalite RSAT correspondante (ou executez depuis un DC/poste a jour)." -Level ERROR
        return $false
    }
    Import-Module LAPS -ErrorAction SilentlyContinue
    return $true
}

function Test-LapsSchemaPresent {
    try {
        $schemaNC = (Get-ADRootDSE).schemaNamingContext
        $attr = Get-ADObject -SearchBase $schemaNC -LDAPFilter "(lDAPDisplayName=msLAPS-Password)" -ErrorAction Stop
        return [bool]$attr
    } catch {
        return $false
    }
}

function Invoke-Audit10LapsDeployment {
    Write-Host "`n--- Etat du deploiement Windows LAPS ---" -ForegroundColor Magenta

    $schemaOk = Test-LapsSchemaPresent
    if ($schemaOk) { Write-Log "Schema Active Directory Windows LAPS present." -Level OK }
    else { Write-Log "Schema Active Directory Windows LAPS ABSENT. Executez la remediation 'Preparer le schema' avant tout deploiement." -Level WARN }

    if (Get-Module -ListAvailable -Name LAPS) { Write-Log "Module PowerShell LAPS present sur ce poste." -Level OK }
    else { Write-Log "Module PowerShell LAPS absent de ce poste (necessaire pour les remediations dediees)." -Level WARN }

    if (-not $schemaOk) { return }

    $computers = @(Get-ADComputer -Filter * -Properties 'msLAPS-PasswordExpirationTime')
    $covered = @($computers | Where-Object { $_.'msLAPS-PasswordExpirationTime' })
    $notCovered = @($computers | Where-Object { -not $_.'msLAPS-PasswordExpirationTime' })

    $pct = if ($computers.Count -gt 0) { [math]::Round(($covered.Count / $computers.Count) * 100, 1) } else { 0 }
    Write-Host ("Couverture LAPS : {0}/{1} ordinateurs ({2} %)" -f $covered.Count, $computers.Count, $pct) -ForegroundColor Yellow

    $path = Join-Path $Script:LogDir ("Rapport_LAPS_Couverture_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    @($covered | Select-Object Name, DistinguishedName, @{N='LAPS';E={'Actif'}}) +
    @($notCovered | Select-Object Name, DistinguishedName, @{N='LAPS';E={'Absent'}}) |
        Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Write-Log ("Rapport exporte : {0}" -f $path) -Level OK
}

function Invoke-Audit10LapsPermissions {
    Write-Host "`n--- Audit des droits de lecture/reset du mot de passe LAPS ---" -ForegroundColor Magenta
    if (-not (Test-LapsModuleAvailable)) { return }

    $targetOUs = @(Select-OUsInteractive -Label "l'audit des permissions LAPS" -Verb "CIBLER")
    if ($targetOUs.Count -eq 0) { Write-Log "Aucune UO ciblee, action annulee." -Level WARN; return }

    $rows = @()
    foreach ($ou in $targetOUs) {
        try {
            $result = Find-LapsADExtendedRights -Identity $ou -ErrorAction Stop
            foreach ($r in $result) {
                foreach ($holder in $r.ExtendedRightHolders) {
                    $rows += [PSCustomObject]@{ OU = $ou; Principal = $holder }
                }
            }
        } catch {
            Write-Log ("Impossible d'auditer les droits LAPS sur {0} : {1}" -f $ou, $_.Exception.Message) -Level WARN
        }
    }

    if ($rows.Count -eq 0) { Write-Log "Aucun droit de lecture/reset LAPS trouve sur les UO ciblees (ou cmdlet indisponible)." -Level WARN; return }

    Write-Host "Principaux disposant d'un droit etendu sur le mot de passe LAPS :" -ForegroundColor Yellow
    $rows | Sort-Object Principal -Unique | ForEach-Object { Write-Host ("  - {0} (sur {1})" -f $_.Principal, $_.OU) }

    $path = Join-Path $Script:LogDir ("Rapport_LAPS_Permissions_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    $rows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Write-Log ("Rapport exporte : {0}. Comparez avec la liste des groupes qui DEVRAIENT avoir ce droit." -f $path) -Level OK
}

function Invoke-Remediate10PrepareSchema {
    Write-Host "`n--- Preparation du schema Active Directory pour Windows LAPS ---" -ForegroundColor Red
    Write-Host "Modification du SCHEMA de la foret (irreversible en pratique). Necessite d'etre membre" -ForegroundColor Yellow
    Write-Host "de Schema Admins et d'operer sur/depuis le Schema Master." -ForegroundColor Yellow

    if (-not (Test-LapsModuleAvailable)) { return }
    if (Test-LapsSchemaPresent) { Write-Log "Le schema Windows LAPS est deja present." -Level OK; return }

    if (-not (Confirm-Action "Executer Update-LapsADSchema (modification du schema de la foret)" -Strong)) { return }

    Invoke-Guarded -Description "Update-LapsADSchema" -Action {
        Update-LapsADSchema -Confirm:$false -ErrorAction Stop
    }
}

function Invoke-Remediate10DeployGpo {
    Write-Host "`n--- Deploiement de la GPO Windows LAPS ---" -ForegroundColor Red

    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Log "Le module GroupPolicy (RSAT-GPMC) n'est pas installe sur ce poste." -Level ERROR
        return
    }
    Import-Module GroupPolicy -ErrorAction SilentlyContinue

    if (-not (Test-LapsSchemaPresent)) {
        Write-Log "Schema Windows LAPS absent : executez d'abord 'Preparer le schema Active Directory'." -Level ERROR
        return
    }

    $lengthInput = Read-Host "Longueur du mot de passe [defaut 20]"
    $length = if ($lengthInput -match '^\d+$') { [int]$lengthInput } else { 20 }
    $ageInput = Read-Host "Age maximal du mot de passe en jours [defaut 30]"
    $age = if ($ageInput -match '^\d+$') { [int]$ageInput } else { 30 }

    $hybrid = (Read-Host "Environnement hybride : sauvegarder dans Microsoft Entra ID plutot que dans Active Directory ? (O/N)") -match '^[oOyY]'
    # BackupDirectory (policy Windows LAPS) : 1 = Azure AD / Entra ID, 2 = Active Directory.
    $backupDirectory = if ($hybrid) { 1 } else { 2 }

    $targetOUs = @(Select-OUsInteractive -Label "la GPO Windows LAPS" -Verb "CIBLER (lien de la GPO)")
    if ($targetOUs.Count -eq 0) { Write-Log "Aucune UO ciblee, action annulee." -Level WARN; return }

    $gpoName = "SEC - Windows LAPS"
    $backupLabel = if ($hybrid) { 'Entra ID' } else { 'Active Directory' }
    if (-not (Confirm-Action ("Creer/MAJ la GPO '{0}' (longueur={1}, age max={2}j, sauvegarde={3}) et la lier sur {4} UO" -f $gpoName, $length, $age, $backupLabel, $targetOUs.Count) -Strong)) { return }

    Invoke-Guarded -Description ("Creation/MAJ de la GPO {0}" -f $gpoName) -Action {
        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        if (-not $gpo) { $gpo = New-GPO -Name $gpoName }
        $key = "HKLM\Software\Microsoft\Policies\LAPS"
        Set-GPRegistryValue -Name $gpoName -Key $key -ValueName "BackupDirectory" -Type DWord -Value $backupDirectory
        Set-GPRegistryValue -Name $gpoName -Key $key -ValueName "PasswordComplexity" -Type DWord -Value 4
        Set-GPRegistryValue -Name $gpoName -Key $key -ValueName "PasswordLength" -Type DWord -Value $length
        Set-GPRegistryValue -Name $gpoName -Key $key -ValueName "PasswordAgeDays" -Type DWord -Value $age
        Set-GPRegistryValue -Name $gpoName -Key $key -ValueName "PostAuthenticationResetDelay" -Type DWord -Value 4

        foreach ($ou in $targetOUs) {
            try { New-GPLink -Name $gpoName -Target $ou -ErrorAction Stop | Out-Null } catch { }
        }
    }

    Write-Log "GPO Windows LAPS deployee et liee. Prise en compte au prochain rafraichissement de GPO sur les machines ciblees." -Level OK
}

function Invoke-Remediate10SetPermissions {
    Write-Host "`n--- Configuration des droits de lecture/reset du mot de passe LAPS ---" -ForegroundColor Red
    Write-Host "Modifie les ACL Active Directory : reservez ce droit au strict necessaire (equipe" -ForegroundColor DarkGray
    Write-Host "support/securite habilitee), jamais a un groupe large type 'Tous les administrateurs'." -ForegroundColor DarkGray

    if (-not (Test-LapsModuleAvailable)) { return }

    $targetOUs = @(Select-OUsInteractive -Label "la delegation des droits LAPS" -Verb "CIBLER")
    if ($targetOUs.Count -eq 0) { return }

    $readGroup = Read-Host "Groupe autorise a LIRE le mot de passe LAPS (vide = ne pas modifier ce droit)"
    $resetGroup = Read-Host "Groupe autorise a FORCER le renouvellement (reset) du mot de passe LAPS (vide = ne pas modifier ce droit)"
    if ([string]::IsNullOrWhiteSpace($readGroup) -and [string]::IsNullOrWhiteSpace($resetGroup)) { Write-Log "Aucun groupe fourni, action annulee." -Level WARN; return }

    $readLabel = if ($readGroup) { $readGroup } else { 'inchange' }
    $resetLabel = if ($resetGroup) { $resetGroup } else { 'inchange' }
    if (-not (Confirm-Action ("Deleguer les droits LAPS sur {0} UO (lecture={1}, reset={2})" -f $targetOUs.Count, $readLabel, $resetLabel) -Strong)) { return }

    foreach ($ou in $targetOUs) {
        if ($readGroup) {
            Invoke-Guarded -Description ("Delegation lecture LAPS sur {0} a {1}" -f $ou, $readGroup) -Action {
                Set-LapsADReadPasswordPermission -Identity $ou -AllowedPrincipals $readGroup -ErrorAction Stop
            }
        }
        if ($resetGroup) {
            Invoke-Guarded -Description ("Delegation reset LAPS sur {0} a {1}" -f $ou, $resetGroup) -Action {
                Set-LapsADResetPasswordPermission -Identity $ou -AllowedPrincipals $resetGroup -ErrorAction Stop
            }
        }
    }
}

# ============================================================
#  SECTION - GPO DE DURCISSEMENT (theme "GPO de durcissement" du menu)
#  Sauvegarde de toutes les GPO avant modification sensible, et creation du
#  socle GPO-SEC-* nomme demande par le cahier des charges. Les remediations
#  thematiques de ce script (LAPS, NTLM, SMB, LLMNR...) continuent pour
#  l'instant de creer leurs propres GPO "SEC - ..." dediees : ce theme cree
#  les 9 GPO-SEC-* en COMPLEMENT (coquilles vides a peupler progressivement),
#  sans toucher aux GPO existantes.
# ============================================================

$Script:GpoSecBaselineNames = @(
    "GPO-SEC-DomainControllers",
    "GPO-SEC-Servers",
    "GPO-SEC-Workstations",
    "GPO-SEC-Authentication",
    "GPO-SEC-WindowsLAPS",
    "GPO-SEC-Audit",
    "GPO-SEC-Defender",
    "GPO-SEC-RDP",
    "GPO-SEC-Network"
)

function Invoke-Audit12GpoBaselineStatus {
    Write-Host "`n--- Etat du socle GPO-SEC-* et des sauvegardes de GPO ---" -ForegroundColor Magenta

    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Log "Le module GroupPolicy (RSAT-GPMC) n'est pas installe sur ce poste." -Level ERROR
        return
    }
    Import-Module GroupPolicy -ErrorAction SilentlyContinue

    $rows = foreach ($name in $Script:GpoSecBaselineNames) {
        $gpo = Get-GPO -Name $name -ErrorAction SilentlyContinue
        [PSCustomObject]@{ GPO = $name; Presente = [bool]$gpo }
    }
    $rows | ForEach-Object {
        $color = if ($_.Presente) { 'Green' } else { 'Yellow' }
        Write-Host ("  - {0} : {1}" -f $_.GPO, $(if ($_.Presente) { 'presente' } else { 'absente' })) -ForegroundColor $color
    }

    $backupRoot = Join-Path $Script:LogDir "GPO_Backups"
    if (Test-Path $backupRoot) {
        $lastBackup = Get-ChildItem -Path $backupRoot -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
        if ($lastBackup) { Write-Log ("Derniere sauvegarde complete des GPO : {0}" -f $lastBackup.FullName) -Level OK }
        else { Write-Log "Dossier de sauvegarde des GPO present mais vide." -Level WARN }
    } else {
        Write-Log "Aucune sauvegarde complete des GPO trouvee dans Logs\GPO_Backups. A faire avant tout changement sensible." -Level WARN
    }

    $path = Join-Path $Script:LogDir ("Rapport_GPOBaseline_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    $rows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Write-Log ("Rapport exporte : {0}" -f $path) -Level OK
}

function Invoke-Remediate12BackupAllGpos {
    Write-Host "`n--- Sauvegarde de TOUTES les GPO du domaine ---" -ForegroundColor Cyan
    Write-Host "Impact : AUCUN (lecture seule des GPO existantes, ecriture uniquement dans Logs\GPO_Backups)." -ForegroundColor DarkGray
    Write-Host "A faire avant tout changement sensible sur une GPO existante, pour disposer d'un retour arriere." -ForegroundColor DarkGray

    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Log "Le module GroupPolicy (RSAT-GPMC) n'est pas installe sur ce poste." -Level ERROR
        return
    }
    Import-Module GroupPolicy -ErrorAction SilentlyContinue

    $backupPath = Join-Path (Join-Path $Script:LogDir "GPO_Backups") (Get-Date -Format "yyyyMMdd_HHmmss")

    if (-not (Confirm-Action ("Sauvegarder toutes les GPO du domaine vers {0}" -f $backupPath))) { return }

    Invoke-Guarded -Description ("Backup-GPO -All vers {0}" -f $backupPath) -Action {
        New-Item -Path $backupPath -ItemType Directory -Force | Out-Null
        $results = Backup-GPO -All -Path $backupPath -ErrorAction Stop
        Write-Log ("{0} GPO sauvegardee(s) dans {1}." -f @($results).Count, $backupPath) -Level OK
    }
}

function Invoke-Remediate12CreateBaselineGpoShells {
    Write-Host "`n--- Creation du socle GPO-SEC-* (coquilles vides) ---" -ForegroundColor Cyan
    Write-Host "Impact : AUCUN sur l'existant. Cree uniquement les GPO manquantes, SANS AUCUN parametre" -ForegroundColor DarkGray
    Write-Host "         et SANS AUCUN lien vers une OU (donc sans effet tant qu'elles ne sont pas remplies" -ForegroundColor DarkGray
    Write-Host "         et liees deliberement)." -ForegroundColor DarkGray
    Write-Host "Les remediations thematiques de ce script (LAPS, NTLM, SMB, LLMNR...) continuent pour" -ForegroundColor DarkGray
    Write-Host "l'instant de creer leurs propres GPO 'SEC - ...' dediees : ce socle nomme est un point de" -ForegroundColor DarkGray
    Write-Host "depart a completer manuellement (ou lors d'une prochaine evolution du script)." -ForegroundColor DarkGray

    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Log "Le module GroupPolicy (RSAT-GPMC) n'est pas installe sur ce poste." -Level ERROR
        return
    }
    Import-Module GroupPolicy -ErrorAction SilentlyContinue

    $missing = @($Script:GpoSecBaselineNames | Where-Object { -not (Get-GPO -Name $_ -ErrorAction SilentlyContinue) })
    if ($missing.Count -eq 0) { Write-Log "Les 9 GPO du socle GPO-SEC-* existent deja." -Level OK; return }

    Write-Host ("GPO manquantes a creer : {0}" -f ($missing -join ', ')) -ForegroundColor Yellow
    if (-not (Confirm-Action ("Creer les {0} GPO manquantes du socle GPO-SEC-* (non liees)" -f $missing.Count))) { return }

    foreach ($name in $missing) {
        Invoke-Guarded -Description ("Creation de la GPO {0}" -f $name) -Action {
            New-GPO -Name $name -Comment "Socle de durcissement AD - coquille creee par le script de remediation, a completer et lier deliberement." | Out-Null
        }
    }
}

# ============================================================
#  SECTION - POSTES ET SERVEURS MEMBRES (theme "Postes et serveurs" du menu)
#  Microsoft Defender (Cloud Protection, Network Protection, SmartScreen, ASR
#  en mode progressif Audit/Warn/Block), administrateurs locaux, RDP.
# ============================================================

function Invoke-Audit13DefenderStatus {
    Write-Host "`n--- Etat de Microsoft Defender sur des postes/serveurs choisis ---" -ForegroundColor Magenta
    Write-Host "Interroge directement les machines choisies (Get-MpComputerStatus/Get-MpPreference) via" -ForegroundColor DarkGray
    Write-Host "PowerShell Remoting : necessite WinRM actif sur ces machines (comme pour les DC)." -ForegroundColor DarkGray

    $targetOU = @(Select-OUsInteractive -Label "l'audit Defender" -Verb "CIBLER")
    if ($targetOU.Count -eq 0) { Write-Log "Aucune UO ciblee, action annulee." -Level WARN; return }

    $computers = @(foreach ($ou in $targetOU) { Get-ADComputer -SearchBase $ou -Filter 'Enabled -eq $true' -Properties DNSHostName })
    if ($computers.Count -eq 0) { Write-Log "Aucun ordinateur actif trouve dans les UO ciblees." -Level WARN; return }

    $names = @($computers | ForEach-Object { if ($_.DNSHostName) { $_.DNSHostName } else { $_.Name } })
    $wr = Test-DCWinRmConnectivity -ComputerNames $names
    if ($wr.Reachable.Count -eq 0) { Write-Log "Aucune machine joignable via PowerShell Remoting (WinRM) parmi celles ciblees." -Level ERROR; return }

    $rows = foreach ($name in $wr.Reachable) {
        try {
            Invoke-Command -ComputerName $name -ScriptBlock {
                $status = Get-MpComputerStatus -ErrorAction Stop
                $pref = Get-MpPreference -ErrorAction Stop
                [PSCustomObject]@{
                    Machine                 = $env:COMPUTERNAME
                    ProtectionTempsReel     = $status.RealTimeProtectionEnabled
                    ProtectionCloud         = ($pref.MAPSReporting -ne 0)
                    ProtectionReseau        = ($pref.EnableNetworkProtection -ne 0)
                    NombreReglesASRDefinies = @($pref.AttackSurfaceReductionRules_Ids).Count
                }
            } -ErrorAction Stop
        } catch {
            Write-Log ("Impossible d'interroger Defender sur {0} : {1}" -f $name, $_.Exception.Message) -Level WARN
        }
    }

    $rows = @($rows)
    $rows | ForEach-Object { Write-Host ("  - {0} : temps reel={1}, cloud={2}, protection reseau={3}, regles ASR={4}" -f $_.Machine, $_.ProtectionTempsReel, $_.ProtectionCloud, $_.ProtectionReseau, $_.NombreReglesASRDefinies) -ForegroundColor Yellow }

    $path = Join-Path $Script:LogDir ("Rapport_Defender_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    $rows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Write-Log ("Rapport exporte : {0}" -f $path) -Level OK
}

function Invoke-Audit13LocalAdmins {
    Write-Host "`n--- Audit des administrateurs locaux sur des postes/serveurs choisis ---" -ForegroundColor Magenta

    $targetOU = @(Select-OUsInteractive -Label "l'audit des administrateurs locaux" -Verb "CIBLER")
    if ($targetOU.Count -eq 0) { Write-Log "Aucune UO ciblee, action annulee." -Level WARN; return }

    $computers = @(foreach ($ou in $targetOU) { Get-ADComputer -SearchBase $ou -Filter 'Enabled -eq $true' -Properties DNSHostName })
    if ($computers.Count -eq 0) { Write-Log "Aucun ordinateur actif trouve dans les UO ciblees." -Level WARN; return }

    $names = @($computers | ForEach-Object { if ($_.DNSHostName) { $_.DNSHostName } else { $_.Name } })
    $wr = Test-DCWinRmConnectivity -ComputerNames $names
    if ($wr.Reachable.Count -eq 0) { Write-Log "Aucune machine joignable via PowerShell Remoting (WinRM) parmi celles ciblees." -Level ERROR; return }

    $rows = foreach ($name in $wr.Reachable) {
        try {
            Invoke-Command -ComputerName $name -ScriptBlock {
                Get-LocalGroupMember -Group "Administrateurs" -ErrorAction SilentlyContinue
                if (-not $?) { Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue }
            } -ErrorAction Stop | ForEach-Object {
                [PSCustomObject]@{ Machine = $name; Membre = $_.Name; Type = $_.ObjectClass }
            }
        } catch {
            Write-Log ("Impossible de lire les administrateurs locaux de {0} : {1}" -f $name, $_.Exception.Message) -Level WARN
        }
    }

    $rows = @($rows)
    if ($rows.Count -eq 0) { Write-Log "Aucun resultat (verifiez les droits d'acces distant aux machines ciblees)." -Level WARN; return }
    $rows | ForEach-Object { Write-Host ("  - {0} : {1} ({2})" -f $_.Machine, $_.Membre, $_.Type) -ForegroundColor Yellow }

    $path = Join-Path $Script:LogDir ("Rapport_AdminsLocaux_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    $rows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Write-Log ("Rapport exporte : {0}. Comparez avec la liste des comptes/groupes qui devraient legitimement etre administrateurs locaux." -f $path) -Level OK
}

function Invoke-Remediate13EnableDefenderProtections {
    Write-Host "`n--- Renforcement Microsoft Defender via GPO (Cloud, Reseau, SmartScreen, ASR) ---" -ForegroundColor Red
    Write-Host "Risque : le mode Bloquer des regles ASR peut bloquer une application legitime qui a un" -ForegroundColor DarkGray
    Write-Host "         comportement proche d'une menace (faux positif). Deploiement PROGRESSIF recommande :" -ForegroundColor DarkGray
    Write-Host "         Audit d'abord (observation sans blocage), puis Avertir, puis Bloquer." -ForegroundColor DarkGray

    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Log "Le module GroupPolicy (RSAT-GPMC) n'est pas installe sur ce poste." -Level ERROR
        return
    }
    Import-Module GroupPolicy -ErrorAction SilentlyContinue

    $modeInput = Read-Host "Mode des regles ASR [1=Audit (defaut, recommande pour commencer) / 2=Avertir / 3=Bloquer]"
    $asrValue = switch ($modeInput) { "2" { "6" }; "3" { "1" }; default { "2" } }
    $modeLabel = switch ($modeInput) { "2" { "Avertir" }; "3" { "Bloquer" }; default { "Audit" } }

    $targetOUs = @(Select-OUsInteractive -Label "la GPO de durcissement Defender" -Verb "CIBLER (lien de la GPO)")
    if ($targetOUs.Count -eq 0) { Write-Log "Aucune UO ciblee, action annulee." -Level WARN; return }

    # Regles ASR couramment recommandees (faible taux de faux positifs) :
    #  - Blocage des appels API Win32 depuis les macros Office
    #  - Blocage de l'execution de scripts potentiellement obfusques
    #  - Protection avancee contre les ransomwares
    #  - Blocage du vol d'identifiants depuis lsass.exe
    #  - Blocage de la creation de contenu executable par les applications Office
    #  - Blocage du lancement de contenu executable telecharge par JavaScript/VBScript
    $asrRules = @(
        "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B",
        "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC",
        "C1DB55AB-C21A-4637-BB3F-A12568109D35",
        "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2",
        "3B576869-A4EC-4529-8536-B80A7769E899",
        "D3E037E1-3EB8-44C8-A917-57927947596D"
    )

    $gpoName = "SEC - Defender Hardening"
    if (-not (Confirm-Action ("Creer/MAJ la GPO '{0}' (Cloud+Reseau+SmartScreen actifs, {1} regles ASR en mode {2}) et la lier sur {3} UO" -f $gpoName, $asrRules.Count, $modeLabel, $targetOUs.Count) -Strong)) { return }

    Invoke-Guarded -Description ("Creation/MAJ de la GPO {0}" -f $gpoName) -Action {
        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        if (-not $gpo) { $gpo = New-GPO -Name $gpoName }

        Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -ValueName "SpynetReporting" -Type DWord -Value 2
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -ValueName "SubmitSamplesConsent" -Type DWord -Value 1
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -ValueName "EnableNetworkProtection" -Type DWord -Value 1
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "EnableSmartScreen" -Type DWord -Value 1
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "ShellSmartScreenLevel" -Type String -Value "Block"

        Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -ValueName "ExploitGuard_ASR_Rules" -Type DWord -Value 1
        foreach ($rule in $asrRules) {
            Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ValueName $rule -Type String -Value $asrValue
        }

        foreach ($ou in $targetOUs) {
            try { New-GPLink -Name $gpoName -Target $ou -ErrorAction Stop | Out-Null } catch { }
        }
    }
    Write-Log ("GPO deployee en mode ASR '{0}'. Surveillez les evenements Defender (ID 1121/1122) avant de passer au mode superieur." -f $modeLabel) -Level OK
}

function Invoke-Remediate13RestrictRdp {
    Write-Host "`n--- Restriction RDP (NLA + niveau de chiffrement) via GPO ---" -ForegroundColor Red
    Write-Host "Risque : casse les clients RDP tres anciens ne supportant pas la Network Level" -ForegroundColor DarkGray
    Write-Host "         Authentication (NLA) - rare sur un parc a jour." -ForegroundColor DarkGray

    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Log "Le module GroupPolicy (RSAT-GPMC) n'est pas installe sur ce poste." -Level ERROR
        return
    }
    Import-Module GroupPolicy -ErrorAction SilentlyContinue

    $targetOUs = @(Select-OUsInteractive -Label "la GPO de restriction RDP" -Verb "CIBLER (lien de la GPO)")
    if ($targetOUs.Count -eq 0) { Write-Log "Aucune UO ciblee, action annulee." -Level WARN; return }

    $gpoName = "SEC - Restriction RDP (NLA)"
    if (-not (Confirm-Action ("Creer/MAJ la GPO '{0}' (NLA obligatoire, chiffrement eleve) et la lier sur {1} UO" -f $gpoName, $targetOUs.Count) -Strong)) { return }

    Invoke-Guarded -Description ("Creation/MAJ de la GPO {0}" -f $gpoName) -Action {
        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        if (-not $gpo) { $gpo = New-GPO -Name $gpoName }
        $key = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        Set-GPRegistryValue -Name $gpoName -Key $key -ValueName "UserAuthentication" -Type DWord -Value 1
        Set-GPRegistryValue -Name $gpoName -Key $key -ValueName "MinEncryptionLevel" -Type DWord -Value 3
        foreach ($ou in $targetOUs) {
            try { New-GPLink -Name $gpoName -Target $ou -ErrorAction Stop | Out-Null } catch { }
        }
    }
    Write-Log "GPO liee. Le controle de QUI a le droit de se connecter en RDP (groupe restreint) reste une etape manuelle dans GPMC (Attribution des droits utilisateur, non exposee par le module GroupPolicy)." -Level WARN
}

function Invoke-Remediate13CleanupLocalAdmins {
    Write-Host "`n--- Retirer des comptes des administrateurs locaux sur des postes/serveurs choisis ---" -ForegroundColor Red
    Write-Host "Risque : retirer un compte qui a reellement besoin de ce privilege local cassera son usage" -ForegroundColor DarkGray
    Write-Host "         sur la machine concernee (application necessitant des droits locaux, support...)." -ForegroundColor DarkGray

    $targetOU = @(Select-OUsInteractive -Label "le nettoyage des administrateurs locaux" -Verb "CIBLER")
    if ($targetOU.Count -eq 0) { return }

    $computers = @(foreach ($ou in $targetOU) { Get-ADComputer -SearchBase $ou -Filter 'Enabled -eq $true' -Properties DNSHostName })
    if ($computers.Count -eq 0) { Write-Log "Aucun ordinateur actif trouve dans les UO ciblees." -Level WARN; return }
    $names = @($computers | ForEach-Object { if ($_.DNSHostName) { $_.DNSHostName } else { $_.Name } })
    $wr = Test-DCWinRmConnectivity -ComputerNames $names
    if ($wr.Reachable.Count -eq 0) { Write-Log "Aucune machine joignable via PowerShell Remoting (WinRM) parmi celles ciblees." -Level ERROR; return }

    $machine = Read-Host "Sur quelle machine agir (nom exact parmi celles ci-dessus) ?"
    if ($wr.Reachable -notcontains $machine) { Write-Log "Machine non joignable ou non trouvee parmi les cibles." -Level ERROR; return }

    $members = @()
    try {
        $members = Invoke-Command -ComputerName $machine -ScriptBlock {
            try { Get-LocalGroupMember -Group "Administrateurs" -ErrorAction Stop } catch { Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop }
        } -ErrorAction Stop
    } catch {
        Write-Log ("Impossible de lire les administrateurs locaux de {0} : {1}" -f $machine, $_.Exception.Message) -Level ERROR
        return
    }

    if ($members.Count -eq 0) { Write-Log "Aucun membre trouve." -Level OK; return }
    for ($i = 0; $i -lt $members.Count; $i++) { Write-Host ("  [{0}] {1}" -f $i, $members[$i].Name) }
    $sel = Read-Host "Numeros a retirer, separes par une virgule (vide = annuler)"
    if ([string]::IsNullOrWhiteSpace($sel)) { return }
    $idx = @($sel -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ } | Where-Object { $_ -lt $members.Count })
    $targets = @($idx | ForEach-Object { $members[$_] })
    if ($targets.Count -eq 0) { return }

    if (-not (Confirm-Action ("Retirer {0} compte(s) des administrateurs locaux de {1}" -f $targets.Count, $machine) -Strong)) { return }

    foreach ($t in $targets) {
        Invoke-Guarded -Description ("Retrait de {0} des administrateurs locaux de {1}" -f $t.Name, $machine) -Action {
            Invoke-Command -ComputerName $machine -ScriptBlock {
                param($member)
                try { Remove-LocalGroupMember -Group "Administrateurs" -Member $member -ErrorAction Stop }
                catch { Remove-LocalGroupMember -Group "Administrators" -Member $member -ErrorAction Stop }
            } -ArgumentList $t.Name -ErrorAction Stop
        }
    }
}

function Invoke-Remediate13EnablePowerShellLoggingExtended {
    Write-Host "`n--- Etendre la journalisation PowerShell aux postes/serveurs choisis ---" -ForegroundColor Red
    Write-Host "Complementaire a l'activation sur les DC (menu Journalisation et detection > 3)." -ForegroundColor DarkGray
    Write-Host "Impact : AUCUN fonctionnel (journalisation uniquement), peut augmenter le volume de logs." -ForegroundColor DarkGray

    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Log "Le module GroupPolicy (RSAT-GPMC) n'est pas installe sur ce poste." -Level ERROR
        return
    }
    Import-Module GroupPolicy -ErrorAction SilentlyContinue

    $targetOUs = @(Select-OUsInteractive -Label "l'extension de la journalisation PowerShell" -Verb "CIBLER (lien de la GPO)")
    if ($targetOUs.Count -eq 0) { Write-Log "Aucune UO ciblee, action annulee." -Level WARN; return }

    $gpoName = "SEC - Audit PowerShell Logging"
    if (-not (Confirm-Action ("Lier la GPO '{0}' (creee si absente) sur {1} UO supplementaire(s)" -f $gpoName, $targetOUs.Count))) { return }

    Invoke-Guarded -Description ("Extension de la GPO {0}" -f $gpoName) -Action {
        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        if (-not $gpo) {
            $gpo = New-GPO -Name $gpoName
            Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ValueName "EnableScriptBlockLogging" -Type DWord -Value 1
            Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ValueName "EnableModuleLogging" -Type DWord -Value 1
        }
        foreach ($ou in $targetOUs) {
            try { New-GPLink -Name $gpoName -Target $ou -ErrorAction Stop | Out-Null } catch { }
        }
    }
}

function Invoke-Remediate13DisableWindowsScriptHost {
    Write-Host "`n--- Bloquer l'execution de scripts .vbs/.js (Windows Script Host) ---" -ForegroundColor Red
    Write-Host "Risque : casse les scripts de connexion/outils internes bases sur WSH (.vbs, .js, .wsf)." -ForegroundColor DarkGray
    Write-Host "         Verifiez l'absence de dependance avant d'appliquer largement." -ForegroundColor DarkGray

    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Log "Le module GroupPolicy (RSAT-GPMC) n'est pas installe sur ce poste." -Level ERROR
        return
    }
    Import-Module GroupPolicy -ErrorAction SilentlyContinue

    $targetOUs = @(Select-OUsInteractive -Label "le blocage Windows Script Host" -Verb "CIBLER (lien de la GPO)")
    if ($targetOUs.Count -eq 0) { Write-Log "Aucune UO ciblee, action annulee." -Level WARN; return }

    $gpoName = "SEC - Blocage Windows Script Host"
    if (-not (Confirm-Action ("Creer/MAJ la GPO '{0}' et la lier sur {1} UO" -f $gpoName, $targetOUs.Count) -Strong)) { return }

    Invoke-Guarded -Description ("Creation/MAJ de la GPO {0}" -f $gpoName) -Action {
        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        if (-not $gpo) { $gpo = New-GPO -Name $gpoName }
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Microsoft\Windows Script Host\Settings" -ValueName "Enabled" -Type DWord -Value 0
        foreach ($ou in $targetOUs) {
            try { New-GPLink -Name $gpoName -Target $ou -ErrorAction Stop | Out-Null } catch { }
        }
    }
}

function Invoke-Remediate13EnableFirewallBaseline {
    Write-Host "`n--- Activer le pare-feu Windows (3 profils) sur des postes/serveurs choisis ---" -ForegroundColor Red
    Write-Host "Risque : si des flux legitimes ne sont pas couverts par les regles predefinies actives" -ForegroundColor DarkGray
    Write-Host "         (ou vos regles personnalisees), ils seront bloques. Testez en OU pilote." -ForegroundColor DarkGray

    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Log "Le module GroupPolicy (RSAT-GPMC) n'est pas installe sur ce poste." -Level ERROR
        return
    }
    Import-Module GroupPolicy -ErrorAction SilentlyContinue

    $targetOUs = @(Select-OUsInteractive -Label "la GPO de pare-feu" -Verb "CIBLER (lien de la GPO)")
    if ($targetOUs.Count -eq 0) { Write-Log "Aucune UO ciblee, action annulee." -Level WARN; return }

    $gpoName = "SEC - Pare-feu Windows actif (Postes-Serveurs)"
    if (-not (Confirm-Action ("Creer/MAJ la GPO '{0}' et la lier sur {1} UO" -f $gpoName, $targetOUs.Count) -Strong)) { return }

    Invoke-Guarded -Description ("Creation/MAJ de la GPO {0}" -f $gpoName) -Action {
        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        if (-not $gpo) { $gpo = New-GPO -Name $gpoName }
        foreach ($fwProfile in @('DomainProfile','PrivateProfile','PublicProfile')) {
            $key = "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\$fwProfile"
            Set-GPRegistryValue -Name $gpoName -Key $key -ValueName "EnableFirewall" -Type DWord -Value 1
            Set-GPRegistryValue -Name $gpoName -Key $key -ValueName "DefaultInboundAction" -Type DWord -Value 1
        }
        foreach ($ou in $targetOUs) {
            try { New-GPLink -Name $gpoName -Target $ou -ErrorAction Stop | Out-Null } catch { }
        }
    }
}

# ============================================================
#  SECTION - RESEAU ET ANTI-RELAY - COMPLEMENT (theme "Reseau et anti-relay")
#  LLMNR est deja couvert (Invoke-RiskyDisableLLMNR). Complements : Global Query
#  Block List (WPAD/ISATAP), NetBIOS, durcissement RPC et WinRM.
# ============================================================

function Invoke-Audit14GlobalQueryBlockList {
    Write-Host "`n--- Audit de la Global Query Block List DNS (WPAD/ISATAP) ---" -ForegroundColor Magenta
    Write-Host "Windows bloque par defaut la resolution DNS des noms 'wpad' et 'isatap' (protection" -ForegroundColor DarkGray
    Write-Host "anti-relay integree depuis Windows Server 2008/Vista). Verifie que ce blocage par defaut" -ForegroundColor DarkGray
    Write-Host "n'a pas ete retire par erreur sur les serveurs DNS (DC)." -ForegroundColor DarkGray

    $dcs = Get-DomainControllersList
    if (-not $dcs) { return }
    $wr = Test-DCWinRmConnectivity -ComputerNames $dcs.HostName
    $dcs = @($dcs | Where-Object { $wr.Reachable -contains $_.HostName })
    if (-not $dcs) { Write-Log "Aucun DC joignable via PowerShell Remoting (WinRM), action annulee." -Level ERROR; return }

    foreach ($dc in $dcs) {
        try {
            $list = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                (Get-DnsServerGlobalQueryBlockList -ErrorAction Stop)
            } -ErrorAction Stop
            $hasWpad = $list.List -contains 'wpad'
            $hasIsatap = $list.List -contains 'isatap'
            $color = if ($list.Enable -and $hasWpad -and $hasIsatap) { 'Green' } else { 'Yellow' }
            Write-Host ("  - {0} : activee={1}, wpad={2}, isatap={3}" -f $dc.HostName, $list.Enable, $hasWpad, $hasIsatap) -ForegroundColor $color
        } catch {
            Write-Log ("Impossible de lire la Global Query Block List sur {0} : {1}" -f $dc.HostName, $_.Exception.Message) -Level WARN
        }
    }
}

function Invoke-Remediate14RestoreGlobalQueryBlockList {
    Write-Host "`n--- Retablir la Global Query Block List DNS (wpad/isatap) ---" -ForegroundColor Cyan
    Write-Host "Impact : restaure une protection par defaut de Windows (aucune incidence si WPAD/ISATAP" -ForegroundColor DarkGray
    Write-Host "         ne sont pas utilises intentionnellement sur le reseau, ce qui est la norme)." -ForegroundColor DarkGray

    $dcs = Get-DomainControllersList
    if (-not $dcs) { return }
    $wr = Test-DCWinRmConnectivity -ComputerNames $dcs.HostName
    $dcs = @($dcs | Where-Object { $wr.Reachable -contains $_.HostName })
    if (-not $dcs) { Write-Log "Aucun DC joignable via PowerShell Remoting (WinRM), action annulee." -Level ERROR; return }

    if (-not (Confirm-Action "Retablir la Global Query Block List (wpad, isatap) activee sur tous les DC" )) { return }

    foreach ($dc in $dcs) {
        Invoke-Guarded -Description ("Retablissement de la Global Query Block List sur {0}" -f $dc.HostName) -Action {
            Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                Set-DnsServerGlobalQueryBlockList -List @('wpad','isatap') -Enable $true -ErrorAction Stop
            } -ErrorAction Stop
        }
    }
}

function Invoke-Remediate14DisableNetbiosOnComputers {
    Write-Host "`n--- Desactivation de NetBIOS sur TCP/IP sur des postes/serveurs choisis ---" -ForegroundColor Red
    Write-Host "Risque : casse la resolution de nom de secours NetBIOS/NBT-NS utilisee par certaines" -ForegroundColor DarkGray
    Write-Host "         applications/imprimantes anciennes quand le DNS echoue." -ForegroundColor DarkGray

    $targetOU = @(Select-OUsInteractive -Label "la desactivation NetBIOS" -Verb "CIBLER")
    if ($targetOU.Count -eq 0) { return }

    $computers = @(foreach ($ou in $targetOU) { Get-ADComputer -SearchBase $ou -Filter 'Enabled -eq $true' -Properties DNSHostName })
    if ($computers.Count -eq 0) { Write-Log "Aucun ordinateur actif trouve dans les UO ciblees." -Level WARN; return }
    $names = @($computers | ForEach-Object { if ($_.DNSHostName) { $_.DNSHostName } else { $_.Name } })
    $wr = Test-DCWinRmConnectivity -ComputerNames $names
    if ($wr.Reachable.Count -eq 0) { Write-Log "Aucune machine joignable via PowerShell Remoting (WinRM) parmi celles ciblees." -Level ERROR; return }

    Write-Host ("Machines ciblees : {0}" -f ($wr.Reachable -join ', ')) -ForegroundColor Yellow
    if (-not (Confirm-Action ("Desactiver NetBIOS sur TCP/IP sur {0} machine(s)" -f $wr.Reachable.Count) -Strong)) { return }

    foreach ($name in $wr.Reachable) {
        Invoke-Guarded -Description ("Desactivation NetBIOS sur {0}" -f $name) -Action {
            Invoke-Command -ComputerName $name -ScriptBlock {
                Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" | ForEach-Object {
                    # SetTcpipNetbios(2) = desactiver NetBIOS sur TCP/IP pour cette interface
                    $_.SetTcpipNetbios(2) | Out-Null
                }
            } -ErrorAction Stop
        }
    }
}

function Invoke-Remediate14RestrictRpc {
    Write-Host "`n--- Durcissement RPC (clients non authentifies, resolution du mappeur de points terminaux) ---" -ForegroundColor Red
    Write-Host "Risque : casse les applications RPC anciennes qui dependent de clients non authentifies" -ForegroundColor DarkGray
    Write-Host "         (rare sur un environnement homogene Windows a jour)." -ForegroundColor DarkGray

    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Log "Le module GroupPolicy (RSAT-GPMC) n'est pas installe sur ce poste." -Level ERROR
        return
    }
    Import-Module GroupPolicy -ErrorAction SilentlyContinue

    $targetOUs = @(Select-OUsInteractive -Label "la GPO de durcissement RPC" -Verb "CIBLER (lien de la GPO)")
    if ($targetOUs.Count -eq 0) { Write-Log "Aucune UO ciblee, action annulee." -Level WARN; return }

    $gpoName = "SEC - Durcissement RPC"
    if (-not (Confirm-Action ("Creer/MAJ la GPO '{0}' et la lier sur {1} UO" -f $gpoName, $targetOUs.Count) -Strong)) { return }

    Invoke-Guarded -Description ("Creation/MAJ de la GPO {0}" -f $gpoName) -Action {
        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        if (-not $gpo) { $gpo = New-GPO -Name $gpoName }
        $key = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
        Set-GPRegistryValue -Name $gpoName -Key $key -ValueName "RestrictRemoteClients" -Type DWord -Value 1
        Set-GPRegistryValue -Name $gpoName -Key $key -ValueName "EnableAuthEpResolution" -Type DWord -Value 1
        foreach ($ou in $targetOUs) {
            try { New-GPLink -Name $gpoName -Target $ou -ErrorAction Stop | Out-Null } catch { }
        }
    }
}

function Invoke-Remediate14RestrictWinRm {
    Write-Host "`n--- Durcissement WinRM (authentification Basic desactivee, trafic chiffre obligatoire) ---" -ForegroundColor Red
    Write-Host "Risque : casse les scripts/outils tiers qui se connectent en WinRM avec l'authentification" -ForegroundColor DarkGray
    Write-Host "         Basic ou en trafic non chiffre." -ForegroundColor DarkGray

    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Log "Le module GroupPolicy (RSAT-GPMC) n'est pas installe sur ce poste." -Level ERROR
        return
    }
    Import-Module GroupPolicy -ErrorAction SilentlyContinue

    $targetOUs = @(Select-OUsInteractive -Label "la GPO de durcissement WinRM" -Verb "CIBLER (lien de la GPO)")
    if ($targetOUs.Count -eq 0) { Write-Log "Aucune UO ciblee, action annulee." -Level WARN; return }

    $gpoName = "SEC - Durcissement WinRM"
    if (-not (Confirm-Action ("Creer/MAJ la GPO '{0}' (Basic desactive, trafic chiffre obligatoire, client+serveur) et la lier sur {1} UO" -f $gpoName, $targetOUs.Count) -Strong)) { return }

    Invoke-Guarded -Description ("Creation/MAJ de la GPO {0}" -f $gpoName) -Action {
        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        if (-not $gpo) { $gpo = New-GPO -Name $gpoName }
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -ValueName "AllowBasic" -Type DWord -Value 0
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -ValueName "AllowUnencryptedTraffic" -Type DWord -Value 0
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -ValueName "AllowBasic" -Type DWord -Value 0
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -ValueName "AllowUnencryptedTraffic" -Type DWord -Value 0
        foreach ($ou in $targetOUs) {
            try { New-GPLink -Name $gpoName -Target $ou -ErrorAction Stop | Out-Null } catch { }
        }
    }
}

function Invoke-Remediate14RestrictSamEnumeration {
    Write-Host "`n--- Restreindre l'enumeration distante SAM/SAMR ---" -ForegroundColor Red
    Write-Host "Limite les appels SAMR distants (enumeration des comptes/groupes locaux) aux membres" -ForegroundColor DarkGray
    Write-Host "du groupe Administrateurs locaux uniquement. Risque : casse les outils de supervision/" -ForegroundColor DarkGray
    Write-Host "inventaire qui enumerent les comptes locaux via un compte non-administrateur." -ForegroundColor DarkGray

    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Log "Le module GroupPolicy (RSAT-GPMC) n'est pas installe sur ce poste." -Level ERROR
        return
    }
    Import-Module GroupPolicy -ErrorAction SilentlyContinue

    $targetOUs = @(Select-OUsInteractive -Label "la restriction SAMR" -Verb "CIBLER (lien de la GPO)")
    if ($targetOUs.Count -eq 0) { Write-Log "Aucune UO ciblee, action annulee." -Level WARN; return }

    $gpoName = "SEC - Restriction enumeration SAMR"
    if (-not (Confirm-Action ("Creer/MAJ la GPO '{0}' (SAMR reserve aux administrateurs locaux) et la lier sur {1} UO" -f $gpoName, $targetOUs.Count) -Strong)) { return }

    Invoke-Guarded -Description ("Creation/MAJ de la GPO {0}" -f $gpoName) -Action {
        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        if (-not $gpo) { $gpo = New-GPO -Name $gpoName }
        # SDDL par defaut recommande par Microsoft : seuls les administrateurs locaux (BA) peuvent utiliser SAMR a distance.
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "RestrictRemoteSAM" -Type String -Value "O:BAG:BAD:(A;;RC;;;BA)"
        foreach ($ou in $targetOUs) {
            try { New-GPLink -Name $gpoName -Target $ou -ErrorAction Stop | Out-Null } catch { }
        }
    }
}

function Invoke-Audit14ExposedServices {
    Write-Host "`n--- Audit des ports/services exposes sur les DC ---" -ForegroundColor Magenta
    Write-Host "Liste les ports TCP en ecoute sur chaque DC, pour reperer un service expose de maniere" -ForegroundColor DarkGray
    Write-Host "inattendue (comparer avec ce qui est reellement necessaire : AD DS, DNS, LDAP/S, Kerberos...)." -ForegroundColor DarkGray

    $dcs = Get-DomainControllersList
    if (-not $dcs) { return }
    $wr = Test-DCWinRmConnectivity -ComputerNames $dcs.HostName
    $dcs = @($dcs | Where-Object { $wr.Reachable -contains $_.HostName })
    if (-not $dcs) { Write-Log "Aucun DC joignable via PowerShell Remoting (WinRM), action annulee." -Level ERROR; return }

    $rows = foreach ($dc in $dcs) {
        try {
            Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {
                    $procName = try { (Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName } catch { "?" }
                    [PSCustomObject]@{ DC = $env:COMPUTERNAME; Port = $_.LocalPort; Processus = $procName }
                }
            } -ErrorAction Stop
        } catch {
            Write-Log ("Impossible de lister les ports en ecoute sur {0} : {1}" -f $dc.HostName, $_.Exception.Message) -Level WARN
        }
    }

    $rows = @($rows | Sort-Object DC, Port -Unique)
    $path = Join-Path $Script:LogDir ("Rapport_PortsExposes_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    $rows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Write-Log ("Rapport exporte : {0} ({1} port(s) en ecoute au total, tous DC confondus)." -f $path, $rows.Count) -Level OK
}

# ============================================================
#  SECTION - SAUVEGARDE ET RESILIENCE AD - COMPLEMENT (theme "Sauvegarde et resilience AD")
#  La Corbeille AD est deja couverte (Invoke-SafeEnableRecycleBin). Complements :
#  etat des sauvegardes System State, planification, procedures de restauration.
# ============================================================

function Invoke-Audit17SystemStateBackupStatus {
    Write-Host "`n--- Etat des sauvegardes System State sur les DC ---" -ForegroundColor Magenta
    Write-Host "Interroge le catalogue de sauvegarde local de chaque DC (wbadmin). Necessite la" -ForegroundColor DarkGray
    Write-Host "fonctionnalite Windows Server Backup installee et au moins une sauvegarde deja" -ForegroundColor DarkGray
    Write-Host "effectuee pour retourner un resultat." -ForegroundColor DarkGray

    $dcs = Get-DomainControllersList
    if (-not $dcs) { return }
    $wr = Test-DCWinRmConnectivity -ComputerNames $dcs.HostName
    $dcs = @($dcs | Where-Object { $wr.Reachable -contains $_.HostName })
    if (-not $dcs) { Write-Log "Aucun DC joignable via PowerShell Remoting (WinRM), action annulee." -Level ERROR; return }

    $rows = foreach ($dc in $dcs) {
        try {
            Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                $output = & wbadmin.exe get versions 2>&1 | Out-String
                if ($output -match 'Version identifier:\s*([0-9/:-]+)') {
                    [PSCustomObject]@{ DC = $env:COMPUTERNAME; SauvegardeTrouvee = $true; DerniereVersion = $Matches[1].Trim() }
                } else {
                    [PSCustomObject]@{ DC = $env:COMPUTERNAME; SauvegardeTrouvee = $false; DerniereVersion = $null }
                }
            } -ErrorAction Stop
        } catch {
            Write-Log ("Impossible d'interroger wbadmin sur {0} : {1}" -f $dc.HostName, $_.Exception.Message) -Level WARN
        }
    }

    $rows = @($rows)
    $rows | ForEach-Object {
        $color = if ($_.SauvegardeTrouvee) { 'Green' } else { 'Red' }
        Write-Host ("  - {0} : sauvegarde trouvee={1}, derniere version={2}" -f $_.DC, $_.SauvegardeTrouvee, $_.DerniereVersion) -ForegroundColor $color
    }

    $missing = @($rows | Where-Object { -not $_.SauvegardeTrouvee })
    if ($missing.Count -gt 0) {
        Write-Log ("{0} DC sans sauvegarde System State detectee. Voir la remediation dediee pour en planifier une." -f $missing.Count) -Level WARN
    }

    $path = Join-Path $Script:LogDir ("Rapport_SystemStateBackup_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    $rows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Write-Log ("Rapport exporte : {0}" -f $path) -Level OK
}

function Invoke-Remediate17ScheduleSystemStateBackup {
    Write-Host "`n--- Planifier une sauvegarde System State quotidienne sur un DC ---" -ForegroundColor Red
    Write-Host "Une sauvegarde non testee ne constitue pas une garantie de reprise : testez la" -ForegroundColor DarkGray
    Write-Host "restauration periodiquement (voir la generation de procedures ci-dessous)." -ForegroundColor DarkGray
    Write-Host "Recommandation : cible de sauvegarde INDEPENDANTE du domaine si possible (partage" -ForegroundColor DarkGray
    Write-Host "reseau avec compte dedie, ou disque non joint au domaine) pour resister a une" -ForegroundColor DarkGray
    Write-Host "compromission generalisee (ransomware chiffrant aussi les sauvegardes accessibles)." -ForegroundColor DarkGray

    $dcs = Get-DomainControllersList
    if (-not $dcs) { return }
    Write-Host "Controleurs de domaine disponibles :"
    for ($i = 0; $i -lt $dcs.Count; $i++) { Write-Host ("  [{0}] {1}" -f $i, $dcs[$i].HostName) }
    $idxInput = Read-Host "DC sur lequel planifier la sauvegarde [0]"
    $targetDC = if ($idxInput -match '^\d+$' -and [int]$idxInput -lt $dcs.Count) { $dcs[[int]$idxInput].HostName } else { $dcs[0].HostName }

    $target = Read-Host "Cible de sauvegarde (ex : \\NAS\Backups\DC01 ou E: - lecteur/partage DEDIE, jamais le disque systeme)"
    if ([string]::IsNullOrWhiteSpace($target)) { Write-Log "Cible de sauvegarde vide, action annulee." -Level WARN; return }

    $timeInput = Read-Host "Heure quotidienne de la sauvegarde (format HH:mm) [defaut 01:00]"
    if ([string]::IsNullOrWhiteSpace($timeInput) -or $timeInput -notmatch '^\d{2}:\d{2}$') { $timeInput = "01:00" }

    if (-not (Confirm-Action ("Planifier une sauvegarde System State quotidienne a {0} sur {1}, cible {2}" -f $timeInput, $targetDC, $target) -Strong)) { return }

    Invoke-Guarded -Description ("Installation de Windows Server Backup sur {0} (si absente)" -f $targetDC) -Action {
        Invoke-Command -ComputerName $targetDC -ScriptBlock {
            if (-not (Get-WindowsFeature -Name Windows-Server-Backup -ErrorAction SilentlyContinue).Installed) {
                Install-WindowsFeature -Name Windows-Server-Backup -ErrorAction Stop | Out-Null
            }
        } -ErrorAction Stop
    }

    Invoke-Guarded -Description ("Creation de la tache planifiee de sauvegarde System State sur {0}" -f $targetDC) -Action {
        Invoke-Command -ComputerName $targetDC -ScriptBlock {
            param($backupTarget, $time)
            $taskName = "SEC - Sauvegarde System State"
            $action = New-ScheduledTaskAction -Execute "wbadmin.exe" -Argument "start systemstatebackup -backupTarget:$backupTarget -quiet"
            $trigger = New-ScheduledTaskTrigger -Daily -At $time
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd

            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Sauvegarde System State quotidienne - deployee par le script de remediation AD" | Out-Null
        } -ArgumentList $target, $timeInput -ErrorAction Stop
    }

    Write-Log ("Tache planifiee creee sur {0}. Verifiez que le compte SYSTEM du DC a bien acces en ecriture a la cible '{1}' (partage reseau : autoriser le compte ordinateur {0}`$)." -f $targetDC, $target) -Level WARN
}

function Invoke-Remediate17GenerateRecoveryProcedures {
    Write-Host "`n--- Generer les procedures de recuperation AD (objet / DC / foret) ---" -ForegroundColor Cyan
    Write-Host "Impact : AUCUN. Ecrit uniquement des fichiers texte de procedure dans Logs\Procedures." -ForegroundColor DarkGray
    Write-Host "Une sauvegarde non testee ne constitue pas une garantie de reprise : ces procedures sont" -ForegroundColor DarkGray
    Write-Host "a tester en conditions reelles au moins une fois (environnement de test/labo)." -ForegroundColor DarkGray

    if (-not (Confirm-Action "Generer/mettre a jour les fichiers de procedure de recuperation")) { return }

    $dir = Join-Path $Script:LogDir "Procedures"

    $objectRecovery = @'
PROCEDURE - RECUPERATION D'UN OBJET AD SUPPRIME PAR ERREUR
============================================================
Prerequis : Corbeille Active Directory activee (menu Sauvegarde et resilience AD > 1).

1. Identifier l'objet supprime :
   Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects -Properties * |
     Where-Object { $_.Name -like '*<nom recherche>*' }

2. Restaurer l'objet (et ses attributs) :
   Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects |
     Where-Object { $_.Name -like '*<nom recherche>*' } |
     Restore-ADObject

3. Verifier l'objet restaure (appartenances de groupe, attributs) et corriger si necessaire.

Si la Corbeille AD n'etait PAS activee au moment de la suppression : restauration
authoritative necessaire depuis une sauvegarde System State (voir procedure DC ci-dessous,
avec ntdsutil "authoritative restore" cible sur le sous-arbre concerne uniquement).
'@

    $dcRecovery = @'
PROCEDURE - RECUPERATION D'UN CONTROLEUR DE DOMAINE
============================================================
Cas 1 : le DC est reparable (materiel/OS intact, AD corrompu ou horloge de replication desynchronisee)
  1. Demarrer en mode DSRM (Directory Services Restore Mode) : bcdedit /set safeboot dsrepair, redemarrer.
  2. Restaurer le System State depuis la derniere sauvegarde saine :
     wbadmin start systemstaterecovery -version:<identifiant version> -backupTarget:<cible>
  3. Si restauration AUTHORITATIVE necessaire (objets a re-propager comme faisant foi) :
     ntdsutil
       activate instance ntds
       authoritative restore
         restore subtree "<DN de l'objet ou sous-arbre>"
  4. Redemarrer normalement (bcdedit /deletevalue safeboot), verifier la replication
     (repadmin /replsummary, repadmin /showrepl).

Cas 2 : le DC est irrecuperable (materiel detruit, corruption totale)
  1. Nettoyer les metadonnees AD residuelles du DC mort :
     ntdsutil -> metadata cleanup -> remove selected server
     (ou nettoyage manuel des objets NTDS Settings, DNS, sites/services)
  2. Retirer/recreer les enregistrements DNS obsoletes du DC.
  3. Promouvoir un nouveau DC (meme nom ou nom different) pour retablir le nombre de DC prevu.

IMPORTANT : ne jamais restaurer un DC a partir d'une sauvegarde plus ancienne que la duree de
vie maximale du "tombstone lifetime" (par defaut 60 jours) sans expertise prealable (risque de
"USN rollback" et de desynchronisation de la replication).
'@

    $forestRecovery = @'
PROCEDURE (RESUME) - RECONSTRUCTION D'UNE FORET ACTIVE DIRECTORY
============================================================
A utiliser en dernier recours (compromission generalisee, perte de tous les DC d'un domaine).
Suivre le "AD Forest Recovery Guide" de Microsoft pour le detail complet ; grandes etapes :

1. Isoler completement l'environnement compromis (reseau deconnecte) avant toute action.
2. Identifier le DC qui detenait le role PDC Emulator du domaine racine de la foret au moment
   de la derniere sauvegarde saine connue.
3. Restaurer ce DC en PREMIER, en mode non-connecte au reseau, via restauration System State
   authoritative complete (voir procedure DC ci-dessus).
4. Reinitialiser DEUX FOIS le mot de passe krbtgt de CHAQUE domaine de la foret (voir menu
   Kerberos et delegations) une fois le premier DC restaure et stable, AVANT de reconnecter
   le reseau.
5. Reconstruire/restaurer les autres DC un par un (restauration System State ou repromotion
   propre apres nettoyage des metadonnees), en verifiant la replication a chaque etape.
6. Ne reconnecter le reseau de production qu'apres validation complete (replication saine,
   SYSVOL/NETLOGON coherents, rotation krbtgt effectuee, comptes a privileges revus).
7. Effectuer un nouvel audit PingCastle complet apres reconstruction (outil de comparaison
   avant/apres dedie, hors perimetre de ce script).
'@

    Invoke-Guarded -Description "Generation des procedures de recuperation" -Action {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
        Set-Content -Path (Join-Path $dir "Recuperation_Objet.txt") -Value $objectRecovery -Encoding UTF8
        Set-Content -Path (Join-Path $dir "Recuperation_DC.txt") -Value $dcRecovery -Encoding UTF8
        Set-Content -Path (Join-Path $dir "Reconstruction_Foret.txt") -Value $forestRecovery -Encoding UTF8
    }

    Write-Log ("Procedures generees dans {0}." -f $dir) -Level OK
}

# ============================================================
#  SECTION - OBSOLESCENCE (theme "Obsolescence" du menu)
#  Inventaire des composants obsoletes/non supportes (OS, protocoles legacy) et
#  generation d'un plan de traitement consolide. Les migrations lourdes elles-
#  memes restent hors perimetre (projet separe, comme indique par le cahier des
#  charges).
# ============================================================

$Script:KnownEolOsPatterns = @(
    "Windows Server 2003", "Windows Server 2008", "Windows Server 2012",
    "Windows XP", "Windows Vista", "Windows 7", "Windows 8"
)

function Invoke-Audit18UnsupportedOS {
    Write-Host "`n--- Inventaire des systemes d'exploitation non/bientot non supportes ---" -ForegroundColor Magenta
    Write-Host "Liste de reference volontairement large et a maintenir a jour (Windows Server 2012/2012" -ForegroundColor DarkGray
    Write-Host "R2 et Windows 8.1 sont deja en fin de support standard) : verifiez la date de fin de" -ForegroundColor DarkGray
    Write-Host "support exacte de chaque version aupres de Microsoft avant d'agir." -ForegroundColor DarkGray

    $computers = @(Get-ADComputer -Filter 'Enabled -eq $true' -Properties OperatingSystem, OperatingSystemVersion, DNSHostName)
    $flagged = @($computers | Where-Object {
        $os = $_.OperatingSystem
        if (-not $os) { return $false }
        foreach ($pattern in $Script:KnownEolOsPatterns) { if ($os -like "*$pattern*") { return $true } }
        return $false
    })
    $unknown = @($computers | Where-Object { -not $_.OperatingSystem })

    Write-Host ("{0} ordinateur(s) actif(s) sur un OS potentiellement obsolete/EOL." -f $flagged.Count) -ForegroundColor Yellow
    $flagged | Select-Object -First 20 | ForEach-Object { Write-Host ("  - {0} : {1}" -f $_.Name, $_.OperatingSystem) }
    if ($flagged.Count -gt 20) { Write-Host "  - ... (liste tronquee, voir le CSV exporte)" }
    if ($unknown.Count -gt 0) { Write-Log ("{0} ordinateur(s) sans attribut OperatingSystem renseigne (compte machine jamais authentifie ou obsolete)." -f $unknown.Count) -Level WARN }

    $path = Join-Path $Script:LogDir ("Rapport_OS_Obsoletes_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    $flagged | Select-Object Name, DNSHostName, OperatingSystem, OperatingSystemVersion | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Write-Log ("Rapport exporte : {0}" -f $path) -Level OK
}

function Invoke-Audit18LegacyProtocolsOnComputers {
    Write-Host "`n--- Protocoles obsoletes actifs sur des postes/serveurs choisis (SMBv1, TLS 1.0/1.1) ---" -ForegroundColor Magenta
    Write-Host "Necessite PowerShell Remoting (WinRM) actif sur les machines ciblees." -ForegroundColor DarkGray

    $targetOU = @(Select-OUsInteractive -Label "l'audit des protocoles obsoletes" -Verb "CIBLER")
    if ($targetOU.Count -eq 0) { Write-Log "Aucune UO ciblee, action annulee." -Level WARN; return }

    $computers = @(foreach ($ou in $targetOU) { Get-ADComputer -SearchBase $ou -Filter 'Enabled -eq $true' -Properties DNSHostName })
    if ($computers.Count -eq 0) { Write-Log "Aucun ordinateur actif trouve dans les UO ciblees." -Level WARN; return }
    $names = @($computers | ForEach-Object { if ($_.DNSHostName) { $_.DNSHostName } else { $_.Name } })
    $wr = Test-DCWinRmConnectivity -ComputerNames $names
    if ($wr.Reachable.Count -eq 0) { Write-Log "Aucune machine joignable via PowerShell Remoting (WinRM) parmi celles ciblees." -Level ERROR; return }

    $rows = foreach ($name in $wr.Reachable) {
        try {
            Invoke-Command -ComputerName $name -ScriptBlock {
                $smb1 = $false
                try { $smb1 = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch { }

                $tlsWeak = $false
                foreach ($proto in @('TLS 1.0','TLS 1.1')) {
                    foreach ($role in @('Client','Server')) {
                        $p = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\$role"
                        if (Test-Path $p) {
                            $enabled = (Get-ItemProperty -Path $p -Name Enabled -ErrorAction SilentlyContinue).Enabled
                            $disabledByDefault = (Get-ItemProperty -Path $p -Name DisabledByDefault -ErrorAction SilentlyContinue).DisabledByDefault
                            if ($enabled -ne 0 -and $disabledByDefault -ne 1) { $tlsWeak = $true }
                        } else {
                            # Absence de cle = comportement par defaut de l'OS (TLS 1.0/1.1 souvent
                            # encore actif par defaut sur les OS anterieurs a Windows Server 2022).
                            $tlsWeak = $true
                        }
                    }
                }

                [PSCustomObject]@{ Machine = $env:COMPUTERNAME; SMB1Actif = [bool]$smb1; TLS10_11Actif = $tlsWeak }
            } -ErrorAction Stop
        } catch {
            Write-Log ("Impossible d'interroger {0} : {1}" -f $name, $_.Exception.Message) -Level WARN
        }
    }

    $rows = @($rows)
    $rows | ForEach-Object { Write-Host ("  - {0} : SMBv1={1}, TLS 1.0/1.1={2}" -f $_.Machine, $_.SMB1Actif, $_.TLS10_11Actif) -ForegroundColor Yellow }

    $path = Join-Path $Script:LogDir ("Rapport_ProtocolesObsoletes_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    $rows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Write-Log ("Rapport exporte : {0}" -f $path) -Level OK
}

function Invoke-Remediate18GenerateTreatmentPlan {
    Write-Host "`n--- Generer le plan de traitement de l'obsolescence (consolide) ---" -ForegroundColor Cyan
    Write-Host "Impact : AUCUN. Reexecute une partie des audits d'obsolescence de ce script (OS, comptes" -ForegroundColor DarkGray
    Write-Host "de service AVEC SPN en RC4/DES) et consolide le resultat en un seul CSV categorise, pour" -ForegroundColor DarkGray
    Write-Host "prioriser les migrations (elles-memes hors perimetre de ce script - a traiter en projet dedie)." -ForegroundColor DarkGray
    Write-Host "Ne reprend PAS les comptes de service SANS SPN ajoutes via une OU dans le theme 'Comptes de" -ForegroundColor DarkGray
    Write-Host "service' (choix d'UO non rejoue ici) : consultez aussi l'audit dedie pour la liste complete." -ForegroundColor DarkGray

    if (-not (Confirm-Action "Lancer la consolidation du plan de traitement de l'obsolescence")) { return }

    $rows = @()

    $computers = @(Get-ADComputer -Filter 'Enabled -eq $true' -Properties OperatingSystem)
    foreach ($c in $computers) {
        $os = $c.OperatingSystem
        if (-not $os) { continue }
        foreach ($pattern in $Script:KnownEolOsPatterns) {
            if ($os -like "*$pattern*") {
                $rows += [PSCustomObject]@{ Categorie = 'OS obsolete'; Element = $c.Name; Detail = $os }
                break
            }
        }
    }

    try {
        $weakAccounts = @(Get-ADUser -LDAPFilter "(servicePrincipalName=*)" -Properties 'msDS-SupportedEncryptionTypes' |
            Where-Object { $val = $_.'msDS-SupportedEncryptionTypes'; -not $val -or (-not ($val -band 0x8) -and -not ($val -band 0x10)) })
        foreach ($a in $weakAccounts) {
            $rows += [PSCustomObject]@{ Categorie = 'Compte de service avec SPN sans AES'; Element = $a.SamAccountName; Detail = (Get-SupportedEncryptionTypesLabel -Value $a.'msDS-SupportedEncryptionTypes') }
        }
    } catch { }

    $path = Join-Path $Script:LogDir ("Plan_Traitement_Obsolescence_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    $rows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Write-Log ("Plan de traitement exporte : {0} ({1} constat(s)). Completez-le manuellement avec les resultats des audits SMBv1/TLS/NTLMv1 (necessitant un choix d'UO ou un delai d'observation, non rejoues automatiquement ici)." -f $path, $rows.Count) -Level OK
}

# ============================================================
#  SECTION - JOURNALISATION ET DETECTION (theme "Journalisation et detection")
#  L'audit avance sur les DC et la journalisation PowerShell (deja existants,
#  ex-theme Controleurs de domaine) rejoignent ce theme dedie. Complements :
#  audit SACL sur les objets sensibles, redirection des journaux vers un
#  collecteur SIEM (Windows Event Forwarding).
# ============================================================

function Invoke-Audit19ObjectAuditingStatus {
    Write-Host "`n--- Audit du SACL (auditing) sur les objets AD sensibles ---" -ForegroundColor Magenta
    Write-Host "Verifie si un audit 'Ecriture de toutes les proprietes' (Succes) existe deja sur la" -ForegroundColor DarkGray
    Write-Host "racine du domaine et sur AdminSDHolder - necessaire, en plus de la sous-categorie" -ForegroundColor DarkGray
    Write-Host "'Modifications du service d'annuaire' (auditpol), pour generer les evenements 5136." -ForegroundColor DarkGray

    try {
        $domainDN = (Get-ADDomain).DistinguishedName
        $adminSDHolderDN = "CN=AdminSDHolder,CN=System,$domainDN"
    } catch {
        Write-Log ("Impossible de lire le domaine : {0}" -f $_.Exception.Message) -Level ERROR
        return
    }

    foreach ($dn in @($domainDN, $adminSDHolderDN)) {
        try {
            $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dn")
            $hasAudit = $entry.ObjectSecurity.GetAuditRules($true, $true, [System.Security.Principal.SecurityIdentifier]) |
                Where-Object { $_.AuditFlags -match 'Success' -and $_.ActiveDirectoryRights -match 'WriteProperty|GenericWrite|GenericAll' }
            $color = if ($hasAudit) { 'Green' } else { 'Yellow' }
            Write-Host ("  - {0} : audit ecriture deja present = {1}" -f $dn, [bool]$hasAudit) -ForegroundColor $color
        } catch {
            Write-Log ("Impossible de lire le SACL de {0} : {1}" -f $dn, $_.Exception.Message) -Level WARN
        }
    }
}

function Invoke-Remediate19ConfigureObjectAuditing {
    Write-Host "`n--- Configurer l'audit SACL sur les objets AD sensibles ---" -ForegroundColor Red
    Write-Host "Ajoute une regle d'audit 'Ecriture de toutes les proprietes' (Succes, tous les" -ForegroundColor DarkGray
    Write-Host "descendants) pour 'Tout le monde' sur la racine du domaine et sur AdminSDHolder." -ForegroundColor DarkGray
    Write-Host "Risque : augmente le volume du journal Securite des DC (deja pris en compte par" -ForegroundColor DarkGray
    Write-Host "         l'audit avance, mais a surveiller si l'espace disque est limite)." -ForegroundColor DarkGray
    Write-Host "Additif uniquement : n'enleve aucune regle d'audit existante." -ForegroundColor DarkGray

    try {
        $domainDN = (Get-ADDomain).DistinguishedName
        $adminSDHolderDN = "CN=AdminSDHolder,CN=System,$domainDN"
    } catch {
        Write-Log ("Impossible de lire le domaine : {0}" -f $_.Exception.Message) -Level ERROR
        return
    }

    if (-not (Confirm-Action "Ajouter l'audit d'ecriture (Succes) sur la racine du domaine et AdminSDHolder" -Strong)) { return }

    foreach ($dn in @($domainDN, $adminSDHolderDN)) {
        Invoke-Guarded -Description ("Ajout de la regle d'audit sur {0}" -f $dn) -Action {
            $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dn")
            $identity = New-Object System.Security.Principal.NTAccount("Everyone")
            $auditRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
                $identity,
                [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                [System.Security.AccessControl.AuditFlags]::Success,
                [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
            )
            $entry.ObjectSecurity.AddAuditRule($auditRule)
            $entry.CommitChanges()
        }
    }
}

function Invoke-Remediate19ConfigureEventForwarding {
    Write-Host "`n--- Configurer la redirection des journaux vers un collecteur (SIEM / WEF) ---" -ForegroundColor Red
    Write-Host "Pousse le parametre 'Configurer le gestionnaire d'abonnements cible' (Windows Event" -ForegroundColor DarkGray
    Write-Host "Forwarding) vers les DC, pour qu'ils pointent vers un collecteur WEF existant." -ForegroundColor DarkGray
    Write-Host "Prerequis : le collecteur WEF/SIEM (souscription, certificats si HTTPS) doit deja" -ForegroundColor DarkGray
    Write-Host "exister cote client - cette action configure uniquement le POINTAGE cote DC." -ForegroundColor DarkGray

    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Log "Le module GroupPolicy (RSAT-GPMC) n'est pas installe sur ce poste." -Level ERROR
        return
    }
    Import-Module GroupPolicy -ErrorAction SilentlyContinue

    $collector = Read-Host "URL du collecteur WEF/SIEM (ex : https://collecteur.domaine.local:5986/wsman/SubscriptionManager/WEC)"
    if ([string]::IsNullOrWhiteSpace($collector)) { Write-Log "URL vide, action annulee." -Level WARN; return }

    $ouDCs = "OU=Domain Controllers,$((Get-ADDomain).DistinguishedName)"
    $gpoName = "SEC - Redirection journaux (WEF)"
    if (-not (Confirm-Action ("Creer/lier la GPO '{0}' sur l'OU Domain Controllers (collecteur : {1})" -f $gpoName, $collector) -Strong)) { return }

    Invoke-Guarded -Description ("Creation/MAJ de la GPO {0}" -f $gpoName) -Action {
        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        if (-not $gpo) { $gpo = New-GPO -Name $gpoName }
        $value = "Server=$collector,Refresh=60"
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager" -ValueName "1" -Type String -Value $value
        try { New-GPLink -Name $gpoName -Target $ouDCs -ErrorAction Stop | Out-Null } catch { }
    }
    Write-Log "GPO liee sur l'OU Domain Controllers. Le service WinRM (client) doit etre actif sur les DC pour que la remontee fonctionne (voir menu Controleurs de domaine)." -Level OK
}

# ============================================================
#  SECTION - CONTROLE FINAL (theme "Controle final" du menu)
#  Rejoue les audits cles de plusieurs themes en une seule passe pour une revue
#  de fin de mission. Ne remplace PAS l'outil separe de comparaison PingCastle
#  avant/apres. Le registre des exceptions documente les risques acceptes/
#  compenses qui ne sont pas corriges par ce script.
# ============================================================

function Invoke-Audit20FinalControlReport {
    Write-Host "`n--- Controle final consolide ---" -ForegroundColor Magenta
    Write-Host "Rejoue une selection d'audits cles (lecture seule) de plusieurs themes deja traites par" -ForegroundColor DarkGray
    Write-Host "ce script, y compris SMB/NTLM/Kerberos/LDAP/LAPS/GPO comme demande par le controle final." -ForegroundColor DarkGray
    Write-Host "Chaque audit exporte deja son propre CSV horodate dans Logs\ - ce controle final se" -ForegroundColor DarkGray
    Write-Host "contente de les enchainer. L'etape NTLMv1/LM peut etre longue (lecture du journal Securite)." -ForegroundColor DarkGray
    Write-Host "Ne remplace pas le rapport PingCastle avant/apres (outil separe)." -ForegroundColor DarkGray

    if (-not (Confirm-Action "Lancer le controle final consolide (peut prendre plusieurs minutes, plus si NTLMv1/LM est inclus)")) { return }

    Write-Host "`n[1/8] Comptes a privileges..." -ForegroundColor DarkCyan
    Invoke-ReportPrivilegedGroups

    Write-Host "`n[2/8] Delegations Kerberos..." -ForegroundColor DarkCyan
    Invoke-RiskyReportDelegations

    Write-Host "`n[3/8] Mots de passe n'expirant jamais..." -ForegroundColor DarkCyan
    Invoke-ReportPasswordNeverExpires

    Write-Host "`n[4/8] Signature SMB sur les DC..." -ForegroundColor DarkCyan
    Invoke-Audit7SmbSigningStatus

    Write-Host "`n[5/8] Certificats LDAPS..." -ForegroundColor DarkCyan
    Invoke-Audit8LdapsCertificates

    Write-Host "`n[6/8] Deploiement Windows LAPS..." -ForegroundColor DarkCyan
    Invoke-Audit10LapsDeployment

    Write-Host "`n[7/8] Socle GPO-SEC-* et sauvegardes de GPO..." -ForegroundColor DarkCyan
    Invoke-Audit12GpoBaselineStatus

    Write-Host "`n[8/8] Usage NTLMv1/LM (peut etre long)..." -ForegroundColor DarkCyan
    if ((Read-Host "Inclure l'analyse NTLMv1/LM (lecture du journal Securite, potentiellement longue) ? (O/N)") -match '^[oOyY]') {
        Invoke-ReportNtlmV1Usage
    } else {
        Write-Log "Etape NTLMv1/LM ignoree. Lancez-la separement depuis le menu NTLM / LM si necessaire." -Level INFO
    }

    Write-Log "Controle final consolide termine. Consultez les rapports CSV individuels generes ci-dessus dans Logs\." -Level OK
    Write-Log "Pensez a completer/consulter le registre des exceptions pour tout constat accepte sans correction (menu Controle final > 2)." -Level INFO
}

function Invoke-Remediate20InitExceptionsRegister {
    Write-Host "`n--- Initialiser/completer le registre des exceptions ---" -ForegroundColor Cyan
    Write-Host "Impact : AUCUN sur l'AD. Cree un fichier CSV pour documenter tout constat accepte sans" -ForegroundColor DarkGray
    Write-Host "correction (risque residuel assume, mesure compensatoire en place, ou contrainte" -ForegroundColor DarkGray
    Write-Host "metier/technique bloquant la remediation)." -ForegroundColor DarkGray

    $path = Join-Path $Script:LogDir "Registre_Exceptions.csv"

    if (Test-Path $path) {
        Write-Log ("Le registre des exceptions existe deja : {0}" -f $path) -Level OK
        return
    }

    if (-not (Confirm-Action ("Creer le registre des exceptions : {0}" -f $path))) { return }
    Invoke-Guarded -Description "Creation du registre des exceptions" -Action {
        [PSCustomObject]@{
            Date         = (Get-Date -Format "dd/MM/yyyy")
            Constat      = "<exemple : compte de service X toujours en RC4>"
            Raison       = "<exemple : application legacy non compatible AES>"
            Compensation = "<exemple : compte isole sur VLAN dedie, surveillance renforcee>"
            Responsable  = "<nom/role>"
            DateRevision = "<date de prochaine revue>"
        } | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    }

    Write-Log "Ajoutez une ligne par exception directement dans ce fichier CSV (Excel ou un editeur de texte) au fil de la mission." -Level INFO
}

# ============================================================
#  SECTION 3 - RAPPORTS TRANSVERSES (lecture seule, aucune modification)
#  Rapports specifiques a un theme (privileges, delegations, NTLMv1...) : voir
#  les fonctions Invoke-Report*/Invoke-Audit* dans les sections precedentes,
#  rattachees a leur menu thematique.
# ============================================================

function Invoke-ReportInactiveAccounts {
    Write-Host "`n--- Rapport : comptes inactifs ---" -ForegroundColor Magenta
    $thresholds = Read-InactivityThresholds -DefaultUserDays 180 -DefaultComputerDays 90
    $cutoffUsers = (Get-Date).AddDays(-$thresholds.UserDays)
    $cutoffComputers = (Get-Date).AddDays(-$thresholds.ComputerDays)

    $users = @(Get-ADUser -Filter { LastLogonTimestamp -lt $cutoffUsers } -Properties LastLogonTimestamp, Enabled)
    $computers = @(Get-ADComputer -Filter { LastLogonTimestamp -lt $cutoffComputers } -Properties LastLogonTimestamp, Enabled)

    $path = Join-Path $Script:LogDir ("Rapport_ComptesInactifs_U{0}j_C{1}j_{2}.csv" -f $thresholds.UserDays, $thresholds.ComputerDays, (Get-Date -Format "yyyyMMdd_HHmmss"))
    @($users | Select-Object SamAccountName, Enabled, @{N='Type';E={'User'}}, @{N='DerniereConnexion';E={ if($_.LastLogonTimestamp){[DateTime]::FromFileTime($_.LastLogonTimestamp)} }}) +
    @($computers | Select-Object SamAccountName, Enabled, @{N='Type';E={'Computer'}}, @{N='DerniereConnexion';E={ if($_.LastLogonTimestamp){[DateTime]::FromFileTime($_.LastLogonTimestamp)} }}) |
        Export-Csv -Path $path -NoTypeInformation -Encoding UTF8

    Write-Log ("Rapport exporte : {0} ({1} utilisateurs > {2}j, {3} ordinateurs > {4}j)" -f $path, $users.Count, $thresholds.UserDays, $computers.Count, $thresholds.ComputerDays) -Level OK
}

function Invoke-ReportPasswordNeverExpires {
    Write-Host "`n--- Rapport : comptes avec mot de passe n'expirant jamais ---" -ForegroundColor Magenta
    $accounts = @(Get-ADUser -Filter 'PasswordNeverExpires -eq $true' -Properties PasswordNeverExpires, PasswordLastSet, Enabled)
    $path = Join-Path $Script:LogDir ("Rapport_PwdNeverExpires_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    $accounts | Select-Object SamAccountName, Enabled, PasswordLastSet | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Write-Log ("Rapport exporte : {0} ({1} comptes)" -f $path, $accounts.Count) -Level OK
}

function Invoke-ReportPrivilegedGroups {
    Write-Host "`n--- Rapport : membres des groupes a privileges ---" -ForegroundColor Magenta
    $groups = @("Domain Admins","Enterprise Admins","Schema Admins","Administrators","Account Operators","Backup Operators","Server Operators","Print Operators","Group Policy Creator Owners","Protected Users")
    $rows = foreach ($g in $groups) {
        try {
            Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop | ForEach-Object {
                [PSCustomObject]@{ Groupe = $g; Compte = $_.SamAccountName; Type = $_.objectClass }
            }
        } catch { }
    }
    $path = Join-Path $Script:LogDir ("Rapport_GroupesPrivilegies_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    $rows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Write-Log ("Rapport exporte : {0} ({1} lignes)" -f $path, $rows.Count) -Level OK
}

function Invoke-ReportDCHotfixes {
    Write-Host "`n--- Rapport : hotfix installes sur les DC ---" -ForegroundColor Magenta
    $dcs = Get-DomainControllersList
    $rows = foreach ($dc in $dcs) {
        try {
            Get-HotFix -ComputerName $dc.HostName -ErrorAction Stop | ForEach-Object {
                [PSCustomObject]@{ DC = $dc.HostName; HotFixID = $_.HotFixID; InstalledOn = $_.InstalledOn }
            }
        } catch {
            Write-Log ("Impossible de lire les hotfix de {0} : {1}" -f $dc.HostName, $_.Exception.Message) -Level WARN
        }
    }
    $path = Join-Path $Script:LogDir ("Rapport_Hotfix_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    $rows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Write-Log ("Rapport exporte : {0}" -f $path) -Level OK
}

function Invoke-ReportNtlmV1Usage {
    Write-Host "`n--- Rapport : usage NTLMv1/LM detecte (journal Securite des DC) ---" -ForegroundColor Magenta
    Write-Host "Necessite l'audit NTLM prealablement active (menu NTLM / LM > 1) ainsi" -ForegroundColor DarkGray
    Write-Host "que l'audit des connexions actif sur les DC (menu Journalisation et detection > 2). Sans ces deux" -ForegroundColor DarkGray
    Write-Host "prerequis actifs depuis un moment, ce rapport reviendra probablement vide." -ForegroundColor DarkGray
    Write-Host "Analyse potentiellement longue sur un DC charge (lecture du journal Securite)." -ForegroundColor Yellow

    $daysInput = Read-Host "Nombre de jours a analyser en arriere [defaut 7]"
    if ([string]::IsNullOrWhiteSpace($daysInput) -or $daysInput -notmatch '^\d+$') { $daysInput = 7 }
    $days = [int]$daysInput

    $dcs = Get-DomainControllersList
    if (-not $dcs) { return }

    $allRows = @()
    foreach ($dc in $dcs) {
        Write-Host ("Analyse de {0}..." -f $dc.HostName) -ForegroundColor DarkGray
        try {
            $rows = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                param($sinceDays)
                # Filtre applique cote serveur (efficace) sur les evenements de logon NTLMv1/LM
                # uniquement. On lit les champs XML (Name=...) et non le texte du message, qui
                # est localise selon la langue de l'OS (memes precautions que pour auditpol).
                $ms = $sinceDays * 86400000
                $xpath = "*[System[(EventID=4624 or EventID=4625) and TimeCreated[timediff(@SystemTime) <= $ms]]] and *[EventData[Data[@Name='LmPackageName']='NTLM V1' or Data[@Name='LmPackageName']='LM']]"
                try {
                    $events = Get-WinEvent -LogName Security -FilterXPath $xpath -ErrorAction Stop
                } catch {
                    return @()
                }
                foreach ($e in $events) {
                    $data = ([xml]$e.ToXml()).Event.EventData.Data
                    [PSCustomObject]@{
                        DC          = $env:COMPUTERNAME
                        TimeCreated = $e.TimeCreated
                        EventId     = $e.Id
                        Version     = ($data | Where-Object { $_.Name -eq 'LmPackageName' }).'#text'
                        Account     = ($data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                        Workstation = ($data | Where-Object { $_.Name -eq 'WorkstationName' }).'#text'
                        SourceIP    = ($data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
                    }
                }
            } -ArgumentList $days -ErrorAction Stop
            $allRows += @($rows)
        } catch {
            Write-Log ("Impossible d'analyser le journal Securite de {0} : {1}" -f $dc.HostName, $_.Exception.Message) -Level WARN
        }
    }

    $allRows = @($allRows)
    if ($allRows.Count -eq 0) {
        Write-Log "Aucune authentification NTLMv1/LM detectee sur la periode (ou audit non actif depuis assez longtemps)." -Level OK
        return
    }

    $path = Join-Path $Script:LogDir ("Rapport_NTLMv1_LM_{0}j_{1}.csv" -f $days, (Get-Date -Format "yyyyMMdd_HHmmss"))
    $allRows | Sort-Object TimeCreated -Descending | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8

    $byAccount = $allRows | Group-Object Account | Sort-Object Count -Descending
    Write-Host ("{0} evenement(s) NTLMv1/LM detecte(s) sur {1} jour(s). Comptes/postes les plus concernes :" -f $allRows.Count, $days) -ForegroundColor Yellow
    $byAccount | Select-Object -First 15 | ForEach-Object { Write-Host ("  - {0} : {1} evenement(s)" -f $_.Name, $_.Count) }

    Write-Log ("Rapport exporte : {0}" -f $path) -Level OK
    Write-Log "Validez ces comptes/postes AVANT d'appliquer l'action 'Desactiver NTLMv1/LM' (menu NTLM / LM > 3)." -Level WARN
}

function Invoke-ReportAll {
    Invoke-ReportInactiveAccounts
    Invoke-ReportPasswordNeverExpires
    Invoke-ReportPrivilegedGroups
    Invoke-ReportDCHotfixes
    Write-Log ("Tous les rapports ont ete exportes dans : {0}" -f $Script:LogDir) -Level OK
}

# ============================================================
#  SECTION 4 - AUTOMATISATION (tache planifiee de desactivation)
# ============================================================

function Get-DisableByDateScheduledScriptContent {
    <#
        Genere le contenu du script autonome deploye sur le serveur cible et
        execute par la tache planifiee. Les parametres (seuils, exclusions) sont
        figes au moment de la configuration : pour les changer, relancer la
        configuration (menu Automatisation > 1), qui remplace le script deploye.
        Ne depend d'aucune variable/fonction du script menu (execution differee
        et decouplee), a l'image du script de rotation KRBTGT.
    #>
    param(
        [int]$DaysUsers,
        [int]$DaysComputers,
        [bool]$ApplyUsers,
        [bool]$ApplyComputers,
        [string[]]$ExcludedOUsUsers,
        [string[]]$ExcludedOUsComputers,
        [string[]]$ExcludedGroups,
        [string]$DisableUserOUName,
        [string]$DisableComputerOUName
    )

    $ousUsersLiteral = ($ExcludedOUsUsers | ForEach-Object { "'{0}'" -f ($_ -replace "'", "''") }) -join ', '
    $ousComputersLiteral = ($ExcludedOUsComputers | ForEach-Object { "'{0}'" -f ($_ -replace "'", "''") }) -join ', '
    $groupsLiteral = ($ExcludedGroups | ForEach-Object { "'{0}'" -f ($_ -replace "'", "''") }) -join ', '

    $header = @"
# Parametres generes par le menu Automatisation le $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
`$DaysUsers = $DaysUsers
`$DaysComputers = $DaysComputers
`$ApplyUsers = `$$ApplyUsers
`$ApplyComputers = `$$ApplyComputers
`$ExcludedOUsUsers = @($ousUsersLiteral)
`$ExcludedOUsComputers = @($ousComputersLiteral)
`$ExcludedGroups = @($groupsLiteral)
`$DisableUserOUName = '$DisableUserOUName'
`$DisableComputerOUName = '$DisableComputerOUName'
"@

    $body = @'
# Disable-ByDate.ps1
# Deploye et execute automatiquement par la tache planifiee "SEC - Desactivation Auto (date/anciennete)".
# Ne PAS executer manuellement sans avoir revu les parametres et exclusions ci-dessus.

$logFile = "C:\ADHC-Scripts\Disable-ByDate.log"

function Write-DisLog {
    param([string]$Message)
    $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Add-Content -Path $logFile -Value $line -Encoding UTF8
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("ADHC-AutoDisable")) {
            New-EventLog -LogName Application -Source "ADHC-AutoDisable" -ErrorAction SilentlyContinue
        }
        Write-EventLog -LogName Application -Source "ADHC-AutoDisable" -EventId 2000 -EntryType Information -Message $Message -ErrorAction SilentlyContinue
    } catch { }
}

function Test-UnderExcludedOU {
    param([string]$DN, [string[]]$OUList)
    foreach ($ou in $OUList) {
        if ([string]::IsNullOrWhiteSpace($ou)) { continue }
        if ($DN -like "*,$ou") { return $true }
    }
    return $false
}

function Add-DisabledMarkerToDescription {
    param([Parameter(Mandatory)][string]$Identity)
    $marker = "Desactive le : {0}" -f (Get-Date -Format "dd/MM/yyyy")
    $obj = Get-ADObject -Identity $Identity -Properties Description
    $newDescription = if ([string]::IsNullOrWhiteSpace($obj.Description)) { $marker } else { "$($obj.Description) | $marker" }
    Set-ADObject -Identity $Identity -Replace @{ Description = $newDescription }
}

Import-Module ActiveDirectory -ErrorAction Stop
Write-DisLog "Debut de l'execution planifiee (utilisateurs > $DaysUsers j / postes > $DaysComputers j)."

try {
    $domain = Get-ADDomain -ErrorAction Stop
} catch {
    Write-DisLog "Impossible de contacter le domaine. Execution annulee."
    exit 1
}
$domainDN = $domain.DistinguishedName
$domainSidStr = $domain.DomainSID.Value

# --- Garde-fous non desactivables : comptes/objets systeme toujours proteges ---
$protectedSids = New-Object System.Collections.Generic.HashSet[string]
foreach ($rid in 500, 501, 502) {
    try {
        $obj = Get-ADObject -LDAPFilter "(objectSid=$domainSidStr-$rid)" -ErrorAction SilentlyContinue
        if ($obj) { [void]$protectedSids.Add($obj.ObjectSID.Value) }
    } catch { }
}
try {
    $selfSid = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    [void]$protectedSids.Add($selfSid)
} catch { }

foreach ($g in $ExcludedGroups) {
    try {
        Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop | ForEach-Object { [void]$protectedSids.Add($_.SID.Value) }
    } catch {
        Write-DisLog "Groupe d'exclusion '$g' introuvable ou inaccessible - ignore."
    }
}

$protectedComputerDNs = New-Object System.Collections.Generic.HashSet[string]
try {
    Get-ADDomainController -Filter * -ErrorAction Stop | ForEach-Object {
        try { [void]$protectedComputerDNs.Add((Get-ADComputer -Identity $_.Name).DistinguishedName) } catch { }
    }
} catch { }

$disableUserOUDN = "OU=$DisableUserOUName,$domainDN"
$disableComputerOUDN = "OU=$DisableComputerOUName,$domainDN"

if ($ApplyUsers) {
    try {
        if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$DisableUserOUName'" -SearchBase $domainDN -ErrorAction SilentlyContinue)) {
            New-ADOrganizationalUnit -Name $DisableUserOUName -Path $domainDN -ProtectedFromAccidentalDeletion $true
        }

        $cutoffUsers = (Get-Date).AddDays(-$DaysUsers)
        $candidates = @(Get-ADUser -Filter { (Enabled -eq $true) -and (LastLogonTimestamp -lt $cutoffUsers) } -Properties LastLogonTimestamp, SID)
        $done = 0
        foreach ($u in $candidates) {
            if ($protectedSids.Contains($u.SID.Value)) { continue }
            if (Test-UnderExcludedOU -DN $u.DistinguishedName -OUList $ExcludedOUsUsers) { continue }
            if ($u.DistinguishedName -like "*,$disableUserOUDN" -or $u.DistinguishedName -like "*,$disableComputerOUDN") { continue }
            try {
                Disable-ADAccount -Identity $u.DistinguishedName -ErrorAction Stop
                Add-DisabledMarkerToDescription -Identity $u.DistinguishedName
                Move-ADObject -Identity $u.DistinguishedName -TargetPath $disableUserOUDN -ErrorAction Stop
                $done++
            } catch {
                Write-DisLog "Echec sur l'utilisateur $($u.SamAccountName) : $($_.Exception.Message)"
            }
        }
        Write-DisLog "$done utilisateur(s) desactive(s) et deplace(s) vers $disableUserOUDN (sur $($candidates.Count) candidat(s) avant exclusions)."
    } catch {
        Write-DisLog "ECHEC du volet UTILISATEURS : $($_.Exception.Message)"
    }
}

if ($ApplyComputers) {
    try {
        if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$DisableComputerOUName'" -SearchBase $domainDN -ErrorAction SilentlyContinue)) {
            New-ADOrganizationalUnit -Name $DisableComputerOUName -Path $domainDN -ProtectedFromAccidentalDeletion $true
        }

        $cutoffComputers = (Get-Date).AddDays(-$DaysComputers)
        $candidates = @(Get-ADComputer -Filter { (Enabled -eq $true) -and (LastLogonTimestamp -lt $cutoffComputers) } -Properties LastLogonTimestamp, SID)
        $done = 0
        foreach ($c in $candidates) {
            if ($protectedSids.Contains($c.SID.Value)) { continue }
            if ($protectedComputerDNs.Contains($c.DistinguishedName)) { continue }
            if (Test-UnderExcludedOU -DN $c.DistinguishedName -OUList $ExcludedOUsComputers) { continue }
            if ($c.DistinguishedName -like "*,$disableUserOUDN" -or $c.DistinguishedName -like "*,$disableComputerOUDN") { continue }
            try {
                Disable-ADAccount -Identity $c.DistinguishedName -ErrorAction Stop
                Add-DisabledMarkerToDescription -Identity $c.DistinguishedName
                Move-ADObject -Identity $c.DistinguishedName -TargetPath $disableComputerOUDN -ErrorAction Stop
                $done++
            } catch {
                Write-DisLog "Echec sur le poste $($c.Name) : $($_.Exception.Message)"
            }
        }
        Write-DisLog "$done poste(s)/serveur(s) desactive(s) et deplace(s) vers $disableComputerOUDN (sur $($candidates.Count) candidat(s) avant exclusions)."
    } catch {
        Write-DisLog "ECHEC du volet POSTES/SERVEURS : $($_.Exception.Message)"
    }
}

Write-DisLog "Fin de l'execution planifiee."
'@

    return $header + "`r`n" + $body
}

function Grant-DisableAutomationPermissions {
    <#
        Delegue au principal indique UNIQUEMENT les droits necessaires pour que
        la tache planifiee desactive et deplace des comptes utilisateur/ordinateur :
          - Ecriture de la propriete userAccountControl (desactivation)
          - Creation/suppression d'objets User et Computer (necessaire pour
            Move-ADObject, qui equivaut a une suppression dans le conteneur source
            + une creation dans le conteneur cible)
        Jamais de droit Domain Admin accorde a la tache planifiee. Applique sur la
        racine de delegation fournie (racine du domaine par defaut, ou une UO
        reduite si choisie) : reduire cette racine limite d'autant le perimetre
        reellement delegue.
    #>
    param(
        [Parameter(Mandatory)][string]$PrincipalSam,
        [Parameter(Mandatory)][string]$TargetDC,
        [Parameter(Mandatory)][string]$DelegationRootDN
    )

    $domainNetbios = (Get-ADDomain).NetBIOSName

    Invoke-Guarded -Description ("Delegation (userAccountControl + creation/suppression User/Computer) sur {0} a {1}" -f $DelegationRootDN, $PrincipalSam) -Action {
        Invoke-Command -ComputerName $TargetDC -ScriptBlock {
            param($rootDN, $account)
            & dsacls.exe "$rootDN" /I:S /G "${account}:WP;userAccountControl;user" | Out-Null
            & dsacls.exe "$rootDN" /I:S /G "${account}:WP;userAccountControl;computer" | Out-Null
            & dsacls.exe "$rootDN" /I:S /G "${account}:CCDC;user" | Out-Null
            & dsacls.exe "$rootDN" /I:S /G "${account}:CCDC;computer" | Out-Null
        } -ArgumentList $DelegationRootDN, "$domainNetbios\$PrincipalSam" -ErrorAction Stop
    }
}

function Invoke-AutomationSetupScheduledTask {
    Write-Host "`n--- Configuration de la tache planifiee de desactivation automatique ---" -ForegroundColor Red
    Write-Host "Execute PERIODIQUEMENT, sans intervention, la desactivation des comptes" -ForegroundColor DarkGray
    Write-Host "utilisateurs/ordinateurs inactifs, avec les memes garde-fous que l'action manuelle :" -ForegroundColor DarkGray
    Write-Host "UO exclues, groupes exclus, comptes systeme (krbtgt, Administrateur, Invite, DC," -ForegroundColor DarkGray
    Write-Host "compte d'execution lui-meme) toujours proteges." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "Important : pour une execution automatique et recurrente, le seuil se base sur une" -ForegroundColor Yellow
    Write-Host "ANCIENNETE glissante (X jours sans connexion), recalculee a chaque execution - une" -ForegroundColor Yellow
    Write-Host "date fixe n'aurait plus de sens d'une execution a l'autre." -ForegroundColor Yellow

    $applyUsers = (Read-Host "Desactiver automatiquement les UTILISATEURS inactifs ? (O/N)") -match '^[oOyY]'
    $applyComputers = (Read-Host "Desactiver automatiquement les POSTES/SERVEURS inactifs ? (O/N)") -match '^[oOyY]'
    if (-not $applyUsers -and -not $applyComputers) { Write-Log "Aucun perimetre selectionne, configuration annulee." -Level WARN; return }

    $thresholds = Read-InactivityThresholds -DefaultUserDays 180 -DefaultComputerDays 90

    $excludedOUsUsers = @()
    $excludedOUsComputers = @()
    if ($applyUsers) { $excludedOUsUsers = @(Select-ExclusionOUs -Label "les UTILISATEURS") }
    if ($applyComputers) { $excludedOUsComputers = @(Select-ExclusionOUs -Label "les POSTES/SERVEURS") }
    $excludedGroups = @(Read-ExtraExclusionGroups)

    $daysInterval = Read-Host "Intervalle entre chaque execution automatique, en jours [defaut 7]"
    if ([string]::IsNullOrWhiteSpace($daysInterval) -or $daysInterval -notmatch '^\d+$') { $daysInterval = 7 }
    $daysInterval = [int]$daysInterval
    if ($daysInterval -lt 1) { $daysInterval = 1 }

    $dcs = Get-DomainControllersList
    if (-not $dcs) { return }
    Write-Host "Controleurs de domaine disponibles :"
    for ($i = 0; $i -lt $dcs.Count; $i++) { Write-Host ("  [{0}] {1}" -f $i, $dcs[$i].HostName) }
    $pdc = (Get-ADDomain).PDCEmulator
    $defaultIdx = [array]::IndexOf($dcs.HostName, $pdc)
    if ($defaultIdx -lt 0) { $defaultIdx = 0 }
    $idxInput = Read-Host ("DC qui hebergera la tache planifiee [defaut {0} = {1}]" -f $defaultIdx, $dcs[$defaultIdx].HostName)
    $targetDC = if ($idxInput -match '^\d+$' -and [int]$idxInput -lt $dcs.Count) { $dcs[[int]$idxInput].HostName } else { $dcs[$defaultIdx].HostName }

    $gmsaName = Read-Host "Nom du gMSA dedie a creer/reutiliser [defaut svc-ADAutoDisable]"
    if ([string]::IsNullOrWhiteSpace($gmsaName)) { $gmsaName = "svc-ADAutoDisable" }

    $domain = Get-ADDomain
    $domainDN = $domain.DistinguishedName
    $domainDNS = $domain.DNSRoot
    $domainNetbios = $domain.NetBIOSName

    Write-Host ""
    Write-Host "Perimetre de delegation (droits accordes au gMSA) :" -ForegroundColor Yellow
    Write-Host ("  Par defaut : racine du domaine ({0}), avec heritage - necessaire car les postes" -f $domainDN) -ForegroundColor DarkGray
    Write-Host "  et utilisateurs concernes peuvent se trouver n'importe ou hors des UO exclues." -ForegroundColor DarkGray
    $delegationRoot = Read-Host "Restreindre la delegation a une UO precise (DN complet, vide = racine du domaine)"
    if ([string]::IsNullOrWhiteSpace($delegationRoot)) { $delegationRoot = $domainDN }

    Write-Host ""
    Write-Host "Resume :" -ForegroundColor Yellow
    Write-Host ("  Utilisateurs      : {0}{1}" -f $(if ($applyUsers) { "OUI, > $($thresholds.UserDays) j" } else { "non" }), $(if ($applyUsers -and $excludedOUsUsers.Count -gt 0) { " ($($excludedOUsUsers.Count) UO exclue(s))" } else { "" }))
    Write-Host ("  Postes/Serveurs   : {0}{1}" -f $(if ($applyComputers) { "OUI, > $($thresholds.ComputerDays) j" } else { "non" }), $(if ($applyComputers -and $excludedOUsComputers.Count -gt 0) { " ($($excludedOUsComputers.Count) UO exclue(s))" } else { "" }))
    Write-Host ("  Groupes exclus    : {0}" -f ($excludedGroups -join ', '))
    Write-Host ("  Intervalle        : tous les {0} jour(s)" -f $daysInterval)
    Write-Host ("  Hote              : {0}" -f $targetDC)
    Write-Host ("  Compte de service : gMSA {0}" -f $gmsaName)
    Write-Host ("  Racine delegation : {0}" -f $delegationRoot)

    if (-not (Confirm-Action "Creer le gMSA, deleguer les droits, deployer le script et creer la tache planifiee avec ces parametres" -Strong)) { return }

    if (-not (Get-OrEnsureKdsRootKey)) { return }

    Invoke-Guarded -Description ("Creation du gMSA {0}" -f $gmsaName) -Action {
        $existingGmsa = Get-ADServiceAccount -Filter "Name -eq '$gmsaName'" -ErrorAction SilentlyContinue
        if (-not $existingGmsa) {
            $dcComputer = Get-ADComputer -Identity $targetDC.Split('.')[0]
            New-ADServiceAccount -Name $gmsaName -DNSHostName "$gmsaName.$domainDNS" -PrincipalsAllowedToRetrieveManagedPassword $dcComputer.DistinguishedName -Enabled $true
        } else {
            Write-Log "Le gMSA existe deja, reutilisation." -Level INFO
        }
    }

    Invoke-Guarded -Description ("Installation/test du gMSA {0} sur {1}" -f $gmsaName, $targetDC) -Action {
        Invoke-Command -ComputerName $targetDC -ScriptBlock {
            param($name)
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            Install-ADServiceAccount -Identity $name -ErrorAction Stop
            if (-not (Test-ADServiceAccount -Identity $name)) {
                throw "Le test du gMSA a echoue (Test-ADServiceAccount)."
            }
        } -ArgumentList $gmsaName -ErrorAction Stop
    }

    Grant-DisableAutomationPermissions -PrincipalSam "$gmsaName$" -TargetDC $targetDC -DelegationRootDN $delegationRoot

    Invoke-Guarded -Description "Deploiement du script de desactivation automatique sur le DC cible" -Action {
        $scriptContent = Get-DisableByDateScheduledScriptContent -DaysUsers $thresholds.UserDays -DaysComputers $thresholds.ComputerDays `
            -ApplyUsers $applyUsers -ApplyComputers $applyComputers `
            -ExcludedOUsUsers $excludedOUsUsers -ExcludedOUsComputers $excludedOUsComputers -ExcludedGroups $excludedGroups `
            -DisableUserOUName $Script:DisableUserOUName -DisableComputerOUName $Script:DisableComputerOUName
        Invoke-Command -ComputerName $targetDC -ScriptBlock {
            param($content)
            $dir = "C:\ADHC-Scripts"
            if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
            Set-Content -Path (Join-Path $dir "Disable-ByDate.ps1") -Value $content -Encoding UTF8
        } -ArgumentList $scriptContent -ErrorAction Stop
    }

    Invoke-Guarded -Description ("Creation de la tache planifiee (tous les {0} jours) sur {1}" -f $daysInterval, $targetDC) -Action {
        Invoke-Command -ComputerName $targetDC -ScriptBlock {
            param($gmsaSam, $domainNetbios, $intervalDays)
            $taskName = "SEC - Desactivation Auto (date/anciennete)"
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\ADHC-Scripts\Disable-ByDate.ps1"'
            $trigger = New-ScheduledTaskTrigger -Daily -DaysInterval $intervalDays -At "03:00"
            $principal = New-ScheduledTaskPrincipal -UserId "$domainNetbios\$gmsaSam`$" -LogonType Password -RunLevel Highest
            $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd

            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Desactivation automatique des comptes utilisateurs/ordinateurs inactifs - deploye par le script de remediation AD"
        } -ArgumentList $gmsaName, $domainNetbios, $daysInterval -ErrorAction Stop
    }

    Write-Log ("Tache planifiee 'SEC - Desactivation Auto (date/anciennete)' creee sur {0}, execution tous les {1} jours a 03:00, sous le compte {2}\{3}$." -f $targetDC, $daysInterval, $domainNetbios, $gmsaName) -Level OK
    Write-Log "Journal local sur le DC : C:\ADHC-Scripts\Disable-ByDate.log (+ journal d'evenements Application, source ADHC-AutoDisable)." -Level INFO
    Write-Log "Pour changer les seuils/exclusions, relancez cette configuration : elle regenere et remplace le script deploye et la tache." -Level INFO
}

function Invoke-AutomationShowStatus {
    Write-Host "`n--- Etat de la tache planifiee de desactivation automatique ---" -ForegroundColor Magenta
    $dcs = Get-DomainControllersList
    if (-not $dcs) { return }
    $taskName = "SEC - Desactivation Auto (date/anciennete)"
    foreach ($dc in $dcs) {
        try {
            $task = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                param($name)
                Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
            } -ArgumentList $taskName -ErrorAction Stop
            if ($task) {
                Write-Host ("{0} : tache presente - derniere execution {1}, prochaine {2}, dernier resultat {3}" -f $dc.HostName, $task.LastRunTime, $task.NextRunTime, $task.LastTaskResult) -ForegroundColor Yellow
            } else {
                Write-Host ("{0} : aucune tache trouvee" -f $dc.HostName) -ForegroundColor DarkGray
            }
        } catch {
            Write-Log ("Impossible d'interroger {0} : {1}" -f $dc.HostName, $_.Exception.Message) -Level WARN
        }
    }
}

function Invoke-AutomationRemoveScheduledTask {
    Write-Host "`n--- Suppression de la tache planifiee de desactivation automatique ---" -ForegroundColor Red
    Write-Host "Ceci arrete uniquement l'AUTOMATISATION : les comptes deja desactives/deplaces ne sont pas restaures." -ForegroundColor DarkGray

    $dcs = Get-DomainControllersList
    if (-not $dcs) { return }
    Write-Host "Controleurs de domaine disponibles :"
    for ($i = 0; $i -lt $dcs.Count; $i++) { Write-Host ("  [{0}] {1}" -f $i, $dcs[$i].HostName) }
    $idxInput = Read-Host "DC hebergeant la tache a supprimer (numero)"
    if ($idxInput -notmatch '^\d+$' -or [int]$idxInput -ge $dcs.Count) { Write-Log "Selection invalide." -Level WARN; return }
    $targetDC = $dcs[[int]$idxInput].HostName

    if (-not (Confirm-Action ("Supprimer la tache planifiee de desactivation automatique sur {0}" -f $targetDC) -Strong)) { return }

    Invoke-Guarded -Description ("Suppression de la tache planifiee sur {0}" -f $targetDC) -Action {
        Invoke-Command -ComputerName $targetDC -ScriptBlock {
            Unregister-ScheduledTask -TaskName "SEC - Desactivation Auto (date/anciennete)" -Confirm:$false -ErrorAction Stop
        } -ErrorAction Stop
    }
}

# ============================================================
#  MENUS
# ============================================================

$Script:ThemeNames = [ordered]@{
    1  = "Comptes a privileges"
    2  = "Comptes de service"
    3  = "Mots de passe et authentification"
    4  = "Kerberos et delegations"
    5  = "NTLM / LM"
    6  = "SMB, SYSVOL et NETLOGON"
    7  = "LDAP / LDAPS"
    8  = "Controleurs de domaine"
    9  = "Windows LAPS"
    10 = "GPO de durcissement (socle GPO-SEC-*)"
    11 = "Postes et serveurs membres"
    12 = "Reseau et anti-relay"
    13 = "Sauvegarde et resilience AD"
    14 = "Obsolescence"
    15 = "Journalisation et detection"
    16 = "Controle final"
    17 = "Rapports transverses"
    18 = "Hygiene des comptes inactifs et automatisation"
}

# Index des actions pour la recherche par mot-cle (menu principal > [R]). Purement
# INFORMATIF : indique ou se trouve une action (theme + numero), ne l'execute jamais
# elle-meme - evite tout risque si ce texte se desynchronise un jour legerement du
# libelle reellement affiche par un Show-*Menu (a tenir a jour en cas d'ajout/retrait
# d'action, mais une desynchronisation n'a ici aucun impact fonctionnel, seulement
# un texte de recherche legerement perime).
$Script:ActionIndex = @(
    [PSCustomObject]@{ Theme=1; Item=1;  Label="Export des membres des groupes a privileges" }
    [PSCustomObject]@{ Theme=1; Item=2;  Label="Nombre de membres Domain Admins / Enterprise Admins (vs seuil)" }
    [PSCustomObject]@{ Theme=1; Item=3;  Label="Usage du compte Administrateur integre (RID 500)" }
    [PSCustomObject]@{ Theme=1; Item=4;  Label="Comptes a privileges potentiellement non nominatifs/partages" }
    [PSCustomObject]@{ Theme=1; Item=5;  Label="Risque Kerberoasting sur les comptes a privileges" }
    [PSCustomObject]@{ Theme=1; Item=6;  Label="(A VALIDER) Marquer les comptes a privileges 'Sensible, ne peut etre delegue'" }
    [PSCustomObject]@{ Theme=1; Item=7;  Label="(A VALIDER) Ajouter les comptes Domain/Enterprise Admins dans 'Protected Users'" }
    [PSCustomObject]@{ Theme=1; Item=8;  Label="(A VALIDER) Nettoyer le groupe Schema Admins" }
    [PSCustomObject]@{ Theme=1; Item=9;  Label="(A VALIDER) Forcer l'expiration des mots de passe des comptes a privileges" }
    [PSCustomObject]@{ Theme=1; Item=10; Label="(A VALIDER) Desactiver le compte Administrateur integre (RID 500)" }
    [PSCustomObject]@{ Theme=1; Item=11; Label="(A VALIDER) Restreindre les comptes a privileges a des postes dedies (PAW)" }

    [PSCustomObject]@{ Theme=2; Item=1; Label="Inventaire des comptes de service (SPN / OU choisies)" }
    [PSCustomObject]@{ Theme=2; Item=2; Label="Comptes de service en chiffrement faible (RC4/DES, sans AES)" }
    [PSCustomObject]@{ Theme=2; Item=3; Label="(A VALIDER) Forcer AES128+AES256 sur les comptes selectionnes" }
    [PSCustomObject]@{ Theme=2; Item=4; Label="(A VALIDER) Interdire la connexion interactive/RDP des comptes selectionnes" }
    [PSCustomObject]@{ Theme=2; Item=5; Label="(A VALIDER) Retirer les comptes de service des groupes a privileges" }
    [PSCustomObject]@{ Theme=2; Item=6; Label="(A VALIDER) Reinitialiser le mot de passe des comptes selectionnes" }
    [PSCustomObject]@{ Theme=2; Item=7; Label="(A VALIDER) Assistant de creation d'un compte de service gere (gMSA)" }

    [PSCustomObject]@{ Theme=4; Item=1; Label="Rapport des delegations Kerberos (non contrainte/contrainte/RBCD)" }
    [PSCustomObject]@{ Theme=4; Item=2; Label="Audit AS-REP Roasting (comptes sans pre-authentification)" }
    [PSCustomObject]@{ Theme=4; Item=3; Label="Audit des relations d'approbation (trusts) et de leur chiffrement" }
    [PSCustomObject]@{ Theme=4; Item=4; Label="(A VALIDER) Reinitialiser le mot de passe KRBTGT (1 des 2 executions requises)" }
    [PSCustomObject]@{ Theme=4; Item=5; Label="(A VALIDER) Configurer la rotation KRBTGT automatique planifiee" }
    [PSCustomObject]@{ Theme=4; Item=6; Label="(A VALIDER) Desactiver DES et forcer AES sur les comptes concernes" }
    [PSCustomObject]@{ Theme=4; Item=7; Label="(A VALIDER) Corriger l'exposition AS-REP Roasting" }
    [PSCustomObject]@{ Theme=4; Item=8; Label="(A VALIDER) Activer Kerberos Armoring (FAST)" }

    [PSCustomObject]@{ Theme=5; Item=1; Label="(SAFE) Activer l'audit NTLM (detection avant tout blocage)" }
    [PSCustomObject]@{ Theme=5; Item=2; Label="Rapport NTLMv1/LM detecte (journal Securite des DC)" }
    [PSCustomObject]@{ Theme=5; Item=3; Label="(A VALIDER) Desactiver NTLMv1/LM (LmCompatibilityLevel) via GPO" }
    [PSCustomObject]@{ Theme=5; Item=4; Label="(A VALIDER) Restriction progressive de NTLM sortant (Deny avec exceptions)" }

    [PSCustomObject]@{ Theme=6; Item=1; Label="Detection de l'usage SMBv1 (active l'audit si besoin, puis lit le journal)" }
    [PSCustomObject]@{ Theme=6; Item=2; Label="Etat de la signature SMB (client/serveur) sur les DC" }
    [PSCustomObject]@{ Theme=6; Item=3; Label="Audit des partages SMB sur des postes/serveurs choisis" }
    [PSCustomObject]@{ Theme=6; Item=4; Label="(A VALIDER) Desactiver SMBv1 (client + serveur) sur les DC" }
    [PSCustomObject]@{ Theme=6; Item=5; Label="(A VALIDER) Desactiver SMBv1 sur des postes/serveurs choisis" }
    [PSCustomObject]@{ Theme=6; Item=6; Label="(A VALIDER) Forcer la signature SMB (client + serveur) via GPO" }
    [PSCustomObject]@{ Theme=6; Item=7; Label="(A VALIDER) Durcir les chemins UNC SYSVOL/NETLOGON (Hardened UNC Paths)" }

    [PSCustomObject]@{ Theme=7; Item=1; Label="Audit des certificats LDAPS et joignabilite du port 636" }
    [PSCustomObject]@{ Theme=7; Item=2; Label="Audit des Simple Binds LDAP non signes (evenement 2887)" }
    [PSCustomObject]@{ Theme=7; Item=3; Label="(A VALIDER) Forcer la signature LDAP / channel binding sur les DC" }
    [PSCustomObject]@{ Theme=7; Item=4; Label="(A VALIDER) Desactiver TLS 1.0/1.1 et activer TLS 1.2+ (SCHANNEL)" }
    [PSCustomObject]@{ Theme=7; Item=5; Label="(A VALIDER) Restreindre les operations LDAP anonymes (dSHeuristics)" }

    [PSCustomObject]@{ Theme=8; Item=1;  Label="Rapport des hotfix installes sur les DC" }
    [PSCustomObject]@{ Theme=8; Item=2;  Label="Etat de la synchronisation horaire (NTP)" }
    [PSCustomObject]@{ Theme=8; Item=3;  Label="Roles et fonctionnalites installes sur les DC" }
    [PSCustomObject]@{ Theme=8; Item=4;  Label="(SAFE) Activer PowerShell Remoting (WinRM) sur les DC injoignables" }
    [PSCustomObject]@{ Theme=8; Item=5;  Label="(SAFE) Desactiver le compte Invite (Guest) s'il est actif" }
    [PSCustomObject]@{ Theme=8; Item=6;  Label="(SAFE) Proteger toutes les OU contre la suppression accidentelle" }
    [PSCustomObject]@{ Theme=8; Item=7;  Label="(SAFE) Limiter le quota de creation d'ordinateurs (ms-DS-MachineAccountQuota = 0)" }
    [PSCustomObject]@{ Theme=8; Item=8;  Label="(A VALIDER) Arreter/desactiver le service Spooler sur les DC" }
    [PSCustomObject]@{ Theme=8; Item=9;  Label="(A VALIDER) Configurer la source NTP externe du PDC Emulator" }
    [PSCustomObject]@{ Theme=8; Item=10; Label="(A VALIDER) Activer le pare-feu Windows (3 profils) sur les DC" }

    [PSCustomObject]@{ Theme=9; Item=1; Label="Etat du deploiement LAPS (schema, couverture)" }
    [PSCustomObject]@{ Theme=9; Item=2; Label="Audit des droits de lecture/reset du mot de passe LAPS" }
    [PSCustomObject]@{ Theme=9; Item=3; Label="(A VALIDER) Preparer le schema Active Directory pour LAPS" }
    [PSCustomObject]@{ Theme=9; Item=4; Label="(A VALIDER) Deployer la GPO Windows LAPS" }
    [PSCustomObject]@{ Theme=9; Item=5; Label="(A VALIDER) Configurer les droits de lecture/reset LAPS" }

    [PSCustomObject]@{ Theme=3; Item=1; Label="Rapport des comptes avec mot de passe n'expirant jamais" }
    [PSCustomObject]@{ Theme=3; Item=2; Label="Audit de la politique de mot de passe par defaut du domaine" }
    [PSCustomObject]@{ Theme=3; Item=3; Label="(SAFE) Retirer le flag 'Mot de passe non requis' sur les comptes concernes" }
    [PSCustomObject]@{ Theme=3; Item=4; Label="(A VALIDER) Corriger la politique de mot de passe par defaut du domaine" }
    [PSCustomObject]@{ Theme=3; Item=5; Label="(A VALIDER) Creer une Fine-Grained Password Policy pour les comptes de service" }
    [PSCustomObject]@{ Theme=3; Item=6; Label="(SAFE) Generer les recommandations MFA / Conditional Access (hybride)" }

    [PSCustomObject]@{ Theme=10; Item=1; Label="Etat du socle GPO-SEC-* et des sauvegardes de GPO" }
    [PSCustomObject]@{ Theme=10; Item=2; Label="(SAFE) Sauvegarder TOUTES les GPO du domaine" }
    [PSCustomObject]@{ Theme=10; Item=3; Label="(SAFE) Creer les GPO manquantes du socle GPO-SEC-* (non liees)" }

    [PSCustomObject]@{ Theme=11; Item=1; Label="Etat de Microsoft Defender sur des machines choisies" }
    [PSCustomObject]@{ Theme=11; Item=2; Label="Audit des administrateurs locaux sur des machines choisies" }
    [PSCustomObject]@{ Theme=11; Item=3; Label="(A VALIDER) Renforcer Microsoft Defender via GPO (Cloud/Reseau/SmartScreen/ASR)" }
    [PSCustomObject]@{ Theme=11; Item=4; Label="(A VALIDER) Restreindre RDP via GPO (NLA obligatoire)" }
    [PSCustomObject]@{ Theme=11; Item=5; Label="(A VALIDER) Retirer des comptes des administrateurs locaux" }
    [PSCustomObject]@{ Theme=11; Item=6; Label="(SAFE) Etendre la journalisation PowerShell aux postes/serveurs choisis" }
    [PSCustomObject]@{ Theme=11; Item=7; Label="(A VALIDER) Bloquer les scripts .vbs/.js (Windows Script Host)" }
    [PSCustomObject]@{ Theme=11; Item=8; Label="(A VALIDER) Activer le pare-feu Windows (3 profils)" }

    [PSCustomObject]@{ Theme=12; Item=1; Label="Audit de la Global Query Block List DNS (WPAD/ISATAP)" }
    [PSCustomObject]@{ Theme=12; Item=2; Label="Audit des ports/services exposes sur les DC" }
    [PSCustomObject]@{ Theme=12; Item=3; Label="(A VALIDER) Desactiver LLMNR via GPO (domaine entier)" }
    [PSCustomObject]@{ Theme=12; Item=4; Label="(SAFE) Retablir la Global Query Block List (wpad/isatap)" }
    [PSCustomObject]@{ Theme=12; Item=5; Label="(A VALIDER) Desactiver NetBIOS sur TCP/IP sur des machines choisies" }
    [PSCustomObject]@{ Theme=12; Item=6; Label="(A VALIDER) Durcir RPC (clients non authentifies, resolution du mappeur)" }
    [PSCustomObject]@{ Theme=12; Item=7; Label="(A VALIDER) Durcir WinRM (authentification Basic desactivee, trafic chiffre)" }
    [PSCustomObject]@{ Theme=12; Item=8; Label="(A VALIDER) Restreindre l'enumeration distante SAM/SAMR" }

    [PSCustomObject]@{ Theme=13; Item=1; Label="Etat des sauvegardes System State sur les DC" }
    [PSCustomObject]@{ Theme=13; Item=2; Label="(SAFE) Activer la Corbeille Active Directory" }
    [PSCustomObject]@{ Theme=13; Item=3; Label="(A VALIDER) Planifier une sauvegarde System State quotidienne" }
    [PSCustomObject]@{ Theme=13; Item=4; Label="(SAFE) Generer les procedures de recuperation (objet / DC / foret)" }

    [PSCustomObject]@{ Theme=14; Item=1; Label="Inventaire des systemes d'exploitation non/bientot non supportes" }
    [PSCustomObject]@{ Theme=14; Item=2; Label="Protocoles obsoletes actifs sur des machines choisies (SMBv1, TLS 1.0/1.1)" }
    [PSCustomObject]@{ Theme=14; Item=3; Label="(SAFE) Generer le plan de traitement de l'obsolescence (consolide)" }

    [PSCustomObject]@{ Theme=15; Item=1; Label="Audit du SACL sur les objets sensibles (racine du domaine, AdminSDHolder)" }
    [PSCustomObject]@{ Theme=15; Item=2; Label="(SAFE) Activer l'audit avance sur les DC (auditpol)" }
    [PSCustomObject]@{ Theme=15; Item=3; Label="(SAFE) Activer la journalisation PowerShell (Script Block Logging)" }
    [PSCustomObject]@{ Theme=15; Item=4; Label="(A VALIDER) Configurer l'audit SACL sur les objets sensibles" }
    [PSCustomObject]@{ Theme=15; Item=5; Label="(A VALIDER) Configurer la redirection des journaux vers un collecteur (WEF/SIEM)" }

    [PSCustomObject]@{ Theme=16; Item=1; Label="Lancer le controle final consolide (rejoue les audits cles de plusieurs themes)" }
    [PSCustomObject]@{ Theme=16; Item=2; Label="(SAFE) Initialiser/completer le registre des exceptions" }

    [PSCustomObject]@{ Theme=17; Item=1; Label="Export comptes inactifs (utilisateurs/ordinateurs)" }
    [PSCustomObject]@{ Theme=17; Item=2; Label="Export global (rapports rapides multi-themes)" }

    [PSCustomObject]@{ Theme=18; Item=1; Label="(A VALIDER) Desactiver les comptes inactifs par anciennete (quarantaine)" }
    [PSCustomObject]@{ Theme=18; Item=2; Label="(A VALIDER) Desactiver postes/utilisateurs a partir d'une DATE choisie" }
    [PSCustomObject]@{ Theme=18; Item=3; Label="Configurer la tache planifiee de desactivation automatique" }
    [PSCustomObject]@{ Theme=18; Item=4; Label="Afficher l'etat de la tache planifiee existante" }
    [PSCustomObject]@{ Theme=18; Item=5; Label="Supprimer la tache planifiee" }
)

function Invoke-SearchActions {
    Write-Host "`n--- Recherche d'une action par mot-cle ---" -ForegroundColor Magenta
    Write-Host "Indique OU se trouve une action (theme + numero) ; ne l'execute pas directement -" -ForegroundColor DarkGray
    Write-Host "rendez-vous ensuite dans le theme indique pour la lancer avec ses garde-fous habituels." -ForegroundColor DarkGray

    $keyword = Read-Host "Mot-cle a rechercher (ex : kerberoasting, laps, smb1, admin, rdp...)"
    if ([string]::IsNullOrWhiteSpace($keyword)) { return }

    $results = @($Script:ActionIndex | Where-Object { $_.Label -like "*$keyword*" } | Sort-Object Theme, Item)
    if ($results.Count -eq 0) {
        Write-Log ("Aucune action ne correspond a '{0}'." -f $keyword) -Level WARN
        return
    }

    Write-Host ""
    Write-Host ("{0} resultat(s) pour '{1}' :" -f $results.Count, $keyword) -ForegroundColor Yellow
    foreach ($r in $results) {
        $color = if ($r.Label -match '^\(SAFE\)') { 'Green' } elseif ($r.Label -match '^\(A VALIDER\)') { 'Red' } else { 'Gray' }
        Write-Host ("  Theme {0,2} ({1,-38}) > {2,2} : {3}" -f $r.Theme, $Script:ThemeNames[$r.Theme], $r.Item, $r.Label) -ForegroundColor $color
    }
}

function Show-PrivilegedAccountsMenu {
    do {
        Show-Banner
        Write-Host "=== COMPTES A PRIVILEGES ===" -ForegroundColor Cyan
        Write-Host "--- Audit (lecture seule) ---" -ForegroundColor DarkGray
        Write-MenuItem "1" "Export des membres des groupes a privileges"
        Write-MenuItem "2" "Nombre de membres Domain Admins / Enterprise Admins (vs seuil)"
        Write-MenuItem "3" "Usage du compte Administrateur integre (RID 500)"
        Write-MenuItem "4" "Comptes a privileges potentiellement non nominatifs/partages"
        Write-MenuItem "5" "Risque Kerberoasting sur les comptes a privileges"
        Write-Host "--- Remediation ---" -ForegroundColor DarkGray
        Write-MenuItem "6" "(A VALIDER) Marquer les comptes a privileges 'Sensible, ne peut etre delegue'"
        Write-MenuItem "7" "(A VALIDER) Ajouter les comptes Domain/Enterprise Admins dans 'Protected Users'"
        Write-MenuItem "8" "(A VALIDER) Nettoyer le groupe Schema Admins"
        Write-MenuItem "9" "(A VALIDER) Forcer l'expiration des mots de passe des comptes a privileges"
        Write-MenuItem "10" "(A VALIDER) Desactiver le compte Administrateur integre (RID 500)"
        Write-MenuItem "11" "(A VALIDER) Restreindre les comptes a privileges a des postes dedies (PAW)"
        Write-Host " 0. Retour au menu principal"
        Write-Host ""
        $choice = Read-Host "Votre choix"
        switch ($choice) {
            "1"  { Invoke-ReportPrivilegedGroups; Pause-Menu }
            "2"  { Invoke-Audit3DomainAdminsCount; Pause-Menu }
            "3"  { Invoke-Audit3BuiltinAdministratorStatus; Pause-Menu }
            "4"  { Invoke-Audit3NonNominativeAccounts; Pause-Menu }
            "5"  { Invoke-Audit3KerberoastingRisk; Pause-Menu }
            "6"  { Invoke-RiskySetPrivilegedNotDelegated; Pause-Menu }
            "7"  { Invoke-RiskyAddToProtectedUsers; Pause-Menu }
            "8"  { Invoke-RiskyCleanupSchemaAdmins; Pause-Menu }
            "9"  { Invoke-RiskyForcePasswordExpirationPrivileged; Pause-Menu }
            "10" { Invoke-Remediate3DisableBuiltinAdministrator; Pause-Menu }
            "11" { Invoke-Remediate3RestrictPrivilegedLogonWorkstations; Pause-Menu }
            "0" { return }
            default { }
        }
    } while ($true)
}

function Show-ServiceAccountsMenu {
    do {
        Show-Banner
        Write-Host "=== COMPTES DE SERVICE ===" -ForegroundColor Cyan
        Write-Host "--- Audit (lecture seule) ---" -ForegroundColor DarkGray
        Write-MenuItem "1" "Inventaire des comptes de service (SPN / OU choisies)"
        Write-MenuItem "2" "Comptes de service en chiffrement faible (RC4/DES, sans AES)"
        Write-Host "--- Remediation ---" -ForegroundColor DarkGray
        Write-MenuItem "3" "(A VALIDER) Forcer AES128+AES256 sur les comptes selectionnes"
        Write-MenuItem "4" "(A VALIDER) Interdire la connexion interactive/RDP des comptes selectionnes"
        Write-MenuItem "5" "(A VALIDER) Retirer les comptes de service des groupes a privileges"
        Write-MenuItem "6" "(A VALIDER) Reinitialiser le mot de passe des comptes selectionnes"
        Write-MenuItem "7" "(A VALIDER) Assistant de creation d'un compte de service gere (gMSA)"
        Write-Host " 0. Retour au menu principal"
        Write-Host ""
        $choice = Read-Host "Votre choix"
        switch ($choice) {
            "1" { Invoke-Audit4ServiceAccountsInventory; Pause-Menu }
            "2" { Invoke-Audit4WeakEncryption; Pause-Menu }
            "3" { Invoke-Remediate4EnableAesOnServiceAccounts; Pause-Menu }
            "4" { Invoke-Remediate4DenyInteractiveLogon; Pause-Menu }
            "5" { Invoke-Remediate4RemoveFromPrivilegedGroups; Pause-Menu }
            "6" { Invoke-Remediate4RotatePassword; Pause-Menu }
            "7" { Invoke-Remediate4CreateGmsa; Pause-Menu }
            "0" { return }
            default { }
        }
    } while ($true)
}

function Show-KerberosMenu {
    do {
        Show-Banner
        Write-Host "=== KERBEROS ET DELEGATIONS ===" -ForegroundColor Cyan
        Write-Host "--- Audit (lecture seule) ---" -ForegroundColor DarkGray
        Write-MenuItem "1" "Rapport des delegations Kerberos (non contrainte/contrainte/RBCD)"
        Write-MenuItem "2" "Audit AS-REP Roasting (comptes sans pre-authentification)"
        Write-MenuItem "3" "Audit des relations d'approbation (trusts) et de leur chiffrement"
        Write-Host "--- Remediation ---" -ForegroundColor DarkGray
        Write-MenuItem "4" "(A VALIDER) Reinitialiser le mot de passe KRBTGT (1 des 2 executions requises)"
        Write-MenuItem "5" "(A VALIDER) Configurer la rotation KRBTGT automatique planifiee"
        Write-MenuItem "6" "(A VALIDER) Desactiver DES et forcer AES sur les comptes concernes"
        Write-MenuItem "7" "(A VALIDER) Corriger l'exposition AS-REP Roasting"
        Write-MenuItem "8" "(A VALIDER) Activer Kerberos Armoring (FAST)"
        Write-Host " 0. Retour au menu principal"
        Write-Host ""
        $choice = Read-Host "Votre choix"
        switch ($choice) {
            "1" { Invoke-RiskyReportDelegations; Pause-Menu }
            "2" { Invoke-Audit5AsRepRoasting; Pause-Menu }
            "3" { Invoke-Audit5TrustsEncryption; Pause-Menu }
            "4" { Invoke-RiskyResetKrbtgt; Pause-Menu }
            "5" { Invoke-RiskySetupKrbtgtScheduledRotation; Pause-Menu }
            "6" { Invoke-RiskyDisableDesForceAes; Pause-Menu }
            "7" { Invoke-Remediate5FixAsRepRoasting; Pause-Menu }
            "8" { Invoke-Remediate5EnableKerberosArmoring; Pause-Menu }
            "0" { return }
            default { }
        }
    } while ($true)
}

function Show-NtlmMenu {
    do {
        Show-Banner
        Write-Host "=== NTLM / LM ===" -ForegroundColor Cyan
        Write-Host "--- Audit ---" -ForegroundColor DarkGray
        Write-MenuItem "1" "(SAFE) Activer l'audit NTLM (detection avant tout blocage)"
        Write-MenuItem "2" "Rapport NTLMv1/LM detecte (journal Securite des DC)"
        Write-Host "--- Remediation ---" -ForegroundColor DarkGray
        Write-MenuItem "3" "(A VALIDER) Desactiver NTLMv1/LM (LmCompatibilityLevel) via GPO"
        Write-MenuItem "4" "(A VALIDER) Restriction progressive de NTLM sortant (Deny avec exceptions)"
        Write-Host " 0. Retour au menu principal"
        Write-Host ""
        $choice = Read-Host "Votre choix"
        switch ($choice) {
            "1" { Invoke-SafeEnableNtlmAudit; Pause-Menu }
            "2" { Invoke-ReportNtlmV1Usage; Pause-Menu }
            "3" { Invoke-RiskyDisableNtlmV1; Pause-Menu }
            "4" { Invoke-Remediate6RestrictNtlmOutgoing; Pause-Menu }
            "0" { return }
            default { }
        }
    } while ($true)
}

function Show-SmbSysvolMenu {
    do {
        Show-Banner
        Write-Host "=== SMB, SYSVOL ET NETLOGON ===" -ForegroundColor Cyan
        Write-Host "--- Audit (lecture seule) ---" -ForegroundColor DarkGray
        Write-MenuItem "1" "Detection de l'usage SMBv1 (active l'audit si besoin, puis lit le journal)"
        Write-MenuItem "2" "Etat de la signature SMB (client/serveur) sur les DC"
        Write-MenuItem "3" "Audit des partages SMB sur des postes/serveurs choisis"
        Write-Host "--- Remediation ---" -ForegroundColor DarkGray
        Write-MenuItem "4" "(A VALIDER) Desactiver SMBv1 (client + serveur) sur les DC"
        Write-MenuItem "5" "(A VALIDER) Desactiver SMBv1 sur des postes/serveurs choisis"
        Write-MenuItem "6" "(A VALIDER) Forcer la signature SMB (client + serveur) via GPO"
        Write-MenuItem "7" "(A VALIDER) Durcir les chemins UNC SYSVOL/NETLOGON (Hardened UNC Paths)"
        Write-Host " 0. Retour au menu principal"
        Write-Host ""
        $choice = Read-Host "Votre choix"
        switch ($choice) {
            "1" { Invoke-Audit7Smb1Usage; Pause-Menu }
            "2" { Invoke-Audit7SmbSigningStatus; Pause-Menu }
            "3" { Invoke-Audit7SensitiveShares; Pause-Menu }
            "4" { Invoke-Remediate7DisableSmb1; Pause-Menu }
            "5" { Invoke-Remediate7DisableSmb1OnComputers; Pause-Menu }
            "6" { Invoke-Remediate7EnforceSmbSigning; Pause-Menu }
            "7" { Invoke-Remediate7HardenedUncPaths; Pause-Menu }
            "0" { return }
            default { }
        }
    } while ($true)
}

function Show-LdapMenu {
    do {
        Show-Banner
        Write-Host "=== LDAP / LDAPS ===" -ForegroundColor Cyan
        Write-Host "--- Audit (lecture seule) ---" -ForegroundColor DarkGray
        Write-MenuItem "1" "Audit des certificats LDAPS et joignabilite du port 636"
        Write-MenuItem "2" "Audit des Simple Binds LDAP non signes (evenement 2887)"
        Write-Host "--- Remediation ---" -ForegroundColor DarkGray
        Write-MenuItem "3" "(A VALIDER) Forcer la signature LDAP / channel binding sur les DC"
        Write-MenuItem "4" "(A VALIDER) Desactiver TLS 1.0/1.1 et activer TLS 1.2+ (SCHANNEL)"
        Write-MenuItem "5" "(A VALIDER) Restreindre les operations LDAP anonymes (dSHeuristics)"
        Write-Host " 0. Retour au menu principal"
        Write-Host ""
        $choice = Read-Host "Votre choix"
        switch ($choice) {
            "1" { Invoke-Audit8LdapsCertificates; Pause-Menu }
            "2" { Invoke-Audit8LdapSimpleBinds; Pause-Menu }
            "3" { Invoke-RiskyEnforceLdapSigning; Pause-Menu }
            "4" { Invoke-Remediate8DisableWeakTls; Pause-Menu }
            "5" { Invoke-Remediate8RestrictAnonymousLdap; Pause-Menu }
            "0" { return }
            default { }
        }
    } while ($true)
}

function Show-DomainControllersMenu {
    do {
        Show-Banner
        Write-Host "=== CONTROLEURS DE DOMAINE ===" -ForegroundColor Cyan
        Write-Host "--- Audit (lecture seule) ---" -ForegroundColor DarkGray
        Write-MenuItem "1" "Rapport des hotfix installes sur les DC"
        Write-MenuItem "2" "Etat de la synchronisation horaire (NTP)"
        Write-MenuItem "3" "Roles et fonctionnalites installes sur les DC"
        Write-Host "--- Remediation (SAFE) ---" -ForegroundColor DarkGray
        Write-MenuItem "4" "(SAFE) Activer PowerShell Remoting (WinRM) sur les DC injoignables"
        Write-MenuItem "5" "(SAFE) Desactiver le compte Invite (Guest) s'il est actif"
        Write-MenuItem "6" "(SAFE) Proteger toutes les OU contre la suppression accidentelle"
        Write-MenuItem "7" "(SAFE) Limiter le quota de creation d'ordinateurs (ms-DS-MachineAccountQuota = 0)"
        Write-Host "--- Remediation (A VALIDER) ---" -ForegroundColor DarkGray
        Write-MenuItem "8" "(A VALIDER) Arreter/desactiver le service Spooler sur les DC"
        Write-MenuItem "9" "(A VALIDER) Configurer la source NTP externe du PDC Emulator"
        Write-MenuItem "10" "(A VALIDER) Activer le pare-feu Windows (3 profils) sur les DC"
        Write-Host " 0. Retour au menu principal"
        Write-Host ""
        Write-Host "(La signature LDAP a rejoint 'LDAP / LDAPS' ; l'audit avance et le PowerShell logging" -ForegroundColor DarkGray
        Write-Host " ont rejoint 'Journalisation et detection'.)" -ForegroundColor DarkGray
        $choice = Read-Host "Votre choix"
        switch ($choice) {
            "1"  { Invoke-ReportDCHotfixes; Pause-Menu }
            "2"  { Invoke-Audit9TimeSyncStatus; Pause-Menu }
            "3"  { Invoke-Audit9InstalledRoles; Pause-Menu }
            "4"  { Invoke-SafeEnableWinRmOnDCs; Pause-Menu }
            "5"  { Invoke-SafeDisableGuest; Pause-Menu }
            "6"  { Invoke-SafeProtectOUs; Pause-Menu }
            "7"  { Invoke-SafeSetMachineAccountQuotaZero; Pause-Menu }
            "8"  { Invoke-RiskyDisableSpoolerOnDCs; Pause-Menu }
            "9"  { Invoke-Remediate9ConfigurePdcTimeSource; Pause-Menu }
            "10" { Invoke-Remediate9EnableFirewallBaseline; Pause-Menu }
            "0" { return }
            default { }
        }
    } while ($true)
}

function Show-LapsMenu {
    do {
        Show-Banner
        Write-Host "=== WINDOWS LAPS ===" -ForegroundColor Cyan
        Write-Host "--- Audit (lecture seule) ---" -ForegroundColor DarkGray
        Write-MenuItem "1" "Etat du deploiement LAPS (schema, couverture)"
        Write-MenuItem "2" "Audit des droits de lecture/reset du mot de passe LAPS"
        Write-Host "--- Remediation ---" -ForegroundColor DarkGray
        Write-MenuItem "3" "(A VALIDER) Preparer le schema Active Directory pour LAPS"
        Write-MenuItem "4" "(A VALIDER) Deployer la GPO Windows LAPS"
        Write-MenuItem "5" "(A VALIDER) Configurer les droits de lecture/reset LAPS"
        Write-Host " 0. Retour au menu principal"
        Write-Host ""
        $choice = Read-Host "Votre choix"
        switch ($choice) {
            "1" { Invoke-Audit10LapsDeployment; Pause-Menu }
            "2" { Invoke-Audit10LapsPermissions; Pause-Menu }
            "3" { Invoke-Remediate10PrepareSchema; Pause-Menu }
            "4" { Invoke-Remediate10DeployGpo; Pause-Menu }
            "5" { Invoke-Remediate10SetPermissions; Pause-Menu }
            "0" { return }
            default { }
        }
    } while ($true)
}

function Show-PasswordAuthMenu {
    do {
        Show-Banner
        Write-Host "=== MOTS DE PASSE ET AUTHENTIFICATION ===" -ForegroundColor Cyan
        Write-Host "--- Audit (lecture seule) ---" -ForegroundColor DarkGray
        Write-MenuItem "1" "Rapport des comptes avec mot de passe n'expirant jamais"
        Write-MenuItem "2" "Audit de la politique de mot de passe par defaut du domaine"
        Write-Host "--- Remediation ---" -ForegroundColor DarkGray
        Write-MenuItem "3" "(SAFE) Retirer le flag 'Mot de passe non requis' sur les comptes concernes"
        Write-MenuItem "4" "(A VALIDER) Corriger la politique de mot de passe par defaut du domaine"
        Write-MenuItem "5" "(A VALIDER) Creer une Fine-Grained Password Policy pour les comptes de service"
        Write-MenuItem "6" "(SAFE) Generer les recommandations MFA / Conditional Access (hybride)"
        Write-Host " 0. Retour au menu principal"
        Write-Host ""
        $choice = Read-Host "Votre choix"
        switch ($choice) {
            "1" { Invoke-ReportPasswordNeverExpires; Pause-Menu }
            "2" { Invoke-Audit11DefaultPasswordPolicy; Pause-Menu }
            "3" { Invoke-SafeClearPasswordNotRequired; Pause-Menu }
            "4" { Invoke-Remediate11HardenDefaultPasswordPolicy; Pause-Menu }
            "5" { Invoke-Remediate11CreateServiceAccountFGPP; Pause-Menu }
            "6" { Invoke-Remediate11GenerateMfaRecommendations; Pause-Menu }
            "0" { return }
            default { }
        }
    } while ($true)
}

function Show-NetworkAntiRelayMenu {
    do {
        Show-Banner
        Write-Host "=== RESEAU ET ANTI-RELAY ===" -ForegroundColor Cyan
        Write-Host "--- Audit (lecture seule) ---" -ForegroundColor DarkGray
        Write-MenuItem "1" "Audit de la Global Query Block List DNS (WPAD/ISATAP)"
        Write-MenuItem "2" "Audit des ports/services exposes sur les DC"
        Write-Host "--- Remediation ---" -ForegroundColor DarkGray
        Write-MenuItem "3" "(A VALIDER) Desactiver LLMNR via GPO (domaine entier)"
        Write-MenuItem "4" "(SAFE) Retablir la Global Query Block List (wpad/isatap)"
        Write-MenuItem "5" "(A VALIDER) Desactiver NetBIOS sur TCP/IP sur des machines choisies"
        Write-MenuItem "6" "(A VALIDER) Durcir RPC (clients non authentifies, resolution du mappeur)"
        Write-MenuItem "7" "(A VALIDER) Durcir WinRM (authentification Basic desactivee, trafic chiffre)"
        Write-MenuItem "8" "(A VALIDER) Restreindre l'enumeration distante SAM/SAMR"
        Write-Host " 0. Retour au menu principal"
        Write-Host ""
        $choice = Read-Host "Votre choix"
        switch ($choice) {
            "1" { Invoke-Audit14GlobalQueryBlockList; Pause-Menu }
            "2" { Invoke-Audit14ExposedServices; Pause-Menu }
            "3" { Invoke-RiskyDisableLLMNR; Pause-Menu }
            "4" { Invoke-Remediate14RestoreGlobalQueryBlockList; Pause-Menu }
            "5" { Invoke-Remediate14DisableNetbiosOnComputers; Pause-Menu }
            "6" { Invoke-Remediate14RestrictRpc; Pause-Menu }
            "7" { Invoke-Remediate14RestrictWinRm; Pause-Menu }
            "8" { Invoke-Remediate14RestrictSamEnumeration; Pause-Menu }
            "0" { return }
            default { }
        }
    } while ($true)
}

function Show-GpoBaselineMenu {
    do {
        Show-Banner
        Write-Host "=== GPO DE DURCISSEMENT (SOCLE GPO-SEC-*) ===" -ForegroundColor Cyan
        Write-Host "--- Audit (lecture seule) ---" -ForegroundColor DarkGray
        Write-MenuItem "1" "Etat du socle GPO-SEC-* et des sauvegardes de GPO"
        Write-Host "--- Remediation ---" -ForegroundColor DarkGray
        Write-MenuItem "2" "(SAFE) Sauvegarder TOUTES les GPO du domaine"
        Write-MenuItem "3" "(SAFE) Creer les GPO manquantes du socle GPO-SEC-* (non liees)"
        Write-Host " 0. Retour au menu principal"
        Write-Host ""
        $choice = Read-Host "Votre choix"
        switch ($choice) {
            "1" { Invoke-Audit12GpoBaselineStatus; Pause-Menu }
            "2" { Invoke-Remediate12BackupAllGpos; Pause-Menu }
            "3" { Invoke-Remediate12CreateBaselineGpoShells; Pause-Menu }
            "0" { return }
            default { }
        }
    } while ($true)
}

function Show-WorkstationsServersMenu {
    do {
        Show-Banner
        Write-Host "=== POSTES ET SERVEURS MEMBRES ===" -ForegroundColor Cyan
        Write-Host "--- Audit (lecture seule) ---" -ForegroundColor DarkGray
        Write-MenuItem "1" "Etat de Microsoft Defender sur des machines choisies"
        Write-MenuItem "2" "Audit des administrateurs locaux sur des machines choisies"
        Write-Host "--- Remediation ---" -ForegroundColor DarkGray
        Write-MenuItem "3" "(A VALIDER) Renforcer Microsoft Defender via GPO (Cloud/Reseau/SmartScreen/ASR)"
        Write-MenuItem "4" "(A VALIDER) Restreindre RDP via GPO (NLA obligatoire)"
        Write-MenuItem "5" "(A VALIDER) Retirer des comptes des administrateurs locaux"
        Write-MenuItem "6" "(SAFE) Etendre la journalisation PowerShell aux postes/serveurs choisis"
        Write-MenuItem "7" "(A VALIDER) Bloquer les scripts .vbs/.js (Windows Script Host)"
        Write-MenuItem "8" "(A VALIDER) Activer le pare-feu Windows (3 profils)"
        Write-Host " 0. Retour au menu principal"
        Write-Host ""
        $choice = Read-Host "Votre choix"
        switch ($choice) {
            "1" { Invoke-Audit13DefenderStatus; Pause-Menu }
            "2" { Invoke-Audit13LocalAdmins; Pause-Menu }
            "3" { Invoke-Remediate13EnableDefenderProtections; Pause-Menu }
            "4" { Invoke-Remediate13RestrictRdp; Pause-Menu }
            "5" { Invoke-Remediate13CleanupLocalAdmins; Pause-Menu }
            "6" { Invoke-Remediate13EnablePowerShellLoggingExtended; Pause-Menu }
            "7" { Invoke-Remediate13DisableWindowsScriptHost; Pause-Menu }
            "8" { Invoke-Remediate13EnableFirewallBaseline; Pause-Menu }
            "0" { return }
            default { }
        }
    } while ($true)
}

function Show-BackupResilienceMenu {
    do {
        Show-Banner
        Write-Host "=== SAUVEGARDE ET RESILIENCE AD ===" -ForegroundColor Cyan
        Write-Host "--- Audit (lecture seule) ---" -ForegroundColor DarkGray
        Write-MenuItem "1" "Etat des sauvegardes System State sur les DC"
        Write-Host "--- Remediation ---" -ForegroundColor DarkGray
        Write-MenuItem "2" "(SAFE) Activer la Corbeille Active Directory"
        Write-MenuItem "3" "(A VALIDER) Planifier une sauvegarde System State quotidienne"
        Write-MenuItem "4" "(SAFE) Generer les procedures de recuperation (objet / DC / foret)"
        Write-Host " 0. Retour au menu principal"
        Write-Host ""
        $choice = Read-Host "Votre choix"
        switch ($choice) {
            "1" { Invoke-Audit17SystemStateBackupStatus; Pause-Menu }
            "2" { Invoke-SafeEnableRecycleBin; Pause-Menu }
            "3" { Invoke-Remediate17ScheduleSystemStateBackup; Pause-Menu }
            "4" { Invoke-Remediate17GenerateRecoveryProcedures; Pause-Menu }
            "0" { return }
            default { }
        }
    } while ($true)
}

function Show-ObsolescenceMenu {
    do {
        Show-Banner
        Write-Host "=== OBSOLESCENCE ===" -ForegroundColor Cyan
        Write-Host "--- Audit (lecture seule) ---" -ForegroundColor DarkGray
        Write-MenuItem "1" "Inventaire des systemes d'exploitation non/bientot non supportes"
        Write-MenuItem "2" "Protocoles obsoletes actifs sur des machines choisies (SMBv1, TLS 1.0/1.1)"
        Write-Host "--- Remediation / outillage ---" -ForegroundColor DarkGray
        Write-MenuItem "3" "(SAFE) Generer le plan de traitement de l'obsolescence (consolide)"
        Write-Host " 0. Retour au menu principal"
        Write-Host ""
        Write-Host "(Les migrations lourdes elles-memes sont hors perimetre de ce script.)" -ForegroundColor DarkGray
        $choice = Read-Host "Votre choix"
        switch ($choice) {
            "1" { Invoke-Audit18UnsupportedOS; Pause-Menu }
            "2" { Invoke-Audit18LegacyProtocolsOnComputers; Pause-Menu }
            "3" { Invoke-Remediate18GenerateTreatmentPlan; Pause-Menu }
            "0" { return }
            default { }
        }
    } while ($true)
}

function Show-LoggingDetectionMenu {
    do {
        Show-Banner
        Write-Host "=== JOURNALISATION ET DETECTION ===" -ForegroundColor Cyan
        Write-Host "--- Audit (lecture seule) ---" -ForegroundColor DarkGray
        Write-MenuItem "1" "Audit du SACL sur les objets sensibles (racine du domaine, AdminSDHolder)"
        Write-Host "--- Remediation (SAFE) ---" -ForegroundColor DarkGray
        Write-MenuItem "2" "(SAFE) Activer l'audit avance sur les DC (auditpol)"
        Write-MenuItem "3" "(SAFE) Activer la journalisation PowerShell (Script Block Logging)"
        Write-Host "--- Remediation (A VALIDER) ---" -ForegroundColor DarkGray
        Write-MenuItem "4" "(A VALIDER) Configurer l'audit SACL sur les objets sensibles"
        Write-MenuItem "5" "(A VALIDER) Configurer la redirection des journaux vers un collecteur (WEF/SIEM)"
        Write-Host " 0. Retour au menu principal"
        Write-Host ""
        $choice = Read-Host "Votre choix"
        switch ($choice) {
            "1" { Invoke-Audit19ObjectAuditingStatus; Pause-Menu }
            "2" { Invoke-SafeEnableDCAuditPolicy; Pause-Menu }
            "3" { Invoke-SafeEnablePowerShellLogging; Pause-Menu }
            "4" { Invoke-Remediate19ConfigureObjectAuditing; Pause-Menu }
            "5" { Invoke-Remediate19ConfigureEventForwarding; Pause-Menu }
            "0" { return }
            default { }
        }
    } while ($true)
}

function Show-FinalControlMenu {
    do {
        Show-Banner
        Write-Host "=== CONTROLE FINAL ===" -ForegroundColor Cyan
        Write-Host "--- Audit (lecture seule) ---" -ForegroundColor DarkGray
        Write-MenuItem "1" "Lancer le controle final consolide (rejoue les audits cles de plusieurs themes)"
        Write-Host "--- Remediation / outillage ---" -ForegroundColor DarkGray
        Write-MenuItem "2" "(SAFE) Initialiser/completer le registre des exceptions"
        Write-Host " 0. Retour au menu principal"
        Write-Host ""
        Write-Host "(Ne remplace pas l'outil separe de comparaison PingCastle avant/apres.)" -ForegroundColor DarkGray
        $choice = Read-Host "Votre choix"
        switch ($choice) {
            "1" { Invoke-Audit20FinalControlReport; Pause-Menu }
            "2" { Invoke-Remediate20InitExceptionsRegister; Pause-Menu }
            "0" { return }
            default { }
        }
    } while ($true)
}

function Show-ReportMenu {
    do {
        Show-Banner
        Write-Host "=== RAPPORTS TRANSVERSES - lecture seule, aucune modification ===" -ForegroundColor Magenta
        Write-MenuItem "1" "Export comptes inactifs (utilisateurs/ordinateurs)"
        Write-MenuItem "2" "Export global (rapports rapides multi-themes)"
        Write-Host " 0. Retour au menu principal"
        Write-Host ""
        $choice = Read-Host "Votre choix"
        switch ($choice) {
            "1" { Invoke-ReportInactiveAccounts; Pause-Menu }
            "2" { Invoke-ReportAll; Pause-Menu }
            "0" { return }
            default { }
        }
    } while ($true)
}

function Show-InactiveAccountsAutomationMenu {
    do {
        Show-Banner
        Write-Host "=== HYGIENE DES COMPTES INACTIFS ET AUTOMATISATION ===" -ForegroundColor Cyan
        Write-Host "--- Remediation manuelle ---" -ForegroundColor DarkGray
        Write-MenuItem "1" "(A VALIDER) Desactiver les comptes inactifs par anciennete (quarantaine)"
        Write-MenuItem "2" "(A VALIDER) Desactiver postes/utilisateurs a partir d'une DATE choisie"
        Write-Host "--- Automatisation (tache planifiee) ---" -ForegroundColor DarkGray
        Write-MenuItem "3" "Configurer la tache planifiee de desactivation automatique"
        Write-MenuItem "4" "Afficher l'etat de la tache planifiee existante"
        Write-MenuItem "5" "Supprimer la tache planifiee"
        Write-Host " 0. Retour au menu principal"
        Write-Host ""
        $choice = Read-Host "Votre choix"
        switch ($choice) {
            "1" { Invoke-RiskyDisableInactiveAccounts; Pause-Menu }
            "2" { Invoke-RiskyDisableByDate; Pause-Menu }
            "3" { Invoke-AutomationSetupScheduledTask; Pause-Menu }
            "4" { Invoke-AutomationShowStatus; Pause-Menu }
            "5" { Invoke-AutomationRemoveScheduledTask; Pause-Menu }
            "0" { return }
            default { }
        }
    } while ($true)
}

function Show-MainMenu {
    do {
        Show-Banner
        Write-Host "MENU PRINCIPAL" -ForegroundColor White

        Write-MenuCategory "Identite et comptes"
        Write-MenuItem "1" "Comptes a privileges" -Color Cyan
        Write-MenuItem "2" "Comptes de service" -Color Cyan
        Write-MenuItem "3" "Mots de passe et authentification" -Color Cyan

        Write-MenuCategory "Authentification et protocoles"
        Write-MenuItem "4" "Kerberos et delegations" -Color Cyan
        Write-MenuItem "5" "NTLM / LM" -Color Cyan
        Write-MenuItem "6" "SMB, SYSVOL et NETLOGON" -Color Cyan
        Write-MenuItem "7" "LDAP / LDAPS" -Color Cyan

        Write-MenuCategory "Infrastructure"
        Write-MenuItem "8"  "Controleurs de domaine" -Color Cyan
        Write-MenuItem "9"  "Windows LAPS" -Color Cyan
        Write-MenuItem "10" "GPO de durcissement (socle GPO-SEC-*)" -Color Cyan
        Write-MenuItem "11" "Postes et serveurs membres" -Color Cyan
        Write-MenuItem "12" "Reseau et anti-relay" -Color Cyan

        Write-MenuCategory "Resilience et pilotage"
        Write-MenuItem "13" "Sauvegarde et resilience AD" -Color Cyan
        Write-MenuItem "14" "Obsolescence" -Color Cyan
        Write-MenuItem "15" "Journalisation et detection" -Color Cyan
        Write-MenuItem "16" "Controle final" -Color Cyan
        Write-MenuItem "17" "Rapports transverses (export global)" -Color Magenta
        Write-MenuItem "18" "Hygiene des comptes inactifs et automatisation" -Color Cyan

        Write-Host ""
        Write-Host " [R] Rechercher une action par mot-cle" -ForegroundColor DarkCyan
        $modeLabel = if ($Script:SimulationMode) { "Activer le mode REEL (desactiver la simulation)" } else { "Repasser en mode SIMULATION" }
        Write-Host (" [S] {0}" -f $modeLabel) -ForegroundColor Yellow
        Write-Host " [Q] Quitter"
        Write-Host ""
        $choice = Read-Host "Votre choix"
        switch ($choice.ToUpper()) {
            "1"  { Show-PrivilegedAccountsMenu }
            "2"  { Show-ServiceAccountsMenu }
            "3"  { Show-PasswordAuthMenu }
            "4"  { Show-KerberosMenu }
            "5"  { Show-NtlmMenu }
            "6"  { Show-SmbSysvolMenu }
            "7"  { Show-LdapMenu }
            "8"  { Show-DomainControllersMenu }
            "9"  { Show-LapsMenu }
            "10" { Show-GpoBaselineMenu }
            "11" { Show-WorkstationsServersMenu }
            "12" { Show-NetworkAntiRelayMenu }
            "13" { Show-BackupResilienceMenu }
            "14" { Show-ObsolescenceMenu }
            "15" { Show-LoggingDetectionMenu }
            "16" { Show-FinalControlMenu }
            "17" { Show-ReportMenu }
            "18" { Show-InactiveAccountsAutomationMenu }
            "R" { Invoke-SearchActions; Pause-Menu }
            "S" {
                if ($Script:SimulationMode) {
                    Write-Host ""
                    Write-Host "Vous allez desactiver le mode simulation : les actions confirmees seront REELLEMENT appliquees." -ForegroundColor Red
                    $confirm = Read-Host "Tapez EXACTEMENT 'CONFIRMER' pour passer en mode reel"
                    if ($confirm -ceq "CONFIRMER") {
                        $Script:SimulationMode = $false
                        Write-Log "Mode REEL active par l'utilisateur." -Level WARN
                    }
                } else {
                    $Script:SimulationMode = $true
                    Write-Log "Retour au mode SIMULATION." -Level INFO
                }
            }
            "Q" { return }
            default { }
        }
    } while ($true)
}

# ============================================================
#  POINT D'ENTREE
# ============================================================

Show-Banner
Write-Log "Demarrage du script de remediation AD." -Level INFO

if (-not (Test-Prerequisites)) {
    Write-Log "Prerequis non satisfaits. Corrigez les points ci-dessus avant de continuer." -Level ERROR
    Read-Host "Appuyez sur Entree pour quitter"
    return
}

Write-Log "Mode simulation actif par defaut. Utilisez [S] dans le menu principal pour appliquer reellement les actions." -Level WARN
Pause-Menu

Show-MainMenu

Write-Log "Fin du script." -Level INFO
