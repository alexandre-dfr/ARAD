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
$Script:QuarantineOUName = "OU_QUARANTAINE_COMPTES_INACTIFS"
$Script:DisableUserOUName = "disable_user"
$Script:DisableComputerOUName = "disable_computer"
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

function Select-ExclusionOUs {
    <#
        Garde-fou : permet d'exclure certaines UO (comptes de service, serveurs
        critiques, postes VIP...) des actions de desactivation par date/anciennete.
    #>
    param([Parameter(Mandatory)][string]$Label)

    $ous = @(Get-ADOrganizationalUnit -Filter * -ErrorAction SilentlyContinue | Sort-Object DistinguishedName)
    if (-not $ous) { return @() }

    Write-Host ""
    Write-Host ("UO disponibles a EXCLURE pour {0} :" -f $Label) -ForegroundColor DarkGray
    for ($i = 0; $i -lt $ous.Count; $i++) { Write-Host ("  [{0}] {1}" -f $i, $ous[$i].DistinguishedName) }
    $sel = Read-Host ("Numeros des UO a exclure pour {0}, separes par une virgule (vide = aucune exclusion)" -f $Label)
    if ([string]::IsNullOrWhiteSpace($sel)) { return @() }

    $idx = @($sel -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ } | Where-Object { $_ -lt $ous.Count })
    return @($idx | ForEach-Object { $ous[$_].DistinguishedName })
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
#  SECTION 1 - ACTIONS SAFE (aucune incidence fonctionnelle)
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
    Write-Host "         consultez le rapport dedie dans le menu [3] Rapports." -ForegroundColor DarkGray

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
    Write-Log "Rappel : l'audit du logon (menu SAFE 'audit avance sur les DC') doit aussi etre actif pour que le rapport NTLMv1/LM (menu [3] Rapports) puisse remonter des resultats." -Level WARN
}

function Invoke-SafeEnablePowerShellLogging {
    Write-Host "`n--- Activation de la journalisation PowerShell (Script Block Logging) via GPO ---" -ForegroundColor Cyan
    Write-Host "Impact : AUCUN fonctionnel. Journalisation uniquement (peut augmenter legerement les logs)." -ForegroundColor DarkGray

    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Log "Le module GroupPolicy (RSAT-GPMC) n'est pas installe sur ce poste." -Level ERROR
        return
    }
    Import-Module GroupPolicy -ErrorAction SilentlyContinue

    $gpoName = "ADHC - Audit PowerShell Logging"
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

    $gpoName = "ADHC - Activation WinRM sur les DC"
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

function Invoke-SafeAll {
    Write-Host "`n=== Execution de toutes les actions SAFE ===" -ForegroundColor Cyan
    if (-not (Confirm-Action "Lancer l'ensemble des actions SAFE listees ci-dessus, une par une")) { return }
    Invoke-SafeEnableWinRmOnDCs
    Invoke-SafeEnableRecycleBin
    Invoke-SafeDisableGuest
    Invoke-SafeProtectOUs
    Invoke-SafeSetMachineAccountQuotaZero
    Invoke-SafeEnableDCAuditPolicy
    Invoke-SafeEnableNtlmAudit
    Invoke-SafeEnablePowerShellLogging
    Invoke-SafeClearPasswordNotRequired
}

# ============================================================
#  SECTION 2 - ACTIONS A VALIDER (impact potentiel)
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
# Deploye et execute automatiquement par la tache planifiee "ADHC - Rotation KRBTGT".
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
            $taskName = "ADHC - Rotation KRBTGT"
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\ADHC-Scripts\Reset-KrbtgtScheduled.ps1"'
            $trigger = New-ScheduledTaskTrigger -Daily -DaysInterval $intervalDays -At "02:00"
            $principal = New-ScheduledTaskPrincipal -UserId "$domainNetbios\$gmsaSam`$" -LogonType Password -RunLevel Highest
            $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd

            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Rotation automatique du mot de passe KRBTGT - deploye par le script de remediation AD"
        } -ArgumentList $gmsaName, $domainNetbios, $days -ErrorAction Stop
    }

    Write-Log ("Tache planifiee 'ADHC - Rotation KRBTGT' creee sur {0}, execution tous les {1} jours a 02:00, sous le compte {2}\{3}$." -f $targetDC, $days, $domainNetbios, $gmsaName) -Level OK
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
    Write-Host "Avant de continuer : avez-vous active l'audit NTLM (menu SAFE) et consulte le rapport" -ForegroundColor Yellow
    Write-Host "'NTLMv1/LM detecte' (menu [3] Rapports) pour identifier les comptes/postes concernes ?" -ForegroundColor Yellow
    if ((Read-Host "Continuer sans avoir verifie ce rapport est deconseille. Continuer quand meme ? (O/N)") -notmatch '^[oOyY]') { return }

    $level = Read-Host "Niveau LmCompatibilityLevel a appliquer (3=intermediaire recommande pour test, 5=NTLMv2 uniquement) [3/5]"
    if ($level -notin @("3","5")) { Write-Log "Valeur invalide, action annulee." -Level WARN; return }

    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Log "Le module GroupPolicy (RSAT-GPMC) n'est pas installe sur ce poste." -Level ERROR
        return
    }
    Import-Module GroupPolicy -ErrorAction SilentlyContinue

    $gpoName = "ADHC - Durcissement NTLM (LmCompatibilityLevel=$level)"
    if (-not (Confirm-Action ("Creer/lier la GPO '{0}' au niveau du domaine" -f $gpoName) -Strong)) { return }

    Invoke-Guarded -Description ("GPO LmCompatibilityLevel=$level") -Action {
        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        if (-not $gpo) { $gpo = New-GPO -Name $gpoName }
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\System\CurrentControlSet\Control\Lsa" -ValueName "LmCompatibilityLevel" -Type DWord -Value ([int]$level)
        Write-Log "GPO creee mais NON liee automatiquement. Liez-la manuellement a un OU pilote avant deploiement large." -Level WARN
    }
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

    $gpoName = "ADHC - Desactivation LLMNR"
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
#  SECTION 3 - RAPPORTS (lecture seule, aucune modification)
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
    $groups = @("Domain Admins","Enterprise Admins","Schema Admins","Administrators","Account Operators","Backup Operators","Protected Users")
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
    Write-Host "Necessite l'audit NTLM prealablement active (menu SAFE 'Activer l'audit NTLM') ainsi" -ForegroundColor DarkGray
    Write-Host "que l'audit des connexions actif sur les DC (menu SAFE 'audit avance'). Sans ces deux" -ForegroundColor DarkGray
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
    Write-Log "Validez ces comptes/postes AVANT d'appliquer l'action 'Desactiver NTLMv1/LM' (menu A VALIDER)." -Level WARN
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
# Deploye et execute automatiquement par la tache planifiee "ADHC - Desactivation Auto (date/anciennete)".
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
            $taskName = "ADHC - Desactivation Auto (date/anciennete)"
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\ADHC-Scripts\Disable-ByDate.ps1"'
            $trigger = New-ScheduledTaskTrigger -Daily -DaysInterval $intervalDays -At "03:00"
            $principal = New-ScheduledTaskPrincipal -UserId "$domainNetbios\$gmsaSam`$" -LogonType Password -RunLevel Highest
            $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd

            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Desactivation automatique des comptes utilisateurs/ordinateurs inactifs - deploye par le script de remediation AD"
        } -ArgumentList $gmsaName, $domainNetbios, $daysInterval -ErrorAction Stop
    }

    Write-Log ("Tache planifiee 'ADHC - Desactivation Auto (date/anciennete)' creee sur {0}, execution tous les {1} jours a 03:00, sous le compte {2}\{3}$." -f $targetDC, $daysInterval, $domainNetbios, $gmsaName) -Level OK
    Write-Log "Journal local sur le DC : C:\ADHC-Scripts\Disable-ByDate.log (+ journal d'evenements Application, source ADHC-AutoDisable)." -Level INFO
    Write-Log "Pour changer les seuils/exclusions, relancez cette configuration : elle regenere et remplace le script deploye et la tache." -Level INFO
}

function Invoke-AutomationShowStatus {
    Write-Host "`n--- Etat de la tache planifiee de desactivation automatique ---" -ForegroundColor Magenta
    $dcs = Get-DomainControllersList
    if (-not $dcs) { return }
    $taskName = "ADHC - Desactivation Auto (date/anciennete)"
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
            Unregister-ScheduledTask -TaskName "ADHC - Desactivation Auto (date/anciennete)" -Confirm:$false -ErrorAction Stop
        } -ErrorAction Stop
    }
}

# ============================================================
#  MENUS
# ============================================================

function Show-SafeMenu {
    do {
        Show-Banner
        Write-Host "=== [1] ACTIONS SAFE - aucune incidence sur la production ===" -ForegroundColor Green
        Write-Host " 1. Activer la Corbeille Active Directory"
        Write-Host " 2. Desactiver le compte Invite (Guest) s'il est actif"
        Write-Host " 3. Proteger toutes les OU contre la suppression accidentelle"
        Write-Host " 4. Limiter le quota de creation d'ordinateurs (ms-DS-MachineAccountQuota = 0)"
        Write-Host " 5. Activer l'audit avance sur les controleurs de domaine (auditpol)"
        Write-Host " 6. Activer la journalisation PowerShell (Script Block Logging) via GPO"
        Write-Host " 7. Retirer le flag 'Mot de passe non requis' sur les comptes concernes"
        Write-Host " 8. Activer l'audit NTLM (detection NTLMv1/LM avant blocage)"
        Write-Host " 9. Activer PowerShell Remoting (WinRM) sur les DC injoignables (GPO et/ou immediat via WMI)"
        Write-Host " 10. Executer TOUTES les actions SAFE"
        Write-Host " 0. Retour au menu principal"
        Write-Host ""
        $choice = Read-Host "Votre choix"
        switch ($choice) {
            "1"  { Invoke-SafeEnableRecycleBin; Pause-Menu }
            "2"  { Invoke-SafeDisableGuest; Pause-Menu }
            "3"  { Invoke-SafeProtectOUs; Pause-Menu }
            "4"  { Invoke-SafeSetMachineAccountQuotaZero; Pause-Menu }
            "5"  { Invoke-SafeEnableDCAuditPolicy; Pause-Menu }
            "6"  { Invoke-SafeEnablePowerShellLogging; Pause-Menu }
            "7"  { Invoke-SafeClearPasswordNotRequired; Pause-Menu }
            "8"  { Invoke-SafeEnableNtlmAudit; Pause-Menu }
            "9"  { Invoke-SafeEnableWinRmOnDCs; Pause-Menu }
            "10" { Invoke-SafeAll; Pause-Menu }
            "0" { return }
            default { }
        }
    } while ($true)
}

function Show-RiskyMenu {
    do {
        Show-Banner
        Write-Host "=== [2] ACTIONS A VALIDER - impact potentiel, fenetre de maintenance recommandee ===" -ForegroundColor Red
        Write-Host " 1.  Reinitialiser le mot de passe KRBTGT (1 des 2 executions requises)"
        Write-Host " 2.  Desactiver NTLMv1/LM (LmCompatibilityLevel) via GPO"
        Write-Host " 3.  Desactiver DES et forcer AES sur les comptes concernes"
        Write-Host " 4.  Marquer les comptes a privileges 'Sensible, ne peut etre delegue'"
        Write-Host " 5.  Ajouter les comptes Domain/Enterprise Admins dans 'Protected Users'"
        Write-Host " 6.  Rapport des delegations Kerberos (non contrainte/contrainte/RBCD)"
        Write-Host " 7.  Nettoyer le groupe Schema Admins"
        Write-Host " 8.  Arreter/desactiver le service Spooler sur les controleurs de domaine"
        Write-Host " 9.  Forcer la signature LDAP / channel binding sur les DC"
        Write-Host " 10. Desactiver LLMNR via GPO (domaine entier)"
        Write-Host " 11. Desactiver les comptes utilisateurs/ordinateurs inactifs (quarantaine)"
        Write-Host " 12. Forcer l'expiration des mots de passe des comptes a privileges"
        Write-Host " 13. Configurer la rotation KRBTGT automatique planifiee (gMSA dedie + tache planifiee)"
        Write-Host " 14. Desactiver postes/serveurs ET/OU utilisateurs a partir d'une DATE choisie (UO dediees + garde-fous)"
        Write-Host " 0.  Retour au menu principal"
        Write-Host ""
        $choice = Read-Host "Votre choix"
        switch ($choice) {
            "1"  { Invoke-RiskyResetKrbtgt; Pause-Menu }
            "2"  { Invoke-RiskyDisableNtlmV1; Pause-Menu }
            "3"  { Invoke-RiskyDisableDesForceAes; Pause-Menu }
            "4"  { Invoke-RiskySetPrivilegedNotDelegated; Pause-Menu }
            "5"  { Invoke-RiskyAddToProtectedUsers; Pause-Menu }
            "6"  { Invoke-RiskyReportDelegations; Pause-Menu }
            "7"  { Invoke-RiskyCleanupSchemaAdmins; Pause-Menu }
            "8"  { Invoke-RiskyDisableSpoolerOnDCs; Pause-Menu }
            "9"  { Invoke-RiskyEnforceLdapSigning; Pause-Menu }
            "10" { Invoke-RiskyDisableLLMNR; Pause-Menu }
            "11" { Invoke-RiskyDisableInactiveAccounts; Pause-Menu }
            "12" { Invoke-RiskyForcePasswordExpirationPrivileged; Pause-Menu }
            "13" { Invoke-RiskySetupKrbtgtScheduledRotation; Pause-Menu }
            "14" { Invoke-RiskyDisableByDate; Pause-Menu }
            "0"  { return }
            default { }
        }
    } while ($true)
}

function Show-ReportMenu {
    do {
        Show-Banner
        Write-Host "=== [3] RAPPORTS - lecture seule, aucune modification ===" -ForegroundColor Magenta
        Write-Host " 1. Export comptes inactifs (utilisateurs/ordinateurs)"
        Write-Host " 2. Export comptes avec mot de passe n'expirant jamais"
        Write-Host " 3. Export membres des groupes a privileges"
        Write-Host " 4. Export hotfix des controleurs de domaine"
        Write-Host " 5. Rapport NTLMv1/LM detecte (necessite l'audit NTLM actif, peut etre long)"
        Write-Host " 6. Export global (rapports rapides, hors NTLMv1/LM)"
        Write-Host " 0. Retour au menu principal"
        Write-Host ""
        $choice = Read-Host "Votre choix"
        switch ($choice) {
            "1" { Invoke-ReportInactiveAccounts; Pause-Menu }
            "2" { Invoke-ReportPasswordNeverExpires; Pause-Menu }
            "3" { Invoke-ReportPrivilegedGroups; Pause-Menu }
            "4" { Invoke-ReportDCHotfixes; Pause-Menu }
            "5" { Invoke-ReportNtlmV1Usage; Pause-Menu }
            "6" { Invoke-ReportAll; Pause-Menu }
            "0" { return }
            default { }
        }
    } while ($true)
}

function Show-AutomationMenu {
    do {
        Show-Banner
        Write-Host "=== [4] AUTOMATISATION - taches planifiees ===" -ForegroundColor Red
        Write-Host " 1. Configurer la tache planifiee de desactivation automatique (postes/utilisateurs)"
        Write-Host " 2. Afficher l'etat de la tache planifiee existante"
        Write-Host " 3. Supprimer la tache planifiee"
        Write-Host " 0. Retour au menu principal"
        Write-Host ""
        $choice = Read-Host "Votre choix"
        switch ($choice) {
            "1" { Invoke-AutomationSetupScheduledTask; Pause-Menu }
            "2" { Invoke-AutomationShowStatus; Pause-Menu }
            "3" { Invoke-AutomationRemoveScheduledTask; Pause-Menu }
            "0" { return }
            default { }
        }
    } while ($true)
}

function Show-MainMenu {
    do {
        Show-Banner
        Write-Host "MENU PRINCIPAL" -ForegroundColor White
        Write-Host " [1] Actions SAFE (aucune incidence prod)" -ForegroundColor Green
        Write-Host " [2] Actions A VALIDER (impact potentiel)" -ForegroundColor Red
        Write-Host " [3] Rapports (lecture seule)" -ForegroundColor Magenta
        Write-Host " [4] Automatisation (taches planifiees)" -ForegroundColor Red
        Write-Host ""
        $modeLabel = if ($Script:SimulationMode) { "Activer le mode REEL (desactiver la simulation)" } else { "Repasser en mode SIMULATION" }
        Write-Host (" [S] {0}" -f $modeLabel) -ForegroundColor Yellow
        Write-Host " [Q] Quitter"
        Write-Host ""
        $choice = Read-Host "Votre choix"
        switch ($choice.ToUpper()) {
            "1" { Show-SafeMenu }
            "2" { Show-RiskyMenu }
            "3" { Show-ReportMenu }
            "4" { Show-AutomationMenu }
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
