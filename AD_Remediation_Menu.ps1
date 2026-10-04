<#
    AD_Remediation_Menu.ps1
    ------------------------------------------------------------------
    Script de remediation Active Directory a menu, base sur les constats
    recurrents releves dans des rapports PingCastle (krbtgt, NTLMv1, LAPS,
    comptes inactifs, delegations, mots de passe n'expirant jamais, etc.)

    Trois familles d'actions (code couleur dans les menus) :
      [AUDIT]     -> lecture seule, aucune modification de l'annuaire/des serveurs
      [SAFE]      -> aucune incidence fonctionnelle sur la prod (fonctionnalites
                     additives, journalisation, protections sans changement de
                     comportement existant)
      [A VALIDER] -> impact potentiel sur des postes/applications/comptes de
                     service legacy. Fenetre de maintenance, confirmation tapee
                     explicitement, mode simulation actif par defaut.

    A executer en tant qu'Administrateur du domaine, depuis un poste avec
    le module ActiveDirectory (RSAT), idealement sur/depuis un DC.

    Ce script NE MODIFIE RIEN tant que le mode simulation n'est pas desactive
    (option [S] du menu principal) ET que l'action n'a pas ete confirmee.

    Parametres :
      -QuickAudit  : lance uniquement le diagnostic rapide (lecture seule),
                     genere le rapport HTML puis quitte (utilisable en tache
                     planifiee ou pour un etat des lieux express).
      -LogDir      : dossier des journaux/rapports (defaut : .\Logs).
      -NoClear     : ne pas effacer l'ecran entre deux menus (utile pour
                     garder l'historique d'une session dans la console).
      -Action      : lance directement une action "theme.item" (ex : 4.2), puis
                     quitte (les questions interactives de l'action restent posees).
      -Simulation  : avec -Action, force le mode simulation (defaut). -Action 1.1
                     -Simulation:$false demande la confirmation habituelle du mode reel.

    Le script peut etre "dot-source" (. .\AD_Remediation_Menu.ps1) sans lancer le
    menu : utilise par les tests automatises (Tests\Invoke-SelfTest.ps1).
    ------------------------------------------------------------------
#>

[CmdletBinding()]
param(
    [switch]$QuickAudit,
    [string]$LogDir,
    [switch]$NoClear,
    [ValidatePattern('^\d{1,2}[\.\-]\d{1,2}$')][string]$Action,
    [bool]$Simulation = $true
)

# ============================================================
#  CONFIGURATION GLOBALE
# ============================================================

$Script:Version        = "3.1"
$Script:SimulationMode = $true
$Script:NoClear        = [bool]$NoClear
$Script:SessionStamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$Script:ScriptRoot     = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$Script:LogDir         = if ($LogDir) { $LogDir } else { Join-Path -Path $Script:ScriptRoot -ChildPath "Logs" }
$Script:ReportDir      = Join-Path -Path $Script:LogDir -ChildPath ("Rapports_{0}" -f $Script:SessionStamp)
$Script:LogFile        = Join-Path -Path $Script:LogDir -ChildPath ("Remediation_AD_{0}.log" -f $Script:SessionStamp)

$Script:QuarantineOUName      = "SEC-OU_QUARANTAINE_COMPTES_INACTIFS"
$Script:DisableUserOUName     = "SEC-disable_user"
$Script:DisableComputerOUName = "SEC-disable_computer"
$Script:RemoteScriptDir       = "C:\SEC-Scripts"

# Groupes a privileges exclus PAR DEFAUT (jamais desactives/deplaces) des actions de
# desactivation par date/anciennete. Les noms sont des CLES : ils sont resolus par SID
# bien connu (cf. Resolve-ADGroupRef), donc fonctionnent aussi sur un AD francise
# ("Admins du domaine", "Administrateurs"...). Des groupes supplementaires peuvent
# etre ajoutes de maniere interactive au moment de l'action.
$Script:DefaultExcludedGroups = @(
    "Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators",
    "Account Operators", "Backup Operators", "Server Operators", "Print Operators",
    "Group Policy Creator Owners", "Protected Users", "DnsAdmins", "Cert Publishers",
    "Key Admins", "Enterprise Key Admins"
)
# Groupes d'administration "tier 0" au sens strict.
$Script:AdminGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
# Groupes a privileges (administration + operateurs integres).
$Script:PrivilegedGroups = @($Script:AdminGroups + @("Account Operators", "Backup Operators", "Server Operators", "Print Operators"))

# Statistiques de session (affichees dans la synthese de fin / rapport HTML).
$Script:SessionStats = [ordered]@{
    Actions  = 0
    Succes   = 0
    Echecs   = 0
    Simulees = 0
}
$Script:SessionReports        = [System.Collections.Generic.List[string]]::new()
$Script:SessionHistory        = [System.Collections.Generic.List[object]]::new()
$Script:CurrentActionFailures = 0
$Script:LastDiagnostic        = $null
$Script:PreviousDiagnostic    = $null
$Script:StrictGroupQueries    = $false
$Script:LastGuardedResult     = $null
$Script:LastActionRef         = $null
$Script:DCListCache           = $null
$Script:DiagHistoryDir        = Join-Path -Path $Script:LogDir -ChildPath "Diagnostics"

foreach ($dir in @($Script:LogDir)) {
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
}

# ============================================================
#  FONCTIONS UTILITAIRES (journal, affichage, saisie)
# ============================================================

function Write-Log {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
        [ValidateSet("INFO","OK","WARN","ERROR","ACTION","SIMU")][string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[{0}] [{1}] {2}" -f $timestamp, $Level, $Message

    $color = switch ($Level) {
        "OK"     { "Green" }
        "WARN"   { "Yellow" }
        "ERROR"  { "Red" }
        "ACTION" { "Cyan" }
        "SIMU"   { "DarkGray" }
        default  { "Gray" }
    }
    Write-Host $line -ForegroundColor $color

    try { Add-Content -LiteralPath $Script:LogFile -Value $line -Encoding UTF8 -ErrorAction Stop } catch { }
}

function Write-OutcomeLog {
    <#
        Message de RESULTAT a afficher apres une ou plusieurs actions Invoke-Guarded.
        Evite les faux positifs dans le journal : en simulation, rien n'a ete fait (le
        message est requalifie) ; si une action de la sequence a echoue, le message de
        succes est remplace par un avertissement explicite.
    #>
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("INFO","OK","WARN")][string]$Level = "OK"
    )
    if ($Script:SimulationMode) {
        Write-Log ("[SIMULATION] En mode reel : {0}" -f $Message) -Level SIMU
    } elseif ($Script:CurrentActionFailures -gt 0) {
        Write-Log ("{0} echec(s) pendant l'action - resultat NON garanti : {1}" -f $Script:CurrentActionFailures, $Message) -Level WARN
    } else {
        Write-Log $Message -Level $Level
    }
}

function Write-Section {
    param([Parameter(Mandatory)][string]$Title, [string]$Color = "Cyan")
    Write-Host ""
    Write-Host ("--- {0} ---" -f $Title) -ForegroundColor $Color
}

function Write-Info {
    # Texte explicatif (gris fonce), une ligne par element.
    param([Parameter(ValueFromRemainingArguments)][string[]]$Lines)
    foreach ($l in $Lines) { Write-Host $l -ForegroundColor DarkGray }
}

function Get-CurrentUserName {
    try { return [Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { return ("{0}\{1}" -f $env:USERDOMAIN, $env:USERNAME) }
}

function Get-CurrentUserSid {
    try { return [Security.Principal.WindowsIdentity]::GetCurrent().User.Value } catch { return $null }
}

function Clear-Screen {
    if (-not $Script:NoClear) { try { Clear-Host } catch { } }
}

function Show-Banner {
    Clear-Screen
    $line = "=" * 78
    Write-Host $line -ForegroundColor DarkCyan
    Write-Host ("  REMEDIATION ACTIVE DIRECTORY (base PingCastle)  -  v{0}" -f $Script:Version) -ForegroundColor DarkCyan
    Write-Host $line -ForegroundColor DarkCyan
    if ($Script:SimulationMode) {
        Write-Host "  Mode      : SIMULATION (aucune modification appliquee)" -ForegroundColor Yellow
    } else {
        Write-Host "  Mode      : REEL - LES ACTIONS CONFIRMEES SONT APPLIQUEES" -ForegroundColor White -BackgroundColor DarkRed
    }
    if ($Script:ADDomainCache) {
        Write-Host ("  Domaine   : {0}   (PDC : {1})" -f $Script:ADDomainCache.DNSRoot, $Script:ADDomainCache.PDCEmulator) -ForegroundColor DarkGray
    }
    Write-Host ("  Operateur : {0}" -f (Get-CurrentUserName)) -ForegroundColor DarkGray
    Write-Host ("  Journal   : {0}" -f $Script:LogFile) -ForegroundColor DarkGray
    $s = $Script:SessionStats
    if ($s.Actions -gt 0 -or $Script:SessionReports.Count -gt 0) {
        Write-Host ("  Session   : {0} action(s) [{1} ok / {2} echec / {3} simulee(s)], {4} rapport(s)" -f $s.Actions, $s.Succes, $s.Echecs, $s.Simulees, $Script:SessionReports.Count) -ForegroundColor DarkGray
    }
    if ($Script:LastDiagnostic) {
        $d = $Script:LastDiagnostic
        $nc = @($d.Findings | Where-Object { $_.Statut -eq 'CRITIQUE' }).Count
        $na = @($d.Findings | Where-Object { $_.Statut -eq 'ALERTE' }).Count
        Write-Host "  Diagnostic: " -ForegroundColor DarkGray -NoNewline
        Write-Host ("indice {0}/100" -f $d.Score) -ForegroundColor $(if ($d.Score -ge 80) { 'Green' } elseif ($d.Score -ge 50) { 'Yellow' } else { 'Red' }) -NoNewline
        Write-Host (" - {0} critique(s), {1} alerte(s) - {2:HH:mm} (actions concernees marquees '!' dans les menus)" -f $nc, $na, $d.Date) -ForegroundColor DarkGray
    }
    Write-Host $line -ForegroundColor DarkCyan
    Write-Host "  Legende : " -ForegroundColor DarkGray -NoNewline
    Write-Host "[AUDIT] " -ForegroundColor Cyan -NoNewline
    Write-Host "lecture seule  " -ForegroundColor DarkGray -NoNewline
    Write-Host "[SAFE] " -ForegroundColor Green -NoNewline
    Write-Host "sans impact prod  " -ForegroundColor DarkGray -NoNewline
    Write-Host "[A VALIDER] " -ForegroundColor Red -NoNewline
    Write-Host "impact potentiel  " -ForegroundColor DarkGray -NoNewline
    Write-Host "[OUTIL]" -ForegroundColor Gray
    Write-Host $line -ForegroundColor DarkCyan
}

function Read-YesNo {
    param([Parameter(Mandatory)][string]$Prompt, [bool]$Default = $false)
    $suffix = if ($Default) { "(O/n)" } else { "(o/N)" }
    $resp = Read-Host ("{0} {1}" -f $Prompt, $suffix)
    if ([string]::IsNullOrWhiteSpace($resp)) { return $Default }
    return ($resp.Trim() -match '^[oOyY]')
}

function Read-IntValue {
    <#
        Saisie d'un entier avec valeur par defaut et bornes : une saisie vide garde la
        valeur par defaut ; une saisie invalide/hors bornes est signalee (au lieu d'etre
        remplacee silencieusement) et redemandee.
    #>
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [Parameter(Mandatory)][int]$Default,
        [int]$Min = 0,
        [int]$Max = [int]::MaxValue
    )
    while ($true) {
        $raw = Read-Host ("{0} [defaut {1}]" -f $Prompt, $Default)
        if ([string]::IsNullOrWhiteSpace($raw)) { return $Default }
        $val = 0
        if ([int]::TryParse($raw.Trim(), [ref]$val) -and $val -ge $Min -and $val -le $Max) { return $val }
        Write-Host ("  Valeur invalide : entier attendu entre {0} et {1}." -f $Min, $Max) -ForegroundColor Yellow
    }
}

function ConvertTo-IndexList {
    <#
        Convertit une saisie utilisateur en liste d'index valides : "0,3,5", "2-6",
        "tous"/"*". Les doublons et index hors bornes sont ignores (et signales).
    #>
    param([string]$Selection, [Parameter(Mandatory)][int]$Count)
    if ([string]::IsNullOrWhiteSpace($Selection) -or $Count -le 0) { return @() }
    $sel = $Selection.Trim()
    if ($sel -in @('tous', 'tout', '*', 'all')) { return @(0..($Count - 1)) }

    $result = [System.Collections.Generic.List[int]]::new()
    foreach ($part in ($sel -split '[,; ]+' | Where-Object { $_ })) {
        if ($part -match '^(\d+)-(\d+)$') {
            $a = [int]$Matches[1]; $b = [int]$Matches[2]
            if ($a -gt $b) { $a, $b = $b, $a }
            for ($i = $a; $i -le $b; $i++) { if ($i -lt $Count -and -not $result.Contains($i)) { $result.Add($i) } }
        } elseif ($part -match '^\d+$') {
            $i = [int]$part
            if ($i -lt $Count) { if (-not $result.Contains($i)) { $result.Add($i) } }
            else { Write-Host ("  Index {0} hors liste, ignore." -f $i) -ForegroundColor Yellow }
        } else {
            Write-Host ("  Saisie '{0}' non reconnue, ignoree." -f $part) -ForegroundColor Yellow
        }
    }
    return @($result)
}

function Select-FromList {
    <#
        Liste numerotee generique + selection multiple (numeros, plages "2-5", 'tous').
        -Display : scriptblock de mise en forme d'un element ($_), defaut SamAccountName/Name.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Items,
        [Parameter(Mandatory)][string]$Prompt,
        [scriptblock]$Display,
        [switch]$Single
    )
    if ($Items.Count -eq 0) { return @() }
    for ($i = 0; $i -lt $Items.Count; $i++) {
        $it = $Items[$i]
        $txt = if ($Display) { & $Display $it }
               elseif ($it.PSObject.Properties['SamAccountName'] -and $it.SamAccountName) { $it.SamAccountName }
               elseif ($it.PSObject.Properties['Name'] -and $it.Name) { $it.Name }
               else { [string]$it }
        Write-Host ("  [{0,3}] {1}" -f $i, $txt)
    }
    $hint = if ($Single) { "numero, vide = annuler" } else { "ex : 0,2,5 ou 1-4 ou 'tous' ; vide = annuler" }
    $sel = Read-Host ("{0} ({1})" -f $Prompt, $hint)
    $idx = @(ConvertTo-IndexList -Selection $sel -Count $Items.Count)
    if ($Single -and $idx.Count -gt 1) { $idx = @($idx[0]) }
    return @($idx | ForEach-Object { $Items[$_] })
}

function Confirm-Action {
    <#
        Confirmation simple (SAFE) : O/N.
        Confirmation renforcee (A VALIDER) : l'utilisateur doit taper exactement CONFIRMER
        en mode reel. En mode SIMULATION (rien ne sera applique), un simple O suffit pour
        derouler le scenario.
    #>
    param(
        [Parameter(Mandatory)][string]$ActionLabel,
        [switch]$Strong
    )

    if ($Strong) {
        Write-Host ""
        if ($Script:SimulationMode) {
            Write-Host "[SIMULATION] Action a impact potentiel - rien ne sera applique :" -ForegroundColor Yellow
            Write-Host ("  -> {0}" -f $ActionLabel) -ForegroundColor Yellow
            $resp = Read-Host "  Derouler la simulation ? (O/N ou CONFIRMER)"
            return ($resp -ceq "CONFIRMER" -or $resp -match '^[oOyY]')
        }
        Write-Host "!!! ACTION A IMPACT POTENTIEL - MODE REEL !!!" -ForegroundColor White -BackgroundColor DarkRed
        Write-Host ("  -> {0}" -f $ActionLabel) -ForegroundColor Red
        Write-Host "  Cette action peut affecter des postes, comptes de service ou applications legacy." -ForegroundColor Yellow
        Write-Host "  Assurez-vous d'etre dans une fenetre de maintenance et d'avoir une sauvegarde/rollback possible." -ForegroundColor Yellow
        $resp = Read-Host "  Tapez EXACTEMENT 'CONFIRMER' pour executer cette action, ou Entree pour annuler"
        $ok = ($resp -ceq "CONFIRMER")
        if (-not $ok) { Write-Log ("Action annulee par l'operateur : {0}" -f $ActionLabel) -Level INFO }
        return $ok
    }

    $prefix = if ($Script:SimulationMode) { "[SIMULATION] " } else { "" }
    return (Read-YesNo -Prompt ("{0}Confirmez-vous : {1} ?" -f $prefix, $ActionLabel))
}

function Invoke-Guarded {
    <#
        Encapsule une action d'ecriture : en mode simulation, journalise seulement ce qui
        SERAIT fait ; sinon execute le scriptblock avec $ErrorActionPreference = Stop, de
        sorte qu'une erreur NON bloquante d'une cmdlet (ex : Set-ADUser sans -ErrorAction)
        soit bien comptee comme un echec au lieu d'etre suivie d'un faux "Termine".
        Le resultat est memorise dans $Script:LastGuardedResult ($true/$false/$null).
    #>
    param(
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][scriptblock]$Action
    )

    $Script:SessionStats.Actions++
    if ($Script:SimulationMode) {
        Write-Log ("[SIMULATION] {0}" -f $Description) -Level SIMU
        $Script:SessionStats.Simulees++
        $Script:LastGuardedResult = $null
        return
    }

    $ErrorActionPreference = 'Stop'
    try {
        Write-Log ("Execution : {0}" -f $Description) -Level ACTION
        & $Action | Out-Host
        Write-Log ("Termine   : {0}" -f $Description) -Level OK
        $Script:SessionStats.Succes++
        $Script:LastGuardedResult = $true
    } catch {
        Write-Log ("Echec de l'action [{0}] : {1}" -f $Description, $_.Exception.Message) -Level ERROR
        $Script:SessionStats.Echecs++
        $Script:CurrentActionFailures++
        $Script:LastGuardedResult = $false
    }
}

function Pause-Menu {
    Write-Host ""
    [void](Read-Host "Appuyez sur Entree pour revenir au menu")
}

function New-RandomComplexPassword {
    <#
        Mot de passe aleatoire cryptographiquement sur, SANS biais modulo (tirage avec
        rejet), garantissant au moins un caractere de chaque classe (complexite AD).
    #>
    param([ValidateRange(16, 256)][int]$Length = 32)
    $sets = @('ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!@#$%^&*()-_=+')
    $all = -join $sets
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $buf = New-Object byte[] 1
    $nextIndex = {
        param([int]$max)
        $limit = 256 - (256 % $max)
        do { $rng.GetBytes($buf) } while ($buf[0] -ge $limit)
        return ($buf[0] % $max)
    }
    $chars = [System.Collections.Generic.List[char]]::new()
    foreach ($s in $sets) { $chars.Add($s[(& $nextIndex $s.Length)]) }
    while ($chars.Count -lt $Length) { $chars.Add($all[(& $nextIndex $all.Length)]) }
    # Melange de Fisher-Yates.
    for ($i = $chars.Count - 1; $i -gt 0; $i--) {
        $j = & $nextIndex ($i + 1)
        $tmp = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $tmp
    }
    $rng.Dispose()
    return (-join $chars)
}

function Export-Report {
    <#
        Export CSV homogene de tous les rapports : dossier de session (Logs\Rapports_<date>),
        separateur ';' (ouverture directe dans Excel FR), UTF-8 avec BOM (accents OK).
        Retourne le chemin du fichier (ou $null si rien a exporter).
    #>
    param(
        [AllowNull()][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory)][string]$Name,
        [string]$Comment
    )
    $rowsArr = @($Rows | Where-Object { $null -ne $_ })
    if ($rowsArr.Count -eq 0) {
        Write-Log ("Rapport '{0}' : aucune ligne a exporter." -f $Name) -Level INFO
        return $null
    }
    if (-not (Test-Path -LiteralPath $Script:ReportDir)) { New-Item -Path $Script:ReportDir -ItemType Directory -Force | Out-Null }
    $path = Join-Path $Script:ReportDir ("{0}_{1}.csv" -f $Name, (Get-Date -Format "yyyyMMdd_HHmmss"))
    try {
        $rowsArr | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8 -Delimiter ';' -ErrorAction Stop
        $Script:SessionReports.Add($path)
        $msg = "Rapport exporte ({0} ligne(s)) : {1}" -f $rowsArr.Count, $path
        if ($Comment) { $msg = "{0}. {1}" -f $msg, $Comment }
        Write-Log $msg -Level OK
        return $path
    } catch {
        Write-Log ("Echec de l'export du rapport '{0}' : {1}" -f $Name, $_.Exception.Message) -Level ERROR
        return $null
    }
}

function Write-ListPreview {
    # Affiche au plus $Max elements d'une liste (le detail complet est dans le CSV).
    param([AllowEmptyCollection()][object[]]$Items, [scriptblock]$Format, [int]$Max = 25, [string]$Color = "Gray")
    $arr = @($Items)
    $arr | Select-Object -First $Max | ForEach-Object { Write-Host ("  - {0}" -f (& $Format $_)) -ForegroundColor $Color }
    if ($arr.Count -gt $Max) { Write-Host ("  ... {0} element(s) supplementaire(s) : voir le CSV exporte." -f ($arr.Count - $Max)) -ForegroundColor DarkGray }
}

function ConvertFrom-FileTimeSafe {
    param($Value)
    if ($null -eq $Value) { return $null }
    try {
        $v = [int64]$Value
        if ($v -le 0 -or $v -eq [int64]::MaxValue) { return $null }
        return [DateTime]::FromFileTime($v)
    } catch { return $null }
}

function Get-ComputerAccountKind {
    <#
        Nature reelle d'un objet renvoye par Get-ADComputer. Les comptes de service geres (MSA,
        gMSA, dMSA) DERIVENT de la classe 'computer' : Get-ADComputer les renvoie, ce qui
        faussait la couverture LAPS, les comptes inactifs et l'inventaire des OS (faux positifs).
        Retourne : MSA, DC, EntraSSO (AZUREADSSOACC), Cluster (CNO/VCO), NonWindows ou Computer.
        Les proprietes PrimaryGroupID, ServicePrincipalName et OperatingSystem doivent avoir ete
        demandees pour les distinctions correspondantes.
    #>
    param([Parameter(Mandatory)]$Computer)
    $cls = [string]$Computer.ObjectClass
    if ($cls -in 'msDS-GroupManagedServiceAccount', 'msDS-ManagedServiceAccount', 'msDS-DelegatedManagedServiceAccount') { return 'MSA' }
    if ($Computer.PrimaryGroupID -in 516, 521) { return 'DC' }
    if ([string]$Computer.SamAccountName -ieq 'AZUREADSSOACC$') { return 'EntraSSO' }
    if (@(@($Computer.ServicePrincipalName) -match '^MSClusterVirtualServer/').Count -gt 0) { return 'Cluster' }
    $os = [string]$Computer.OperatingSystem
    if ($os -and $os -notmatch 'Windows') { return 'NonWindows' }
    return 'Computer'
}

function Get-GppPasswordEntries {
    <#
        Extrait d'un fichier de preferences GPO (Groups.xml, Services.xml...) chaque element
        portant un 'cpassword' NON vide, avec le compte declare DANS LE MEME element (auparavant
        le premier compte du fichier etait attribue a tous les mots de passe trouves).
    #>
    param([AllowEmptyString()][string]$Content)
    if ([string]::IsNullOrEmpty($Content)) { return @() }
    return @(foreach ($m in [regex]::Matches($Content, '<(\w+)\s[^>]*\bcpassword="([^"]+)"[^>]*>')) {
        $tag = $m.Value
        $user = if ($tag -match '\b(?:userName|accountName|runAs|username)="([^"]*)"') { $Matches[1] } else { $null }
        [PSCustomObject]@{ Element = $m.Groups[1].Value; Compte = $user }
    })
}

# ============================================================
#  CONTEXTE ACTIVE DIRECTORY (cache, groupes, SID bien connus)
# ============================================================

function Get-CachedADDomain {
    if (-not $Script:ADDomainCache) { $Script:ADDomainCache = Get-ADDomain -ErrorAction Stop }
    return $Script:ADDomainCache
}

function Get-CachedADForest {
    if (-not $Script:ADForestCache) { $Script:ADForestCache = Get-ADForest -ErrorAction Stop }
    return $Script:ADForestCache
}

function Get-RootDomainSid {
    # SID du domaine racine de la foret (Enterprise/Schema Admins y sont definis).
    if (-not $Script:RootDomainSidCache) {
        $dom = Get-CachedADDomain
        $forest = Get-CachedADForest
        if ($forest.RootDomain -ieq $dom.DNSRoot) {
            $Script:RootDomainSidCache = $dom.DomainSID.Value
        } else {
            $Script:RootDomainSidCache = (Get-ADDomain -Identity $forest.RootDomain -Server $forest.RootDomain -ErrorAction Stop).DomainSID.Value
        }
    }
    return $Script:RootDomainSidCache
}

# Correspondance nom (anglais) -> SID bien connu. Les noms de groupes integres sont
# LOCALISES sur un AD installe en francais ("Admins du domaine", "Administrateurs"...) :
# une recherche par nom echoue alors silencieusement (faux negatifs). La resolution par
# SID/RID est independante de la langue.
$Script:WellKnownGroupMap = @{
    'Domain Admins'                      = @{ Scope = 'Domain'; Rid = 512 }
    'Domain Users'                       = @{ Scope = 'Domain'; Rid = 513 }
    'Domain Controllers'                 = @{ Scope = 'Domain'; Rid = 516 }
    'Cert Publishers'                    = @{ Scope = 'Domain'; Rid = 517 }
    'Schema Admins'                      = @{ Scope = 'Root';   Rid = 518 }
    'Enterprise Admins'                  = @{ Scope = 'Root';   Rid = 519 }
    'Group Policy Creator Owners'        = @{ Scope = 'Domain'; Rid = 520 }
    'Read-only Domain Controllers'       = @{ Scope = 'Domain'; Rid = 521 }
    'Protected Users'                    = @{ Scope = 'Domain'; Rid = 525 }
    'Key Admins'                         = @{ Scope = 'Domain'; Rid = 526 }
    'Enterprise Key Admins'              = @{ Scope = 'Root';   Rid = 527 }
    'Administrators'                     = @{ Sid = 'S-1-5-32-544' }
    'Account Operators'                  = @{ Sid = 'S-1-5-32-548' }
    'Server Operators'                   = @{ Sid = 'S-1-5-32-549' }
    'Print Operators'                    = @{ Sid = 'S-1-5-32-550' }
    'Backup Operators'                   = @{ Sid = 'S-1-5-32-551' }
    'Pre-Windows 2000 Compatible Access' = @{ Sid = 'S-1-5-32-554' }
}

function Resolve-ADGroupRef {
    <#
        Retourne l'identite a utiliser pour interroger un groupe (SID si groupe bien
        connu, sinon le nom fourni) et le serveur a cibler (domaine racine pour les
        groupes de foret, ex : Enterprise Admins depuis un domaine enfant).
    #>
    param([Parameter(Mandatory)][string]$Name)
    $entry = $Script:WellKnownGroupMap[$Name]
    if (-not $entry) { return [PSCustomObject]@{ Name = $Name; Identity = $Name; Server = $null } }
    if ($entry.Sid) { return [PSCustomObject]@{ Name = $Name; Identity = $entry.Sid; Server = $null } }

    $dom = Get-CachedADDomain
    if ($entry.Scope -eq 'Root') {
        $forest = Get-CachedADForest
        $server = if ($forest.RootDomain -ieq $dom.DNSRoot) { $null } else { $forest.RootDomain }
        return [PSCustomObject]@{ Name = $Name; Identity = ("{0}-{1}" -f (Get-RootDomainSid), $entry.Rid); Server = $server }
    }
    return [PSCustomObject]@{ Name = $Name; Identity = ("{0}-{1}" -f $dom.DomainSID.Value, $entry.Rid); Server = $null }
}

function Test-IsADNotFoundError {
    # Vrai si l'erreur signifie "objet introuvable" (et non droits/connectivite).
    param($ErrorRecord)
    $e = $ErrorRecord.Exception
    while ($e) {
        if ($e.GetType().Name -eq 'ADIdentityNotFoundException') { return $true }
        $e = $e.InnerException
    }
    return $false
}

function Get-GroupMembersSafe {
    <#
        Get-ADGroupMember robuste : resolution par SID bien connu, ciblage du domaine
        racine si necessaire, et AVERTISSEMENT explicite en cas d'echec (un groupe
        illisible ne doit jamais etre interprete comme un groupe vide = faux "OK").
    #>
    param(
        [Parameter(Mandatory)][string]$Group,
        [switch]$Recursive
    )
    try {
        $ref = Resolve-ADGroupRef -Name $Group
        $p = @{ Identity = $ref.Identity; ErrorAction = 'Stop' }
        if ($ref.Server) { $p['Server'] = $ref.Server }
        if ($Recursive) { $p['Recursive'] = $true }
        return @(Get-ADGroupMember @p)
    } catch {
        # Groupe INEXISTANT (ex : Key Admins avant le niveau 2016, DnsAdmins sans DNS integre a
        # l'AD) : il n'a reellement aucun membre - ce n'est pas une erreur de lecture.
        if (Test-IsADNotFoundError $_) {
            Write-Verbose ("Groupe '{0}' absent de l'annuaire : aucun membre." -f $Group)
            return @()
        }
        # En mode strict (diagnostic), un groupe illisible doit faire echouer le controle (statut
        # ERREUR) plutot que d'etre compte comme vide (faux OK).
        if ($Script:StrictGroupQueries) { throw }
        Write-Log ("Lecture du groupe '{0}' impossible : {1} - resultat potentiellement INCOMPLET." -f $Group, $_.Exception.Message) -Level WARN
        return @()
    }
}

function Get-ExpandedGroupMemberSids {
    param([string[]]$GroupNames)
    $sids = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($g in $GroupNames) {
        if ([string]::IsNullOrWhiteSpace($g)) { continue }
        foreach ($m in (Get-GroupMembersSafe -Group $g -Recursive)) { [void]$sids.Add($m.SID.Value) }
    }
    return , $sids
}

function Get-PrivilegedUsers {
    <#
        Comptes UTILISATEURS membres (directs ou indirects) des groupes indiques, sans
        doublon, relus avec les proprietes demandees. Les comptes d'un autre domaine de
        la foret (ex : membres d'Enterprise Admins du domaine racine) sont signales.
    #>
    param(
        [string[]]$Groups = $Script:AdminGroups,
        [string[]]$Properties = @()
    )
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $result = [System.Collections.Generic.List[object]]::new()
    foreach ($g in $Groups) {
        foreach ($m in (Get-GroupMembersSafe -Group $g -Recursive)) {
            if ($m.objectClass -ne 'user') { continue }
            if (-not $seen.Add($m.SID.Value)) { continue }
            try {
                $result.Add((Get-ADUser -Identity $m.SID -Properties $Properties -ErrorAction Stop))
            } catch {
                Write-Log ("Compte {0} ({1}) non lisible dans ce domaine (autre domaine de la foret ?) - ignore." -f $m.SamAccountName, $m.SID.Value) -Level WARN
            }
        }
    }
    return @($result)
}

function Get-AlwaysProtectedPrincipalSids {
    <#
        Comptes systeme JAMAIS desactivables/deplacables, quels que soient les
        choix de l'utilisateur : Administrateur, Invite et krbtgt integres (RID
        500/501/502), et le compte qui execute le script lui-meme.
    #>
    $sids = [System.Collections.Generic.HashSet[string]]::new()
    try {
        $domainSidStr = (Get-CachedADDomain).DomainSID.Value
        foreach ($rid in 500, 501, 502) { [void]$sids.Add("$domainSidStr-$rid") }
    } catch { }
    $me = Get-CurrentUserSid
    if ($me) { [void]$sids.Add($me) }
    return , $sids
}

function Get-DomainControllersList {
    <#
        Liste des DC du domaine, mise en cache pour la session (interrogee par la plupart des
        actions). -Refresh relit l'annuaire ; -Strict leve une exception en cas d'echec au lieu
        de retourner une liste vide (le diagnostic ne doit jamais conclure "0 DC" sur une erreur).
    #>
    param([switch]$Refresh, [switch]$Strict)
    if ($Script:DCListCache -and -not $Refresh) { return @($Script:DCListCache) }
    try {
        # @() force un tableau meme s'il n'y a qu'1 seul DC.
        $Script:DCListCache = @(Get-ADDomainController -Filter * -ErrorAction Stop | Sort-Object HostName)
        return @($Script:DCListCache)
    } catch {
        if ($Strict) { throw }
        Write-Log "Impossible de lister les controleurs de domaine : $($_.Exception.Message)" -Level ERROR
        return @()
    }
}

function Get-ProtectedDCComputerDNs {
    # Les controleurs de domaine (y compris RODC) ne doivent jamais etre desactives/deplaces.
    $dns = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($dc in (Get-DomainControllersList)) {
        if ($dc.ComputerObjectDN) { [void]$dns.Add($dc.ComputerObjectDN) }
    }
    return , $dns
}

function Test-IsLocalComputer {
    <#
        Compare le nom court d'un hote (avant le premier '.') au nom NetBIOS de la
        machine locale, pour detecter quand une action ciblant un DC vise en fait
        la machine sur laquelle le script s'execute.
    #>
    param([Parameter(Mandatory)][string]$ComputerName)
    $short = $ComputerName.Split('.')[0]
    return ($short -ieq $env:COMPUTERNAME -or $short -ieq 'localhost' -or $ComputerName -eq '.')
}

function Test-WinRmConnectivity {
    <#
        Verifie que le PowerShell Remoting (WinRM) repond sur chaque machine AVANT de
        lancer une action a distance dessus. La machine LOCALE est toujours consideree
        joignable : Invoke-OnDC l'execute en local, sans WinRM.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$ComputerNames)

    $reachable = [System.Collections.Generic.List[string]]::new()
    $unreachable = [System.Collections.Generic.List[string]]::new()
    $i = 0
    foreach ($name in $ComputerNames) {
        $i++
        if ($ComputerNames.Count -gt 3) {
            Write-Progress -Activity "Test de connectivite WinRM" -Status $name -PercentComplete ([int](100 * $i / $ComputerNames.Count))
        }
        if (Test-IsLocalComputer -ComputerName $name) { $reachable.Add($name); continue }
        try {
            Test-WSMan -ComputerName $name -ErrorAction Stop | Out-Null
            $reachable.Add($name)
        } catch {
            $unreachable.Add($name)
        }
    }
    if ($ComputerNames.Count -gt 3) { Write-Progress -Activity "Test de connectivite WinRM" -Completed }

    if ($unreachable.Count -gt 0) {
        Write-Log ("PowerShell Remoting (WinRM) injoignable sur : {0}. Ces machines seront ignorees pour cette action." -f ($unreachable -join ', ')) -Level WARN
        Write-Log "A verifier : service WinRM demarre ('Enable-PSRemoting -Force'), regle de pare-feu 'Gestion a distance de Windows (HTTP-In)', resolution DNS, machine allumee. Pour les DC : menu 8 > 4." -Level WARN
    }
    return [PSCustomObject]@{ Reachable = @($reachable); Unreachable = @($unreachable) }
}

function Get-ReachableDCs {
    # Liste des DC joignables en WinRM (la machine locale l'est toujours).
    $dcs = @(Get-DomainControllersList)
    if ($dcs.Count -eq 0) { return @() }
    $wr = Test-WinRmConnectivity -ComputerNames @($dcs | ForEach-Object { $_.HostName })
    $ok = @($dcs | Where-Object { $wr.Reachable -contains $_.HostName })
    if ($ok.Count -eq 0) { Write-Log "Aucun DC joignable via PowerShell Remoting (WinRM), action annulee." -Level ERROR }
    return $ok
}

function Invoke-OnDC {
    <#
        Remplace Invoke-Command -ComputerName pour toutes les actions distantes (DC ou
        machine membre) : si la cible est la machine locale, execute le scriptblock EN
        LOCAL (sans WinRM), le self-remoting echouant frequemment avec "Acces refuse".
        Memes parametres qu'Invoke-Command (ScriptBlock, ArgumentList, ErrorAction).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [object[]]$ArgumentList
    )
    $params = @{ ScriptBlock = $ScriptBlock }
    if ($PSBoundParameters.ContainsKey('ArgumentList')) { $params['ArgumentList'] = $ArgumentList }
    if ($PSBoundParameters.ContainsKey('ErrorAction'))  { $params['ErrorAction']  = $PSBoundParameters['ErrorAction'] }

    if (Test-IsLocalComputer -ComputerName $ComputerName) {
        Invoke-Command @params
    } else {
        Invoke-Command @params -ComputerName $ComputerName
    }
}

function Select-OUsInteractive {
    <#
        Selecteur d'UO interactif generique et numerote, avec FILTRE par mot-cle (utile
        sur un annuaire comptant des centaines d'UO). Propose aussi les conteneurs par
        defaut CN=Computers / CN=Users (ce ne sont PAS des UO : sans cette option, les
        machines/comptes qui y resident ne pourraient jamais etre cibles) et la racine
        du domaine. Un DN complet peut aussi etre saisi directement.
    #>
    param(
        [Parameter(Mandatory)][string]$Label,
        [string]$Verb = "EXCLURE",
        [switch]$IncludeDomainRoot
    )

    $domainDN = (Get-CachedADDomain).DistinguishedName
    $ous = @(Get-ADOrganizationalUnit -Filter * -ErrorAction SilentlyContinue | Sort-Object DistinguishedName | ForEach-Object { $_.DistinguishedName })
    $extras = @()
    foreach ($c in @((Get-CachedADDomain).ComputersContainer, (Get-CachedADDomain).UsersContainer)) {
        if ($c -and $ous -notcontains $c) { $extras += $c }
    }
    if ($IncludeDomainRoot) { $extras = @($domainDN) + $extras }
    $all = @($extras + $ous)
    if ($all.Count -eq 0) { return @() }

    Write-Host ""
    Write-Host ("Selection des UO a {0} pour {1}" -f $Verb, $Label) -ForegroundColor Cyan
    $list = $all
    if ($all.Count -gt 30) {
        $filter = Read-Host ("{0} UO/conteneurs disponibles. Filtre par mot-cle (vide = tout afficher)" -f $all.Count)
        if (-not [string]::IsNullOrWhiteSpace($filter)) {
            $list = @($all | Where-Object { $_ -like "*$filter*" })
            if ($list.Count -eq 0) { Write-Host "  Aucun resultat pour ce filtre : liste complete affichee." -ForegroundColor Yellow; $list = $all }
        }
    }
    for ($i = 0; $i -lt $list.Count; $i++) { Write-Host ("  [{0,3}] {1}" -f $i, $list[$i]) }
    $sel = Read-Host ("Numeros a {0} (ex : 0,3 ou 2-5 ; 'tous' ; un DN complet est accepte ; vide = aucune)" -f $Verb)
    if ([string]::IsNullOrWhiteSpace($sel)) { return @() }

    if ($sel -match '(?i)^\s*(OU|CN|DC)=') {
        try {
            $obj = Get-ADObject -Identity $sel.Trim() -ErrorAction Stop
            return @($obj.DistinguishedName)
        } catch {
            Write-Log ("DN introuvable : {0}" -f $sel) -Level ERROR
            return @()
        }
    }
    $chosen = @(ConvertTo-IndexList -Selection $sel -Count $list.Count | ForEach-Object { $list[$_] })

    # Retire les UO deja couvertes par une UO parente selectionnee (evite les doublons).
    $chosen = @($chosen | Where-Object {
        $dn = $_
        -not ($chosen | Where-Object { $_ -ne $dn -and $dn.EndsWith(",$_", [StringComparison]::OrdinalIgnoreCase) })
    })
    return $chosen
}

function Select-ExclusionOUs {
    param([Parameter(Mandatory)][string]$Label)
    return @(Select-OUsInteractive -Label $Label -Verb "EXCLURE")
}

function Test-DNUnderAny {
    # Vrai si le DN est situe SOUS l'une des UO de la liste (comparaison sans joker).
    param([string]$DN, [string[]]$Containers)
    foreach ($c in $Containers) {
        if ([string]::IsNullOrWhiteSpace($c)) { continue }
        if ($DN.EndsWith(",$c", [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Get-TargetComputers {
    <#
        Choix des machines cibles d'une action distante : par UO (recursif) ou par saisie
        directe de noms (pratique pour un pilote sur 1 ou 2 machines). Retourne la liste
        des noms DNS JOIGNABLES en WinRM. -IncludeDCs : sinon les DC sont retires (ils
        disposent de leurs propres actions dediees).
    #>
    param(
        [Parameter(Mandatory)][string]$Label,
        [switch]$IncludeDCs
    )
    Write-Host ""
    Write-Host ("Ciblage des machines pour {0} :" -f $Label) -ForegroundColor Cyan
    Write-Host "  [1] Par UO (toutes les machines actives sous les UO choisies)"
    Write-Host "  [2] Par noms de machines saisis (pilote)"
    $mode = Read-Host "Mode de ciblage [1/2] (defaut 1)"

    $names = @()
    if ($mode -eq '2') {
        $raw = Read-Host "Noms des machines, separes par une virgule"
        foreach ($n in ($raw -split '[,; ]+' | Where-Object { $_ })) {
            try {
                $c = Get-ADComputer -Identity $n.Trim() -Properties DNSHostName -ErrorAction Stop
                $names += $(if ($c.DNSHostName) { $c.DNSHostName } else { $c.Name })
            } catch {
                Write-Log ("Machine '{0}' introuvable dans l'annuaire - ignoree." -f $n) -Level WARN
            }
        }
    } else {
        $targetOU = @(Select-OUsInteractive -Label $Label -Verb "CIBLER")
        if ($targetOU.Count -eq 0) { Write-Log "Aucune UO ciblee, action annulee." -Level WARN; return @() }
        $seen = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($ou in $targetOU) {
            foreach ($c in @(Get-ADComputer -SearchBase $ou -Filter 'Enabled -eq $true' -Properties DNSHostName, PrimaryGroupID -ErrorAction SilentlyContinue)) {
                $kind = Get-ComputerAccountKind -Computer $c
                # Comptes de service geres / compte Seamless SSO : pas de machine derriere.
                if ($kind -in 'MSA', 'EntraSSO') { continue }
                if (-not $IncludeDCs -and $kind -eq 'DC') { continue }
                if ($seen.Add($c.DistinguishedName)) { $names += $(if ($c.DNSHostName) { $c.DNSHostName } else { $c.Name }) }
            }
        }
    }

    if ($names.Count -eq 0) { Write-Log "Aucun ordinateur actif trouve pour ce ciblage." -Level WARN; return @() }
    Write-Host ("{0} machine(s) ciblee(s), test de connectivite WinRM..." -f $names.Count) -ForegroundColor DarkGray
    $wr = Test-WinRmConnectivity -ComputerNames $names
    if ($wr.Reachable.Count -eq 0) { Write-Log "Aucune machine joignable via PowerShell Remoting (WinRM) parmi celles ciblees." -Level ERROR }
    return @($wr.Reachable)
}

# ============================================================
#  GPO : helpers communs
# ============================================================

function Test-GroupPolicyModule {
    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Log "Le module GroupPolicy (RSAT-GPMC) n'est pas installe sur ce poste." -Level ERROR
        return $false
    }
    Import-Module GroupPolicy -ErrorAction SilentlyContinue
    return $true
}

function Get-OrCreateGpo {
    param([Parameter(Mandatory)][string]$Name, [string]$Comment = "Creee par le script de remediation AD (SEC)")
    $gpo = Get-GPO -Name $Name -ErrorAction SilentlyContinue
    if (-not $gpo) {
        $gpo = New-GPO -Name $Name -Comment $Comment -ErrorAction Stop
        Write-Log ("GPO '{0}' creee." -f $Name) -Level INFO
    }
    return $gpo
}

function Add-GpoLinkSafe {
    <#
        Lie une GPO aux cibles indiquees. Contrairement a un "try { New-GPLink } catch { }",
        distingue "deja liee" (normal) d'un vrai echec (droits, cible inexistante), qui
        est remonte comme erreur au lieu d'etre ignore silencieusement.
    #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string[]]$Targets)
    foreach ($t in $Targets) {
        $inh = Get-GPInheritance -Target $t -ErrorAction Stop
        if (@($inh.GpoLinks | Where-Object { $_.DisplayName -eq $Name }).Count -gt 0) {
            Write-Log ("GPO '{0}' deja liee sur {1}." -f $Name, $t) -Level INFO
            continue
        }
        New-GPLink -Name $Name -Target $t -LinkEnabled Yes -ErrorAction Stop | Out-Null
        Write-Log ("GPO '{0}' liee sur {1}." -f $Name, $t) -Level INFO
    }
}

function Get-DomainControllersOU {
    return ("OU=Domain Controllers,{0}" -f (Get-CachedADDomain).DistinguishedName)
}

function Test-TargetsIncludeDCs {
    # Avertit si une GPO "postes/serveurs" va etre liee a l'UO des DC ou a la racine.
    param([string[]]$Targets)
    $domainDN = (Get-CachedADDomain).DistinguishedName
    $dcOU = Get-DomainControllersOU
    return [bool]($Targets | Where-Object { $_ -ieq $dcOU -or $_ -ieq $domainDN })
}

function Get-GpoSysvolPath {
    param([Parameter(Mandatory)][Guid]$GpoId)
    $dom = Get-CachedADDomain
    # Ecriture sur le PDC (comme GPMC) pour eviter les conflits de replication DFSR.
    return ("\\{0}\SYSVOL\{1}\Policies\{{{2}}}" -f $dom.PDCEmulator, $dom.DNSRoot, $GpoId.ToString().ToUpper())
}

function Read-SecurityTemplate {
    # Lit un GptTmpl.inf en table ordonnee : section -> (cle -> valeur).
    param([Parameter(Mandatory)][string]$Path)
    $sections = [ordered]@{}
    if (-not (Test-Path -LiteralPath $Path)) { return $sections }
    $current = $null
    foreach ($line in (Get-Content -LiteralPath $Path -ErrorAction Stop)) {
        if ($line -match '^\s*\[(.+)\]\s*$') {
            $current = $Matches[1]
            if (-not $sections.Contains($current)) { $sections[$current] = [ordered]@{} }
        } elseif ($current -and $line -match '^\s*([^=;]+?)\s*=\s*(.*)$') {
            $sections[$current][$Matches[1]] = $Matches[2].Trim()
        }
    }
    return $sections
}

function Set-GpoSecurityTemplateValues {
    <#
        Ecrit des parametres de securite (politique de mot de passe, attribution des
        droits utilisateur...) dans le modele de securite (GptTmpl.inf) d'une GPO,
        ce que le module GroupPolicy ne sait pas faire :
          1. lit/fusionne le GptTmpl.inf existant (UTF-16, format secedit) ;
          2. declare l'extension cote client "Security" dans gPCMachineExtensionNames ;
          3. incremente la version machine (GPT.INI + attribut versionNumber) pour que
             les clients appliquent la nouvelle version au prochain rafraichissement.
        A appeler a l'interieur d'Invoke-Guarded (leve une exception en cas d'echec).
    #>
    param(
        [Parameter(Mandatory)][Guid]$GpoId,
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Values
    )
    $dom = Get-CachedADDomain
    $gpoPath = Get-GpoSysvolPath -GpoId $GpoId
    $secEditDir = Join-Path $gpoPath "MACHINE\Microsoft\Windows NT\SecEdit"
    $infPath = Join-Path $secEditDir "GptTmpl.inf"
    if (-not (Test-Path -LiteralPath $secEditDir)) { New-Item -Path $secEditDir -ItemType Directory -Force | Out-Null }

    # Edition LIGNE A LIGNE : les sections/cles non concernees sont conservees a l'identique
    # (format secedit : 'Unicode=yes', '[Registry Values]' sans espaces, etc.).
    $lines = [System.Collections.Generic.List[string]]::new()
    if (Test-Path -LiteralPath $infPath) { foreach ($l in (Get-Content -LiteralPath $infPath -ErrorAction Stop)) { $lines.Add($l) } }
    if ($lines.Count -eq 0) {
        foreach ($l in @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1')) { $lines.Add($l) }
    }
    $secStart = -1
    for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i].Trim() -ieq "[$Section]") { $secStart = $i; break } }
    if ($secStart -lt 0) {
        # Nouvelle section inseree avant [Version] (ou en fin de fichier).
        $ver = -1
        for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i].Trim() -ieq '[Version]') { $ver = $i; break } }
        if ($ver -lt 0) { $ver = $lines.Count }
        $lines.Insert($ver, "[$Section]")
        $secStart = $ver
    }
    $secEnd = $lines.Count
    for ($i = $secStart + 1; $i -lt $lines.Count; $i++) { if ($lines[$i] -match '^\s*\[') { $secEnd = $i; break } }
    foreach ($k in $Values.Keys) {
        $newLine = "{0} = {1}" -f $k, $Values[$k]
        $found = $false
        for ($i = $secStart + 1; $i -lt $secEnd; $i++) {
            if ($lines[$i] -match ('^\s*' + [regex]::Escape($k) + '\s*=')) { $lines[$i] = $newLine; $found = $true; break }
        }
        if (-not $found) { $lines.Insert($secEnd, $newLine); $secEnd++ }
    }
    $text = $lines -join "`r`n"
    Set-Content -LiteralPath $infPath -Value $text -Encoding Unicode -ErrorAction Stop

    # Extension cote client "Security" ({827D319E...} + outil {803E14A0...}).
    $gpcDN = "CN={{{0}}},CN=Policies,CN=System,{1}" -f $GpoId.ToString().ToUpper(), $dom.DistinguishedName
    $gpc = Get-ADObject -Identity $gpcDN -Properties gPCMachineExtensionNames, versionNumber -Server $dom.PDCEmulator -ErrorAction Stop
    $secCse = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'
    $ext = [string]$gpc.gPCMachineExtensionNames
    if ($ext -notlike '*{827D319E-6EAC-11D2-A4EA-00C04F79F83A}*') {
        $groups = @([regex]::Matches($ext, '\[[^\]]+\]') | ForEach-Object { $_.Value }) + $secCse
        $ext = -join ($groups | Sort-Object -Unique)
    }

    # Version : 16 bits de poids faible = partie machine.
    $version = [int]$gpc.versionNumber
    $machine = ($version -band 0xFFFF) + 1
    if ($machine -gt 0xFFFF) { $machine = 1 }
    $newVersion = ($version -band 0xFFFF0000) -bor $machine
    Set-ADObject -Identity $gpcDN -Replace @{ gPCMachineExtensionNames = $ext; versionNumber = $newVersion } -Server $dom.PDCEmulator -ErrorAction Stop

    $gptIni = Join-Path $gpoPath "GPT.INI"
    $iniText = if (Test-Path -LiteralPath $gptIni) { Get-Content -LiteralPath $gptIni -Raw } else { "[General]`r`nVersion=0`r`n" }
    if ($iniText -match '(?m)^Version=\d+') { $iniText = $iniText -replace '(?m)^Version=\d+', "Version=$newVersion" }
    else { $iniText = $iniText.TrimEnd() + "`r`nVersion=$newVersion`r`n" }
    Set-Content -LiteralPath $gptIni -Value $iniText -Encoding ASCII -ErrorAction Stop
}

function Backup-SingleGpo {
    # Sauvegarde ponctuelle d'une GPO avant modification (Logs\GPO_Backups\<date>_<nom>).
    param([Parameter(Mandatory)][Guid]$GpoId, [Parameter(Mandatory)][string]$Label)
    $safe = ($Label -replace '[^A-Za-z0-9_-]', '_')
    $path = Join-Path (Join-Path $Script:LogDir "GPO_Backups") ("{0}_{1}" -f (Get-Date -Format "yyyyMMdd_HHmmss"), $safe)
    New-Item -Path $path -ItemType Directory -Force | Out-Null
    Backup-GPO -Guid $GpoId -Path $path -ErrorAction Stop | Out-Null
    Write-Log ("Sauvegarde de la GPO '{0}' : {1}" -f $Label, $path) -Level INFO
}

# ============================================================
#  KERBEROS / CHIFFREMENT / REPLICATION : helpers communs
# ============================================================

function Get-SupportedEncryptionTypesLabel {
    param([Nullable[int]]$Value)
    if (-not $Value) { return "Non defini (types par defaut du domaine - RC4 possible)" }
    $labels = @()
    if ($Value -band 0x1)  { $labels += "DES-CBC-CRC" }
    if ($Value -band 0x2)  { $labels += "DES-CBC-MD5" }
    if ($Value -band 0x4)  { $labels += "RC4-HMAC" }
    if ($Value -band 0x8)  { $labels += "AES128" }
    if ($Value -band 0x10) { $labels += "AES256" }
    if ($labels.Count -eq 0) { return ("Valeur non standard ({0})" -f $Value) }
    return ($labels -join '+')
}

function Test-HasAesEncryptionType {
    param($Value)
    if (-not $Value) { return $false }
    return [bool](([int]$Value) -band 0x18)
}

function Get-AesKeysIntroductionDate {
    <#
        Approximation (methode utilisee par PingCastle) : le groupe "Read-only Domain
        Controllers" (RID 521) est cree lors de la preparation du domaine au niveau 2008.
        Un mot de passe change AVANT cette date n'a vraisemblablement PAS de cle AES
        dans l'annuaire : forcer AES-only sur ce compte casserait son authentification
        tant que son mot de passe n'a pas ete rechange.
    #>
    if ($null -eq $Script:AesIntroDateCache) {
        try {
            $sid = "{0}-521" -f (Get-CachedADDomain).DomainSID.Value
            $Script:AesIntroDateCache = (Get-ADGroup -Identity $sid -Properties whenCreated -ErrorAction Stop).whenCreated
        } catch {
            $Script:AesIntroDateCache = [datetime]::MinValue
        }
    }
    if ($Script:AesIntroDateCache -eq [datetime]::MinValue) { return $null }
    return $Script:AesIntroDateCache
}

function Test-ADReplicationHealth {
    <#
        Etat de la replication AD du domaine, via les cmdlets AD (independantes de la
        langue de l'OS, contrairement au texte de 'repadmin /replsummary').
        Retourne un objet { Healthy ; Details[] }. Etat incertain = NON sain.
    #>
    $details = [System.Collections.Generic.List[string]]::new()
    $healthy = $true
    try {
        $target = (Get-CachedADDomain).DNSRoot
        $partners = @(Get-ADReplicationPartnerMetadata -Target $target -Scope Domain -ErrorAction Stop)
        foreach ($p in $partners) {
            if ($p.LastReplicationResult -ne 0) {
                $healthy = $false
                $details.Add(("{0} <- {1} : erreur {2} (dernier succes {3})" -f $p.Server, $p.Partner, $p.LastReplicationResult, $p.LastReplicationSuccess))
            }
        }
        $failures = @(Get-ADReplicationFailure -Target $target -Scope Domain -ErrorAction Stop | Where-Object { $_.FailureCount -gt 0 })
        foreach ($f in $failures) {
            $healthy = $false
            $details.Add(("{0} <- {1} : {2} echec(s) consecutif(s), derniere erreur {3}" -f $f.Server, $f.Partner, $f.FailureCount, $f.LastError))
        }
        if ($partners.Count -eq 0 -and @(Get-DomainControllersList).Count -gt 1) {
            $healthy = $false
            $details.Add("Aucune metadonnee de replication lue alors que le domaine compte plusieurs DC.")
        }
    } catch {
        $healthy = $false
        $details.Add(("Etat de replication non verifiable : {0}" -f $_.Exception.Message))
    }
    return [PSCustomObject]@{ Healthy = $healthy; Details = @($details) }
}

# ============================================================
#  PREREQUIS
# ============================================================

function Test-Prerequisites {
    $ok = $true

    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Log ("PowerShell {0} detecte : PowerShell 5.1 minimum requis." -f $PSVersionTable.PSVersion) -Level ERROR
        $ok = $false
    }

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Log "Le module ActiveDirectory (RSAT) est introuvable. Installez les RSAT AD DS avant de continuer." -Level ERROR
        return $false
    }
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

    try {
        $dom = Get-CachedADDomain
        Write-Log ("Domaine : {0} (niveau fonctionnel {1}), foret : {2}." -f $dom.DNSRoot, $dom.DomainMode, (Get-CachedADForest).Name) -Level INFO
    } catch {
        Write-Log ("Impossible de contacter le domaine Active Directory : {0}" -f $_.Exception.Message) -Level ERROR
        return $false
    }

    # Appartenance aux groupes d'administration verifiee via le JETON de session (SID),
    # independamment de la langue de l'annuaire et en tenant compte de l'imbrication.
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    $isAdmin = $false
    try {
        foreach ($g in @('Domain Admins', 'Enterprise Admins')) {
            $sid = New-Object Security.Principal.SecurityIdentifier((Resolve-ADGroupRef -Name $g).Identity)
            if ($principal.IsInRole($sid)) { $isAdmin = $true }
        }
    } catch { }
    if (-not $isAdmin) {
        Write-Log ("Le compte courant ({0}) n'est membre ni de 'Admins du domaine' ni de 'Administrateurs de l'entreprise' (jeton de session). Les actions d'ecriture echoueront probablement ; les audits restent utilisables selon vos droits." -f $id.Name) -Level WARN
    }

    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log "La console n'est pas lancee en tant qu'Administrateur local (UAC). Relancez PowerShell en 'Executer en tant qu'administrateur'." -Level WARN
    }

    foreach ($m in @(
        @{ Name = 'GroupPolicy'; Usage = 'actions creant/modifiant des GPO' },
        @{ Name = 'LAPS';        Usage = 'theme Windows LAPS' }
    )) {
        if (-not (Get-Module -ListAvailable -Name $m.Name)) {
            Write-Log ("Module '{0}' absent : {1} indisponibles." -f $m.Name, $m.Usage) -Level INFO
        }
    }
    return $ok
}

# ============================================================
#  THEME 1 - COMPTES A PRIVILEGES
# ============================================================

function Invoke-ReportPrivilegedGroups {
    Write-Section "Rapport : membres des groupes a privileges" Magenta
    Write-Info "Membres directs ET indirects (imbrication resolue), groupes resolus par SID (AD francise OK)."
    $groups = @($Script:DefaultExcludedGroups | Where-Object { $_ -ne 'Protected Users' }) + @('Protected Users')
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($g in $groups) {
        $members = @(Get-GroupMembersSafe -Group $g -Recursive)
        Write-Host ("  {0,-30} : {1} membre(s)" -f $g, $members.Count) -ForegroundColor $(if ($g -eq 'Schema Admins' -and $members.Count -gt 0) { 'Yellow' } else { 'Gray' })
        foreach ($m in $members) {
            $u = $null
            if ($m.objectClass -eq 'user') {
                try { $u = Get-ADUser -Identity $m.SID -Properties Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires, AccountNotDelegated, ServicePrincipalName -ErrorAction Stop } catch { }
            }
            $rows.Add([PSCustomObject]@{
                Groupe              = $g
                Compte              = $m.SamAccountName
                Type                = $m.objectClass
                Actif               = if ($u) { $u.Enabled } else { $null }
                DerniereConnexion   = if ($u) { $u.LastLogonDate } else { $null }
                MdpDernierChangement = if ($u) { $u.PasswordLastSet } else { $null }
                MdpNExpireJamais    = if ($u) { $u.PasswordNeverExpires } else { $null }
                NonDelegable        = if ($u) { $u.AccountNotDelegated } else { $null }
                PorteurSPN          = if ($u) { [bool]$u.ServicePrincipalName } else { $null }
                SID                 = $m.SID.Value
            })
        }
    }
    $disabled = @($rows | Where-Object { $_.Actif -eq $false } | Sort-Object Compte -Unique)
    if ($disabled.Count -gt 0) {
        Write-Log ("{0} compte(s) DESACTIVE(S) encore membre(s) d'un groupe a privileges : a retirer (hygiene)." -f $disabled.Count) -Level WARN
    }
    [void](Export-Report -Rows $rows -Name "Rapport_GroupesPrivilegies")
}

function Invoke-Audit3DomainAdminsCount {
    Write-Section "Nombre de membres Domain Admins / Enterprise Admins" Magenta
    Write-Info "Recommandation generale : limiter au strict necessaire (quelques comptes nominatifs)." `
               "Aucun seuil universel n'existe - ajustez selon la taille de l'organisation."

    $threshold = Read-IntValue -Prompt "Seuil d'alerte pour Domain Admins" -Default 5 -Min 1 -Max 1000

    $da = @(Get-GroupMembersSafe -Group "Domain Admins" -Recursive)
    $ea = @(Get-GroupMembersSafe -Group "Enterprise Admins" -Recursive)

    $colorDa = if ($da.Count -gt $threshold) { 'Red' } else { 'Green' }
    Write-Host ("Domain Admins : {0} membre(s) (seuil {1})" -f $da.Count, $threshold) -ForegroundColor $colorDa
    Write-ListPreview -Items $da -Format { param($m) "{0} ({1})" -f $m.SamAccountName, $m.objectClass }
    Write-Host ("Enterprise Admins : {0} membre(s) (devrait etre vide hors operation de foret)" -f $ea.Count) -ForegroundColor $(if ($ea.Count -gt 1) { 'Yellow' } else { 'Green' })
    Write-ListPreview -Items $ea -Format { param($m) "{0} ({1})" -f $m.SamAccountName, $m.objectClass }

    if ($da.Count -gt $threshold) {
        Write-Log ("Domain Admins depasse le seuil ({0} > {1}) : revoyez si chaque membre a reellement besoin de ce privilege en permanence." -f $da.Count, $threshold) -Level WARN
    } else {
        Write-Log ("Domain Admins sous le seuil ({0} <= {1})." -f $da.Count, $threshold) -Level OK
    }

    [void](Export-Report -Name "Rapport_DomainAdmins" -Rows (
        @($da | Select-Object SamAccountName, objectClass, @{N='Groupe';E={'Domain Admins'}}) +
        @($ea | Select-Object SamAccountName, objectClass, @{N='Groupe';E={'Enterprise Admins'}})))
}

function Invoke-Audit3BuiltinAdministratorStatus {
    Write-Section "Usage du compte Administrateur integre (RID 500)" Magenta
    Write-Info "Bonne pratique : ce compte ne doit pas etre utilise au quotidien (comptes nominatifs" `
               "dedies a la place), et peut etre desactive s'il existe d'autres comptes Domain Admins actifs."

    try {
        $domainSid = (Get-CachedADDomain).DomainSID.Value
        $builtinAdmin = Get-ADUser -Identity "$domainSid-500" -Properties Enabled, LastLogonDate, PasswordLastSet, ServicePrincipalName -ErrorAction Stop
    } catch {
        Write-Log ("Impossible de lire le compte Administrateur integre : {0}" -f $_.Exception.Message) -Level ERROR
        return
    }

    Write-Host ("Compte : {0}" -f $builtinAdmin.SamAccountName) -ForegroundColor Yellow
    Write-Host ("  Actif                  : {0}" -f $builtinAdmin.Enabled)
    Write-Host ("  Derniere connexion     : {0} (attribut repliquant, precision ~14 jours)" -f $builtinAdmin.LastLogonDate)
    Write-Host ("  Dernier changement mdp : {0}" -f $builtinAdmin.PasswordLastSet)

    if ($builtinAdmin.PasswordLastSet -and $builtinAdmin.PasswordLastSet -lt (Get-Date).AddYears(-1)) {
        Write-Log "Mot de passe du compte Administrateur integre inchange depuis plus d'un an : a renouveler (compte cible privilegie)." -Level WARN
    }
    if ($builtinAdmin.ServicePrincipalName) {
        Write-Log "Le compte Administrateur integre porte un SPN : exposition Kerberoasting directe d'un compte Domain Admin. A retirer en priorite." -Level ERROR
    }
    if ($builtinAdmin.Enabled) {
        if ($builtinAdmin.LastLogonDate -and $builtinAdmin.LastLogonDate -gt (Get-Date).AddDays(-30)) {
            Write-Log "Le compte Administrateur integre est ACTIF et a ete utilise dans les 30 derniers jours : signe d'un usage au quotidien a corriger." -Level WARN
        } else {
            Write-Log "Le compte Administrateur integre est actif mais ne semble pas utilise recemment. Envisagez de le desactiver (item 10)." -Level WARN
        }
    } else {
        Write-Log "Le compte Administrateur integre est deja desactive." -Level OK
    }
}

function Invoke-Remediate3DisableBuiltinAdministrator {
    Write-Section "Desactiver le compte Administrateur integre (RID 500)" Red
    Write-Info "Garde-fou : refuse de continuer si aucun AUTRE compte Domain Admins actif n'existe," `
               "pour ne jamais se retrouver sans aucun moyen d'administration du domaine." `
               "Rappel : le compte RID 500 reste utilisable en mode DSRM / restauration de foret."

    try {
        $domainSid = (Get-CachedADDomain).DomainSID.Value
        $builtinAdmin = Get-ADUser -Identity "$domainSid-500" -Properties Enabled -ErrorAction Stop
    } catch {
        Write-Log ("Impossible de lire le compte Administrateur integre : {0}" -f $_.Exception.Message) -Level ERROR
        return
    }

    if (-not $builtinAdmin.Enabled) { Write-Log "Le compte Administrateur integre est deja desactive." -Level OK; return }

    $otherActiveDA = @(Get-PrivilegedUsers -Groups @('Domain Admins') -Properties Enabled |
        Where-Object { $_.SID.Value -ne $builtinAdmin.SID.Value -and $_.Enabled })

    if ($otherActiveDA.Count -eq 0) {
        Write-Log "Aucun AUTRE compte Domain Admins actif trouve : desactivation du compte integre REFUSEE (risque de perte totale d'acces administratif)." -Level ERROR
        return
    }

    Write-Host ("{0} autre(s) compte(s) Domain Admins actif(s) confirme(s) :" -f $otherActiveDA.Count) -ForegroundColor Yellow
    Write-ListPreview -Items $otherActiveDA -Format { param($u) $u.SamAccountName }

    $current = Get-CurrentUserSid
    if ($current -eq $builtinAdmin.SID.Value) {
        Write-Log "Vous etes connecte AVEC le compte Administrateur integre : reconnectez-vous avec un compte nominatif avant de le desactiver." -Level ERROR
        return
    }

    if (-not (Confirm-Action "Desactiver le compte Administrateur integre (RID 500)" -Strong)) { return }

    Invoke-Guarded -Description "Desactivation du compte Administrateur integre" -Action {
        Disable-ADAccount -Identity $builtinAdmin.DistinguishedName
    }
}

function Invoke-Audit3NonNominativeAccounts {
    Write-Section "Comptes a privileges potentiellement non nominatifs/partages" Magenta
    Write-Info "Heuristique : compte a privileges sans Prenom NI Nom renseigne, ou dont le nom est un" `
               "nom generique (admin, administrateur, root, support, test, svc...). Un compte nominatif" `
               "prefixe (ex : adm-jdupont) est une bonne pratique : il n'est PAS signale."

    $accounts = @(Get-PrivilegedUsers -Groups $Script:AdminGroups -Properties GivenName, Surname, Description, Enabled)
    $genericRegex = '^(admin|adm|administrat(eur|or)|root|support|helpdesk|hotline|test|temp|tmp|backup|sauvegarde|scan|svc|service|install|deploy|sccm|exploit)[-_.]?\d*$'
    $rows = @(foreach ($acc in $accounts) {
        $noName = [string]::IsNullOrWhiteSpace($acc.GivenName) -and [string]::IsNullOrWhiteSpace($acc.Surname)
        $generic = $acc.SamAccountName -match $genericRegex
        if ($noName -or $generic) {
            [PSCustomObject]@{
                SamAccountName = $acc.SamAccountName
                Actif          = $acc.Enabled
                Prenom         = $acc.GivenName
                Nom            = $acc.Surname
                Motif          = (@($(if ($generic) { 'nom generique' }), $(if ($noName) { 'prenom/nom vides' })) | Where-Object { $_ }) -join ' + '
                Description    = $acc.Description
            }
        }
    })

    if ($rows.Count -eq 0) { Write-Log "Aucun compte a privileges suspect (heuristique nom generique / sans prenom-nom)." -Level OK; return }

    Write-Host ("{0} compte(s) a valider (heuristique, a confirmer au cas par cas) :" -f $rows.Count) -ForegroundColor Yellow
    Write-ListPreview -Items $rows -Format { param($r) "{0} : {1}" -f $r.SamAccountName, $r.Motif }
    [void](Export-Report -Rows $rows -Name "Rapport_ComptesNonNominatifs")
}

function Invoke-Audit3KerberoastingRisk {
    Write-Section "Risque Kerberoasting sur les comptes a privileges" Magenta
    Write-Info "Comptes membres d'un groupe a privileges ET porteurs d'un SPN : n'importe quel compte" `
               "authentifie peut demander un ticket de service chiffre avec leur mot de passe, puis" `
               "l'attaquer hors ligne (d'autant plus vite que le chiffrement est RC4)."

    $privilegedSids = Get-ExpandedGroupMemberSids -GroupNames $Script:PrivilegedGroups
    $spnAccounts = @(Get-ADUser -LDAPFilter "(&(servicePrincipalName=*)(!(sAMAccountName=krbtgt*)))" -Properties ServicePrincipalName, 'msDS-SupportedEncryptionTypes', PasswordLastSet, Enabled)
    $atRisk = @($spnAccounts | Where-Object { $privilegedSids.Contains($_.SID.Value) })

    if ($atRisk.Count -eq 0) { Write-Log "Aucun compte a privileges porteur d'un SPN detecte." -Level OK; return }

    $rows = @($atRisk | ForEach-Object {
        [PSCustomObject]@{
            SamAccountName  = $_.SamAccountName
            Actif           = $_.Enabled
            MdpDernierChgt  = $_.PasswordLastSet
            Chiffrement     = Get-SupportedEncryptionTypesLabel -Value $_.'msDS-SupportedEncryptionTypes'
            SPN             = $_.ServicePrincipalName -join ' | '
        }
    })
    Write-Host ("{0} compte(s) a privileges avec SPN (cible Kerberoasting) :" -f $rows.Count) -ForegroundColor Red
    Write-ListPreview -Items $rows -Color Red -Format { param($r) "{0} (actif={1}, mdp change le {2}, chiffrement : {3})" -f $r.SamAccountName, $r.Actif, $r.MdpDernierChgt, $r.Chiffrement }
    [void](Export-Report -Rows $rows -Name "Rapport_KerberoastingRisk" -Comment "Retirer le SPN ou le privilege, sinon mot de passe tres long (25+), AES uniquement, ou migration en gMSA.")
}

function Invoke-RiskySetPrivilegedNotDelegated {
    Write-Section "Marquage des comptes a privileges 'Sensible, ne peut etre delegue'" Red
    Write-Info "Risque : casse les scenarios ou ces comptes sont utilises via une delegation Kerberos" `
               "(ex : compte de service qui delegue l'auth pour un autre systeme)."

    $accounts = @(Get-PrivilegedUsers -Groups $Script:AdminGroups -Properties AccountNotDelegated, Enabled)
    $toFix = @($accounts | Where-Object { -not $_.AccountNotDelegated })

    if ($toFix.Count -eq 0) { Write-Log "Tous les comptes a privileges sont deja marques non-delegables." -Level OK; return }

    Write-Host ("{0} compte(s) a privileges NON marques 'sensible' :" -f $toFix.Count) -ForegroundColor Yellow
    $selected = @(Select-FromList -Items $toFix -Prompt "Comptes a marquer" -Display { param($u) "{0} (actif={1})" -f $u.SamAccountName, $u.Enabled })
    if ($selected.Count -eq 0) { return }

    if (-not (Confirm-Action ("Appliquer le flag 'compte sensible - ne peut etre delegue' a {0} compte(s)" -f $selected.Count) -Strong)) { return }

    foreach ($acc in $selected) {
        Invoke-Guarded -Description ("AccountNotDelegated sur {0}" -f $acc.SamAccountName) -Action {
            Set-ADAccountControl -Identity $acc.DistinguishedName -AccountNotDelegated $true
        }
    }
}

function Invoke-RiskyAddToProtectedUsers {
    Write-Section "Ajout des comptes a privileges dans le groupe 'Protected Users'" Red
    Write-Info "Risque : ces comptes ne pourront plus s'authentifier en NTLM/DES/RC4, n'auront plus de" `
               "delegation possible, ni d'identifiants mis en cache, et leur TGT sera limite a 4h." `
               "Peut casser des taches planifiees, services ou applis legacy utilisant ces comptes." `
               "Ne JAMAIS y placer de comptes de service ni de comptes ordinateur."

    try {
        $mode = [string](Get-CachedADDomain).DomainMode
        if ($mode -match '2000|2003|2008|2012Domain$') {
            Write-Log ("Niveau fonctionnel {0} : les protections cote DC de Protected Users (pas de RC4/DES, TGT 4h) exigent Windows Server 2012 R2 minimum." -f $mode) -Level WARN
        }
    } catch { }

    $accounts = @(Get-PrivilegedUsers -Groups @("Domain Admins", "Enterprise Admins") -Properties ServicePrincipalName, Enabled)
    $puSids = Get-ExpandedGroupMemberSids -GroupNames @('Protected Users')
    $toAdd = @($accounts | Where-Object { -not $puSids.Contains($_.SID.Value) })

    if ($toAdd.Count -eq 0) { Write-Log "Tous les comptes Domain/Enterprise Admins sont deja dans Protected Users." -Level OK; return }

    $current = Get-CurrentUserSid
    Write-Host ("{0} compte(s) candidat(s) a l'ajout dans Protected Users :" -f $toAdd.Count) -ForegroundColor Yellow
    $selected = @(Select-FromList -Items $toAdd -Prompt "Comptes a ajouter" -Display {
        param($u)
        $flags = @()
        if ($u.ServicePrincipalName) { $flags += "porte un SPN : compte de service ? A EXCLURE" }
        if ($u.SID.Value -eq $current) { $flags += "compte de la session courante" }
        if (-not $u.Enabled) { $flags += "desactive" }
        if ($flags) { "{0}  <-- {1}" -f $u.SamAccountName, ($flags -join ', ') } else { $u.SamAccountName }
    })
    if ($selected.Count -eq 0) { return }

    if (-not (Confirm-Action ("Ajouter {0} compte(s) au groupe Protected Users" -f $selected.Count) -Strong)) { return }

    $pu = Resolve-ADGroupRef -Name 'Protected Users'
    foreach ($acc in $selected) {
        Invoke-Guarded -Description ("Ajout de {0} a Protected Users" -f $acc.SamAccountName) -Action {
            Add-ADGroupMember -Identity $pu.Identity -Members $acc.SID
        }
    }
    Write-OutcomeLog "Comptes ajoutes. Gardez au moins un compte d'administration HORS Protected Users (secours) le temps de valider l'absence d'effet de bord." -Level WARN
}

function Invoke-RiskyCleanupSchemaAdmins {
    Write-Section "Nettoyage du groupe Schema Admins" Red
    Write-Info "Bonne pratique : ce groupe doit rester VIDE en permanence, et n'etre peuple que" `
               "temporairement lors d'une modification de schema planifiee."

    $ref = Resolve-ADGroupRef -Name 'Schema Admins'
    try {
        $p = @{ Identity = $ref.Identity; ErrorAction = 'Stop' }
        if ($ref.Server) { $p['Server'] = $ref.Server }
        $members = @(Get-ADGroupMember @p)
    } catch {
        Write-Log ("Lecture de Schema Admins impossible : {0}" -f $_.Exception.Message) -Level ERROR
        return
    }
    if ($members.Count -eq 0) { Write-Log "Le groupe Schema Admins est deja vide." -Level OK; return }

    Write-Host ("{0} membre(s) direct(s) de Schema Admins :" -f $members.Count) -ForegroundColor Yellow
    $targets = @(Select-FromList -Items $members -Prompt "Membres a retirer" -Display { param($m) "{0} ({1})" -f $m.SamAccountName, $m.objectClass })
    if ($targets.Count -eq 0) { return }

    if (-not (Confirm-Action ("Retirer {0} compte(s) de Schema Admins" -f $targets.Count) -Strong)) { return }

    foreach ($m in $targets) {
        Invoke-Guarded -Description ("Retrait de {0} de Schema Admins" -f $m.SamAccountName) -Action {
            $rp = @{ Identity = $ref.Identity; Members = $m.SID; Confirm = $false }
            if ($ref.Server) { $rp['Server'] = $ref.Server }
            Remove-ADGroupMember @rp
        }
    }
}

function Invoke-RiskyForcePasswordExpirationPrivileged {
    Write-Section "Forcer l'expiration des mots de passe sur les comptes a privileges" Red
    Write-Info "Risque : des comptes de service 'admin' avec mot de passe n'expirant jamais peuvent" `
               "cesser de fonctionner s'ils ne sont pas reconfigures avant expiration." `
               "Attention : si le mot de passe est plus ancien que l'age maximal du domaine, le compte" `
               "devra changer son mot de passe DES la prochaine ouverture de session."

    $accounts = @(Get-PrivilegedUsers -Groups @("Domain Admins", "Enterprise Admins", "Administrators") -Properties PasswordNeverExpires, PasswordLastSet, ServicePrincipalName, Enabled)
    $toFix = @($accounts | Where-Object { $_.PasswordNeverExpires })

    if ($toFix.Count -eq 0) { Write-Log "Aucun compte a privileges avec mot de passe n'expirant jamais." -Level OK; return }

    $maxAge = $null
    try { $maxAge = (Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop).MaxPasswordAge } catch { }
    Write-Host ("{0} compte(s) concerne(s) :" -f $toFix.Count) -ForegroundColor Yellow
    $selected = @(Select-FromList -Items $toFix -Prompt "Comptes a traiter" -Display {
        param($u)
        $expired = $maxAge -and $maxAge.TotalDays -gt 0 -and $u.PasswordLastSet -and ($u.PasswordLastSet -lt (Get-Date).Add(-$maxAge))
        $t = "{0} (mdp change le {1})" -f $u.SamAccountName, $u.PasswordLastSet
        if ($u.ServicePrincipalName) { $t += "  <-- porte un SPN (compte de service ?)" }
        if ($expired) { $t += "  <-- expirera IMMEDIATEMENT" }
        $t
    })
    if ($selected.Count -eq 0) { return }

    if (-not (Confirm-Action ("Activer l'expiration du mot de passe sur {0} compte(s) (PasswordNeverExpires = false)" -f $selected.Count) -Strong)) { return }

    foreach ($acc in $selected) {
        Invoke-Guarded -Description ("Activation expiration mdp sur {0}" -f $acc.SamAccountName) -Action {
            Set-ADUser -Identity $acc.DistinguishedName -PasswordNeverExpires $false
        }
    }
    Write-OutcomeLog "Prevenez les proprietaires de ces comptes AVANT expiration effective du mot de passe." -Level WARN
}

function Invoke-Remediate3RestrictPrivilegedLogonWorkstations {
    Write-Section "Restreindre les comptes a privileges a des postes d'administration dedies (PAW)" Red
    Write-Info "Positionne l'attribut 'Se connecter a' (LogonWorkstations) : le compte ne pourra plus" `
               "ouvrir de session que sur les machines listees. Risque : verrouillage du compte hors" `
               "de ces machines - gardez toujours un moyen d'acces de secours (autre compte, console DC)." `
               "Pensez a inclure les DC si le compte doit encore s'y connecter."

    $accounts = @(Get-PrivilegedUsers -Groups @("Domain Admins", "Enterprise Admins") -Properties LogonWorkstations)
    if ($accounts.Count -eq 0) { Write-Log "Aucun compte Domain/Enterprise Admins trouve." -Level OK; return }

    $current = Get-CurrentUserSid
    $selected = @(Select-FromList -Items $accounts -Prompt "Comptes a restreindre" -Display {
        param($u)
        $t = "{0} (actuel : {1})" -f $u.SamAccountName, $(if ($u.LogonWorkstations) { $u.LogonWorkstations } else { 'aucune restriction' })
        if ($u.SID.Value -eq $current) { $t += "  <-- compte de la session courante" }
        $t
    })
    if ($selected.Count -eq 0) { return }

    $workstations = Read-Host "Noms NetBIOS des postes d'administration autorises, separes par une virgule (ex : PAW01,PAW02)"
    $wsArr = @($workstations -split '[,; ]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($wsArr.Count -eq 0) { Write-Log "Aucun poste fourni, action annulee." -Level WARN; return }
    foreach ($w in $wsArr) {
        if (-not (Get-ADComputer -Filter "Name -eq '$($w -replace "'", "''")'" -ErrorAction SilentlyContinue)) {
            Write-Log ("Poste '{0}' introuvable dans l'annuaire : verifiez l'orthographe (risque de verrouillage du compte)." -f $w) -Level WARN
        }
    }
    $wsList = $wsArr -join ','

    if (-not (Confirm-Action ("Restreindre {0} compte(s) aux postes : {1}" -f $selected.Count, $wsList) -Strong)) { return }

    foreach ($acc in $selected) {
        Invoke-Guarded -Description ("Restriction de connexion de {0} aux postes {1}" -f $acc.SamAccountName, $wsList) -Action {
            Set-ADUser -Identity $acc.DistinguishedName -LogonWorkstations $wsList
        }
    }
}

function Get-ProtectedObjectSids {
    <#
        SID de TOUS les objets (utilisateurs, ordinateurs ET groupes imbriques) membres
        directs ou indirects des groupes proteges par AdminSDHolder, via la regle LDAP
        LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941). Contrairement a
        Get-ADGroupMember -Recursive, inclut les groupes imbriques (eux aussi proteges).
    #>
    $protectedGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators',
                         'Backup Operators', 'Server Operators', 'Print Operators', 'Domain Controllers',
                         'Read-only Domain Controllers', 'Key Admins', 'Enterprise Key Admins')
    $sids = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($g in $protectedGroups) {
        try {
            $ref = Resolve-ADGroupRef -Name $g
            $p = @{ Identity = $ref.Identity; ErrorAction = 'Stop' }
            if ($ref.Server) { $p['Server'] = $ref.Server }
            $grp = Get-ADGroup @p
            [void]$sids.Add($grp.SID.Value)
            $q = @{ LDAPFilter = "(memberOf:1.2.840.113556.1.4.1941:=$($grp.DistinguishedName))"; Properties = 'objectSid'; ErrorAction = 'Stop' }
            foreach ($o in @(Get-ADObject @q)) { if ($o.objectSid) { [void]$sids.Add($o.objectSid.Value) } }
        } catch {
            Write-Log ("Lecture du groupe protege '{0}' impossible : {1}" -f $g, $_.Exception.Message) -Level WARN
        }
    }
    foreach ($s in (Get-AlwaysProtectedPrincipalSids)) { [void]$sids.Add($s) }
    return , $sids
}

function Get-AdminCountOrphans {
    # Objets avec adminCount=1 qui ne sont PLUS membres d'aucun groupe protege :
    # ils gardent un ACL fige (heritage desactive) herite d'AdminSDHolder.
    $protectedSids = Get-ProtectedObjectSids
    $objs = @(Get-ADObject -LDAPFilter "(&(adminCount=1)(|(objectClass=user)(objectClass=group)))" -Properties objectSid, sAMAccountName, objectClass, whenChanged -ErrorAction SilentlyContinue)
    return @($objs | Where-Object {
        $_.objectSid -and -not $protectedSids.Contains($_.objectSid.Value) -and
        $_.sAMAccountName -notlike 'krbtgt*' -and
        -not ($_.objectSid.Value -like 'S-1-5-32-*')
    })
}

function Invoke-Audit3AdminCountOrphans {
    Write-Section "Comptes 'adminCount=1' orphelins (anciens administrateurs)" Magenta
    Write-Info "Un compte retire d'un groupe protege garde adminCount=1 et un ACL fige sans heritage :" `
               "les delegations de l'UO ne s'y appliquent plus, et ce sont souvent d'anciens comptes" `
               "d'administration oublies. A nettoyer (item 14) apres verification."

    $orphans = @(Get-AdminCountOrphans)
    if ($orphans.Count -eq 0) { Write-Log "Aucun objet adminCount=1 orphelin." -Level OK; return }

    Write-Host ("{0} objet(s) adminCount=1 hors groupes proteges :" -f $orphans.Count) -ForegroundColor Yellow
    Write-ListPreview -Items $orphans -Format { param($o) "{0} ({1})" -f $o.sAMAccountName, $o.objectClass }
    [void](Export-Report -Name "Rapport_AdminCountOrphelins" -Rows ($orphans | Select-Object sAMAccountName, objectClass, DistinguishedName, whenChanged))
}

function Invoke-Remediate3CleanAdminCountOrphans {
    Write-Section "Nettoyer les comptes 'adminCount=1' orphelins" Red
    Write-Info "Remet adminCount a vide et REACTIVE l'heritage des permissions sur les objets choisis :" `
               "ils retrouvent les delegations de leur UO (helpdesk, etc.). Les ACE explicites existantes" `
               "sont conservees. Risque faible, mais l'ACL effectif de l'objet change."

    $orphans = @(Get-AdminCountOrphans)
    if ($orphans.Count -eq 0) { Write-Log "Aucun objet adminCount=1 orphelin." -Level OK; return }

    $selected = @(Select-FromList -Items $orphans -Prompt "Objets a nettoyer" -Display { param($o) "{0} ({1}) - {2}" -f $o.sAMAccountName, $o.objectClass, $o.DistinguishedName })
    if ($selected.Count -eq 0) { return }
    if (-not (Confirm-Action ("Nettoyer adminCount et reactiver l'heritage sur {0} objet(s)" -f $selected.Count) -Strong)) { return }

    foreach ($o in $selected) {
        Invoke-Guarded -Description ("Nettoyage adminCount + heritage ACL sur {0}" -f $o.sAMAccountName) -Action {
            Set-ADObject -Identity $o.DistinguishedName -Clear adminCount
            $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($o.DistinguishedName)")
            $de.ObjectSecurity.SetAccessRuleProtection($false, $true)
            $de.CommitChanges()
            $de.Dispose()
        }
    }
    Write-OutcomeLog "Si un objet nettoye est encore membre (indirect) d'un groupe protege, SDProp le reprotegera sous 60 min : verifiez avec l'audit (item 12)." -Level INFO
}

function Invoke-Audit3SensitiveGroupsMembership {
    Write-Section "Groupes sensibles souvent oublies (Pre-Windows 2000, DnsAdmins, operateurs...)" Magenta
    Write-Info "- 'Acces compatible pre-Windows 2000' contenant 'Tout le monde' ou 'Anonyme' : lecture" `
               "  anonyme de l'annuaire (enumeration des comptes, groupes...)." `
               "- DnsAdmins, operateurs (comptes, serveurs, sauvegarde, impression) et GPCO : chemins" `
               "  d'elevation connus vers Domain Admins ; doivent etre vides ou tres restreints."

    $rows = [System.Collections.Generic.List[object]]::new()
    $preWin2k = Resolve-ADGroupRef -Name 'Pre-Windows 2000 Compatible Access'
    try {
        $members = @(Get-ADGroup -Identity $preWin2k.Identity -Properties member -ErrorAction Stop).member
        foreach ($dn in $members) {
            $sid = $null
            try { $sid = (Get-ADObject -Identity $dn -Properties objectSid -ErrorAction Stop).objectSid.Value } catch { }
            if (-not $sid -and $dn -match '^CN=(S-1-[\d-]+),') { $sid = $Matches[1] }
            $risk = switch ($sid) {
                'S-1-1-0'  { 'CRITIQUE : Tout le monde (lecture anonyme possible)' }
                'S-1-5-7'  { 'CRITIQUE : Ouverture de session anonyme' }
                'S-1-5-11' { 'Normal (Utilisateurs authentifies)' }
                default    { 'A verifier' }
            }
            $rows.Add([PSCustomObject]@{ Groupe = 'Pre-Windows 2000 Compatible Access'; Membre = $dn; SID = $sid; Evaluation = $risk })
        }
    } catch {
        Write-Log ("Lecture du groupe 'Acces compatible pre-Windows 2000' impossible : {0}" -f $_.Exception.Message) -Level WARN
    }

    foreach ($g in @('DnsAdmins', 'Account Operators', 'Server Operators', 'Backup Operators', 'Print Operators', 'Group Policy Creator Owners', 'Key Admins', 'Enterprise Key Admins')) {
        foreach ($m in (Get-GroupMembersSafe -Group $g -Recursive)) {
            $rows.Add([PSCustomObject]@{ Groupe = $g; Membre = $m.SamAccountName; SID = $m.SID.Value; Evaluation = 'Doit etre vide ou justifie' })
        }
    }

    if ($rows.Count -eq 0) { Write-Log "Aucun membre dans les groupes sensibles controles." -Level OK; return }
    foreach ($r in $rows) {
        $color = if ($r.Evaluation -like 'CRITIQUE*') { 'Red' } elseif ($r.Evaluation -like 'Normal*') { 'DarkGray' } else { 'Yellow' }
        Write-Host ("  - {0,-36} : {1} ({2})" -f $r.Groupe, $r.Membre, $r.Evaluation) -ForegroundColor $color
    }
    [void](Export-Report -Rows $rows -Name "Rapport_GroupesSensibles")
}

function Get-DomainRootDangerousAces {
    <#
        ACE "Autoriser" de la racine du domaine qui donnent le controle du domaine : DCSync
        (Replicating Directory Changes All, ou "tous les droits etendus"), Controle total,
        WriteDacl, WriteOwner. Les titulaires legitimes par defaut (Domain Controllers,
        Enterprise Domain Controllers, Administrateurs, Domain/Enterprise Admins, SYSTEM) sont
        ignores. Comparaison par SID (independante de la langue). Les ACE "heritage seulement"
        ou limitees a un type d'objet enfant ne s'appliquent pas a la racine : ignorees.
        Note : "Controle total" est un masque COMPOSITE, teste par egalite (un simple -band
        signalerait a tort toute ACE de lecture).
    #>
    $dom = Get-CachedADDomain
    $sid = $dom.DomainSID.Value
    $rootSid = Get-RootDomainSid
    $legit = @("$sid-512", "$sid-516", "$rootSid-519", "$rootSid-498", 'S-1-5-9', 'S-1-5-18', 'S-1-5-32-544')
    $acl = (Get-ADObject -Identity $dom.DistinguishedName -Properties nTSecurityDescriptor -ErrorAction Stop).nTSecurityDescriptor
    if (-not $acl) { throw "Descripteur de securite de la racine du domaine illisible." }
    $getChangesAll = [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    $R = [System.DirectoryServices.ActiveDirectoryRights]
    $rows = foreach ($ace in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
        if ($ace.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
        if ($ace.InheritedObjectType -ne [guid]::Empty) { continue }
        $aceSid = $ace.IdentityReference.Value
        if ($legit -contains $aceSid) { continue }
        $rights = $ace.ActiveDirectoryRights
        $what = @()
        if (($rights -band $R::GenericAll) -eq $R::GenericAll) { $what += 'Controle total' }
        else {
            if ($rights -band $R::WriteDacl) { $what += 'Modifier les permissions (WriteDacl)' }
            if ($rights -band $R::WriteOwner) { $what += 'Modifier le proprietaire (WriteOwner)' }
            if (($rights -band $R::ExtendedRight) -and ($ace.ObjectType -eq $getChangesAll -or $ace.ObjectType -eq [guid]::Empty)) { $what += 'DCSync (Replicating Directory Changes All)' }
        }
        if ($what.Count -eq 0) { continue }
        $name = try { $ace.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value } catch { $aceSid }
        [PSCustomObject]@{
            Principal            = $name
            SID                  = $aceSid
            Droits               = $what -join ', '
            # Entra Connect (MSOL_*, AAD_*), ancien DirSync (Sync_*), agent Entra Cloud Sync (provAgentgMSA).
            SynchroEntraProbable = [bool]($name -match '\\(MSOL_|AAD_|Sync_|provAgentgMSA)')
        }
    }
    return @($rows)
}

function Invoke-Audit3DomainRootControl {
    Write-Section "Droits de replication (DCSync) et controle de la racine du domaine" Magenta
    Write-Info "Un principal disposant de 'Replicating Directory Changes All' peut extraire TOUS les" `
               "secrets du domaine (DCSync : hachage krbtgt -> Golden Ticket). Controle total, WriteDacl" `
               "et WriteOwner sur la racine permettent de s'accorder ce droit. Les titulaires par defaut" `
               "(DC, Administrateurs, Domain/Enterprise Admins) ne sont pas listes." `
               "Les comptes de synchronisation Entra (MSOL_*, provAgentgMSA) ont legitimement ce droit : ils" `
               "doivent alors etre proteges comme des comptes tier 0."
    try { $rows = @(Get-DomainRootDangerousAces) } catch {
        Write-Log ("Lecture de l'ACL de la racine du domaine impossible : {0}" -f $_.Exception.Message) -Level ERROR
        return
    }
    if ($rows.Count -eq 0) { Write-Log "Aucun principal non standard ne controle la racine du domaine ni ne dispose du droit DCSync." -Level OK; return }
    foreach ($r in $rows) {
        $color = if ($r.SynchroEntraProbable) { 'Yellow' } else { 'Red' }
        Write-Host ("  - {0} : {1}{2}" -f $r.Principal, $r.Droits, $(if ($r.SynchroEntraProbable) { '  (compte de synchronisation Entra Connect probable : a proteger en tier 0)' } else { '' })) -ForegroundColor $color
    }
    $unexpected = @($rows | Where-Object { -not $_.SynchroEntraProbable })
    if ($unexpected.Count -gt 0) { Write-Log ("{0} principal(aux) inattendu(s) avec un controle du domaine : a verifier IMMEDIATEMENT (persistance d'attaquant possible, ou heritage Exchange)." -f $unexpected.Count) -Level ERROR }
    [void](Export-Report -Rows $rows -Name "Rapport_ControleRacineDomaine" -Comment "Retrait d'une ACE : Utilisateurs et ordinateurs AD > Proprietes de la racine > Securite > Avance (apres validation).")
}

function Get-PrivilegedAccountsHygiene {
    <#
        Comptes membres (directs ou indirects) des groupes a privileges : DESACTIVES (membres
        inutiles, a retirer) et ACTIFS mais INACTIFS depuis plus de $Days jours (ou jamais
        connectes, hors comptes crees depuis moins de 30 jours). Le compte Administrateur
        integre (RID 500), dont la non-utilisation est la bonne pratique, est exclu de
        l'inactivite.
    #>
    param([int]$Days = 180)
    $rid500 = "{0}-500" -f (Get-CachedADDomain).DomainSID.Value
    $now = Get-Date
    $users = @(Get-PrivilegedUsers -Groups $Script:PrivilegedGroups -Properties Enabled, LastLogonDate, PasswordLastSet, whenCreated)
    return @(foreach ($u in $users) {
        $state = $null
        if (-not $u.Enabled) { $state = 'Desactive (a retirer des groupes a privileges)' }
        elseif ($u.SID.Value -ne $rid500 -and $u.whenCreated -lt $now.AddDays(-30) -and (-not $u.LastLogonDate -or $u.LastLogonDate -lt $now.AddDays(-$Days))) {
            $state = if ($u.LastLogonDate) { "Inactif depuis plus de $Days jours" } else { 'Jamais connecte' }
        }
        if ($state) {
            [PSCustomObject]@{ SamAccountName = $u.SamAccountName; Actif = $u.Enabled; DerniereConnexion = $u.LastLogonDate; MdpChangeLe = $u.PasswordLastSet; Etat = $state; DN = $u.DistinguishedName }
        }
    })
}

function Invoke-Audit3PrivilegedAccountsHygiene {
    Write-Section "Comptes a privileges inactifs ou desactives" Magenta
    Write-Info "Un compte d'administration inutilise reste une cible (mot de passe ancien, souvent oublie" `
               "des revues) ; un compte desactive n'a rien a faire dans un groupe a privileges." `
               "LastLogonDate est replique avec un retard pouvant atteindre 14 jours."
    $days = Read-IntValue -Prompt "Seuil d'inactivite (jours)" -Default 180 -Min 30 -Max 3650
    $rows = @(Get-PrivilegedAccountsHygiene -Days $days)
    if ($rows.Count -eq 0) { Write-Log ("Aucun compte a privileges desactive ou inactif depuis plus de {0} jours." -f $days) -Level OK; return }
    Write-ListPreview -Items $rows -Color Yellow -Format { param($r) "{0} : {1} (derniere connexion : {2})" -f $r.SamAccountName, $r.Etat, $(if ($r.DerniereConnexion) { $r.DerniereConnexion.ToString('dd/MM/yyyy') } else { 'jamais' }) }
    [void](Export-Report -Rows $rows -Name "Rapport_ComptesPrivilegiesInactifs" -Comment "Retirer des groupes, puis desactiver (theme 18) apres validation avec le titulaire.")
}

function Get-NonStandardPrimaryGroupAccounts {
    <#
        Comptes dont le GROUPE PRINCIPAL (primaryGroupID) n'est pas celui attendu : utilisateurs
        513 (Utilisateurs du domaine) / 514 (Invites), ordinateurs 515 (Ordinateurs du domaine),
        516 (DC), 521 (RODC). L'appartenance via le groupe principal n'apparait PAS dans l'attribut
        memberOf : un primaryGroupID=512 donne les droits Domain Admins de facon discrete.
    #>
    $domSid = (Get-CachedADDomain).DomainSID.Value
    $privileged = @(512, 516, 518, 519, 520, 521, 526, 527)
    $objs = @(Get-ADUser -LDAPFilter '(&(!(primaryGroupID=513))(!(primaryGroupID=514)))' -Properties primaryGroupID, Enabled -ErrorAction Stop) +
            @(Get-ADComputer -LDAPFilter '(&(!(primaryGroupID=515))(!(primaryGroupID=516))(!(primaryGroupID=521)))' -Properties primaryGroupID, Enabled -ErrorAction Stop)
    $names = @{}
    return @(foreach ($o in $objs) {
        $pg = [int]$o.primaryGroupID
        if (-not $names.ContainsKey($pg)) {
            $names[$pg] = try { (Get-ADGroup -Identity ("{0}-{1}" -f $domSid, $pg) -ErrorAction Stop).Name } catch { "RID $pg" }
        }
        [PSCustomObject]@{
            Compte         = $o.SamAccountName
            Classe         = $o.ObjectClass
            Actif          = $o.Enabled
            GroupePrincipal = $names[$pg]
            RID            = $pg
            Evaluation     = if ($pg -in $privileged) { 'CRITIQUE : groupe principal privilegie (appartenance invisible dans memberOf)' } else { 'A verifier : groupe principal inhabituel' }
            DN             = $o.DistinguishedName
        }
    })
}

function Invoke-Audit3NonStandardPrimaryGroup {
    Write-Section "Groupe principal non standard (appartenance cachee)" Magenta
    Write-Info "L'appartenance a un groupe via l'attribut primaryGroupID n'est pas visible dans memberOf" `
               "ni dans la plupart des outils : technique de persistance discrete. Correction : remettre" `
               "le groupe principal par defaut (Utilisateurs/Ordinateurs du domaine) apres verification."
    try { $rows = @(Get-NonStandardPrimaryGroupAccounts) } catch {
        Write-Log ("Recherche impossible : {0}" -f $_.Exception.Message) -Level ERROR
        return
    }
    if ($rows.Count -eq 0) { Write-Log "Tous les comptes ont le groupe principal attendu." -Level OK; return }
    Write-ListPreview -Items $rows -Color Yellow -Format { param($r) "{0} ({1}, actif={2}) : {3} -> {4}" -f $r.Compte, $r.Classe, $r.Actif, $r.GroupePrincipal, $r.Evaluation }
    [void](Export-Report -Rows $rows -Name "Rapport_GroupePrincipalNonStandard" -Comment "Correction : Set-ADUser <compte> -Replace @{primaryGroupID=513} (ajouter d'abord le compte a 'Utilisateurs du domaine').")
}

# ============================================================
#  THEME 2 - COMPTES DE SERVICE
# ============================================================

function Get-ServiceAccountCandidates {
    <#
        Identifie les comptes "candidats compte de service" : porteurs d'au moins un SPN
        (heuristique principale, independante de toute convention de nommage), completes
        par une/des UO choisies interactivement (comptes de service sans SPN).
        Exclut krbtgt / krbtgt_<RODC> (portent le SPN kadmin/changepw : ce ne sont PAS
        des comptes de service et ne doivent jamais etre traites ici) et les comptes
        d'approbation (trusts). Les gMSA ne sont jamais retournes (non vus par Get-ADUser).
    #>
    $props = @('ServicePrincipalName', 'PasswordLastSet', 'PasswordNeverExpires', 'LastLogonDate', 'Enabled', 'Description', 'msDS-SupportedEncryptionTypes', 'userAccountControl')
    $exclude = "(!(sAMAccountName=krbtgt*))(!(userAccountControl:1.2.840.113556.1.4.803:=2048))"
    $bySpn = @(Get-ADUser -LDAPFilter "(&(servicePrincipalName=*)$exclude)" -Properties $props)
    Write-Host ("{0} compte(s) utilisateur porteur(s) d'au moins un SPN (heuristique principale)." -f $bySpn.Count) -ForegroundColor DarkGray

    $extraOUs = @(Select-OUsInteractive -Label "des comptes de service SANS SPN (par convention/emplacement)" -Verb "AJOUTER (en plus des comptes avec SPN)")
    $byOU = @()
    foreach ($ou in $extraOUs) {
        $byOU += @(Get-ADUser -SearchBase $ou -LDAPFilter "(&(objectClass=user)$exclude)" -Properties $props)
    }
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    return @(@($bySpn) + @($byOU) | Where-Object { $_ -and $seen.Add($_.SID.Value) })
}

function Invoke-Audit4ServiceAccountsInventory {
    Write-Section "Inventaire des comptes de service" Magenta
    Write-Info "Heuristique : comptes porteurs d'un SPN, completes par des UO choisies." `
               "Pas de marqueur AD universel 'compte de service' : ce rapport reste une aide," `
               "a valider au cas par cas (proprietaire, usage reel)."

    $accounts = @(Get-ServiceAccountCandidates)
    if ($accounts.Count -eq 0) { Write-Log "Aucun compte de service candidat trouve." -Level OK; return }

    $privilegedSids = Get-ExpandedGroupMemberSids -GroupNames $Script:PrivilegedGroups
    $aesDate = Get-AesKeysIntroductionDate

    $rows = @($accounts | ForEach-Object {
        [PSCustomObject]@{
            SamAccountName         = $_.SamAccountName
            Actif                  = $_.Enabled
            DerniereConnexion      = $_.LastLogonDate
            MdpDernierChangement   = $_.PasswordLastSet
            MdpNExpireJamais       = $_.PasswordNeverExpires
            MdpSansCleAES          = [bool]($aesDate -and $_.PasswordLastSet -and $_.PasswordLastSet -lt $aesDate)
            NombreSPN              = @($_.ServicePrincipalName).Count
            SPN                    = ($_.ServicePrincipalName -join ' | ')
            ChiffrementSupporte    = Get-SupportedEncryptionTypesLabel -Value $_.'msDS-SupportedEncryptionTypes'
            MembreGroupePrivilegie = $privilegedSids.Contains($_.SID.Value)
            Description            = $_.Description
        }
    })

    [void](Export-Report -Rows $rows -Name "Rapport_ComptesDeService")

    $checks = @(
        @{ Rows = @($rows | Where-Object { [string]::IsNullOrWhiteSpace($_.Description) }); Msg = "compte(s) de service sans proprietaire documente dans la Description" }
        @{ Rows = @($rows | Where-Object { $_.MembreGroupePrivilegie }); Msg = "compte(s) de service membre(s) d'un groupe a privileges (item 5)" }
        @{ Rows = @($rows | Where-Object { $_.MdpDernierChangement -and $_.MdpDernierChangement -lt (Get-Date).AddYears(-1) }); Msg = "compte(s) de service avec un mot de passe de plus d'un an (item 6, ou migration gMSA)" }
        @{ Rows = @($rows | Where-Object { $_.MdpSansCleAES }); Msg = "compte(s) dont le mot de passe precede l'introduction d'AES dans le domaine (pas de cle AES : RC4 uniquement)" }
    )
    foreach ($c in $checks) {
        if ($c.Rows.Count -gt 0) { Write-Log ("{0} {1}." -f $c.Rows.Count, $c.Msg) -Level WARN }
    }
}

function Invoke-Audit4WeakEncryption {
    Write-Section "Comptes de service en chiffrement Kerberos faible (sans AES)" Magenta
    Write-Info "Signale les comptes dont msDS-SupportedEncryptionTypes n'inclut pas AES, ET ceux dont le" `
               "mot de passe est anterieur a l'introduction d'AES dans le domaine (aucune cle AES en base," `
               "meme si l'attribut est correct)."
    $accounts = @(Get-ServiceAccountCandidates)
    $aesDate = Get-AesKeysIntroductionDate
    $weak = @($accounts | Where-Object {
        -not (Test-HasAesEncryptionType $_.'msDS-SupportedEncryptionTypes') -or
        ($aesDate -and $_.PasswordLastSet -and $_.PasswordLastSet -lt $aesDate)
    })

    if ($weak.Count -eq 0) { Write-Log "Tous les comptes de service candidats supportent deja AES." -Level OK; return }

    $rows = @($weak | ForEach-Object {
        [PSCustomObject]@{
            SamAccountName = $_.SamAccountName
            Actif          = $_.Enabled
            Chiffrement    = Get-SupportedEncryptionTypesLabel -Value $_.'msDS-SupportedEncryptionTypes'
            MdpChangeLe    = $_.PasswordLastSet
            CleAESProbable = -not ($aesDate -and $_.PasswordLastSet -and $_.PasswordLastSet -lt $aesDate)
        }
    })
    Write-Host ("{0} compte(s) sans AES effectif :" -f $rows.Count) -ForegroundColor Yellow
    Write-ListPreview -Items $rows -Format { param($r) "{0} ({1}{2})" -f $r.SamAccountName, $r.Chiffrement, $(if (-not $r.CleAESProbable) { ', mot de passe trop ancien : pas de cle AES' } else { '' }) }
    [void](Export-Report -Rows $rows -Name "Rapport_ComptesDeService_ChiffrementFaible")
}

function Set-AesEncryptionOnAccounts {
    <#
        Logique commune "forcer AES" (themes 2 et 4) : choix AES seul (24) ou AES+RC4
        transitoire (28), et avertissement par compte si le mot de passe est anterieur a
        l'introduction d'AES (le compte n'a alors AUCUNE cle AES : AES seul le casserait
        tant que son mot de passe n'a pas ete rechange).
    #>
    param([Parameter(Mandatory)][object[]]$Accounts)

    Write-Host ""
    Write-Host "Types de chiffrement a positionner :" -ForegroundColor Cyan
    Write-Host "  [1] AES128 + AES256 uniquement (valeur 24) - cible recommandee"
    Write-Host "  [2] AES128 + AES256 + RC4 (valeur 28) - etape de transition, sans rupture RC4"
    $choice = Read-Host "Choix [1/2] (defaut 1)"
    $value = if ($choice -eq '2') { 28 } else { 24 }

    $aesDate = Get-AesKeysIntroductionDate
    $noAesKeys = @($Accounts | Where-Object { $aesDate -and $_.PasswordLastSet -and $_.PasswordLastSet -lt $aesDate })
    if ($value -eq 24 -and $noAesKeys.Count -gt 0) {
        Write-Host ""
        Write-Host ("ATTENTION : {0} compte(s) ont un mot de passe anterieur au {1:dd/MM/yyyy} (introduction AES) :" -f $noAesKeys.Count, $aesDate) -ForegroundColor Red
        Write-ListPreview -Items $noAesKeys -Color Red -Format { param($a) "{0} (mdp change le {1})" -f $a.SamAccountName, $a.PasswordLastSet }
        Write-Host "Sans cle AES en base, 'AES uniquement' casserait leur authentification Kerberos." -ForegroundColor Yellow
        Write-Host "Reinitialisez d'abord leur mot de passe (theme 2 > 6), ou choisissez AES+RC4." -ForegroundColor Yellow
        if (-not (Read-YesNo -Prompt "Exclure ces comptes du traitement ?" -Default $true)) {
            Write-Log "L'operateur a choisi de forcer AES uniquement sur des comptes sans cle AES." -Level WARN
        } else {
            $ids = @($noAesKeys | ForEach-Object { $_.SID.Value })
            $Accounts = @($Accounts | Where-Object { $ids -notcontains $_.SID.Value })
        }
    }
    if ($Accounts.Count -eq 0) { Write-Log "Aucun compte restant a traiter." -Level INFO; return }

    if (-not (Confirm-Action ("Positionner msDS-SupportedEncryptionTypes = {0} ({1}) sur {2} compte(s)" -f $value, (Get-SupportedEncryptionTypesLabel -Value $value), $Accounts.Count) -Strong)) { return }

    foreach ($acc in $Accounts) {
        Invoke-Guarded -Description ("msDS-SupportedEncryptionTypes={0} sur {1}" -f $value, $acc.SamAccountName) -Action {
            Set-ADUser -Identity $acc.DistinguishedName -Replace @{ "msDS-SupportedEncryptionTypes" = $value }
        }
    }
    Write-OutcomeLog "Les nouveaux tickets de service seront emis en AES au fil de leur renouvellement (purge possible : klist purge sur les serveurs concernes)." -Level OK
}

function Invoke-Remediate4EnableAesOnServiceAccounts {
    Write-Section "Forcer AES sur des comptes de service selectionnes" Red
    Write-Info "Risque : casse l'authentification Kerberos des applications qui ne supportent QUE" `
               "RC4/DES (rare mais existe sur des applis tres anciennes / appliances non-Windows)."

    $accounts = @(Get-ServiceAccountCandidates | Where-Object { -not (Test-HasAesEncryptionType $_.'msDS-SupportedEncryptionTypes') -or $_.'msDS-SupportedEncryptionTypes' -band 0x4 })
    if ($accounts.Count -eq 0) { Write-Log "Aucun compte de service sans AES ou avec RC4 actif a corriger." -Level OK; return }

    Write-Host "Comptes sans AES (ou avec RC4 encore autorise) :" -ForegroundColor Yellow
    $selected = @(Select-FromList -Items $accounts -Prompt "Comptes a corriger" -Display { param($a) "{0} ({1}, mdp change le {2})" -f $a.SamAccountName, (Get-SupportedEncryptionTypesLabel -Value $a.'msDS-SupportedEncryptionTypes'), $a.PasswordLastSet })
    if ($selected.Count -eq 0) { return }
    Set-AesEncryptionOnAccounts -Accounts $selected
}

function Invoke-Remediate4DenyInteractiveLogon {
    Write-Section "Interdire la connexion interactive / RDP des comptes de service" Red
    Write-Info "Cree/complete un groupe dedie, et une GPO qui l'ajoute aux droits 'Interdire l'ouverture" `
               "de session locale' et 'Interdire l'ouverture de session par les services Bureau a distance'." `
               "Risque : si un compte selectionne sert aussi a une maintenance manuelle en session" `
               "interactive, cet acces sera coupe. Note : les droits utilisateur ne FUSIONNENT pas entre" `
               "GPO - si une autre GPO definit deja ces deux droits sur les memes machines, seule celle de" `
               "plus haute priorite s'applique (verifiez avec gpresult)."

    if (-not (Test-GroupPolicyModule)) { return }

    $accounts = @(Get-ServiceAccountCandidates)
    if ($accounts.Count -eq 0) { return }
    $selected = @(Select-FromList -Items $accounts -Prompt "Comptes a restreindre")
    if ($selected.Count -eq 0) { return }

    $groupName = Read-Host "Nom du groupe AD dedie a creer/completer [defaut GG-ComptesDeService-NoInteractif]"
    if ([string]::IsNullOrWhiteSpace($groupName)) { $groupName = "GG-ComptesDeService-NoInteractif" }
    $targetOU = @(Select-OUsInteractive -Label "la GPO d'interdiction de connexion interactive/RDP" -Verb "CIBLER (lien de la GPO)")
    if ($targetOU.Count -eq 0) { Write-Log "Aucune UO ciblee, action annulee (la GPO ne serait liee nulle part)." -Level WARN; return }
    if (Test-TargetsIncludeDCs -Targets $targetOU) {
        Write-Log "La cible inclut l'UO des DC ou la racine : la GPO 'Default Domain Controllers Policy' definit deja des droits utilisateur sur les DC. Preferez des UO de serveurs membres." -Level WARN
    }

    $gpoName = "SEC - Comptes de service - Interdiction logon interactif"
    if (-not (Confirm-Action ("Creer/completer le groupe '{0}' avec {1} compte(s), et creer/lier la GPO '{2}' sur {3} UO" -f $groupName, $selected.Count, $gpoName, $targetOU.Count) -Strong)) { return }

    $groupFilter = "Name -eq '$($groupName -replace "'", "''")'"
    Invoke-Guarded -Description ("Creation/verification du groupe {0}" -f $groupName) -Action {
        $grp = Get-ADGroup -Filter $groupFilter -ErrorAction SilentlyContinue
        if (-not $grp) {
            $grp = New-ADGroup -Name $groupName -SamAccountName $groupName -GroupScope Global -GroupCategory Security -Description "Comptes de service - connexion interactive/RDP interdite (SEC)" -PassThru
        }
        Add-ADGroupMember -Identity $grp -Members ($selected | ForEach-Object { $_.SID })
    }

    Invoke-Guarded -Description ("Creation de la GPO '{0}' (droits utilisateur) et liens" -f $gpoName) -Action {
        $gpo = Get-OrCreateGpo -Name $gpoName
        $groupSid = (Get-ADGroup -Filter $groupFilter -ErrorAction Stop | Select-Object -First 1).SID.Value
        if (-not $groupSid) { throw "Groupe '$groupName' introuvable." }
        Set-GpoSecurityTemplateValues -GpoId $gpo.Id -Section 'Privilege Rights' -Values ([ordered]@{
            'SeDenyInteractiveLogonRight'       = "*$groupSid"
            'SeDenyRemoteInteractiveLogonRight' = "*$groupSid"
        })
        Add-GpoLinkSafe -Name $gpoName -Targets $targetOU
    }
    Write-OutcomeLog ("GPO '{0}' configuree (groupe '{1}' interdit en session locale et RDP) et liee. Prise en compte au prochain gpupdate des machines ciblees." -f $gpoName, $groupName)
}

function Invoke-Remediate4RemoveFromPrivilegedGroups {
    Write-Section "Retirer les comptes de service des groupes a privileges" Red
    Write-Info "Risque : si le compte de service a reellement besoin de ce privilege pour fonctionner," `
               "le retirer cassera l'application concernee. A valider avec le proprietaire applicatif." `
               "Seules les appartenances DIRECTES sont retirables ici (une appartenance indirecte se" `
               "corrige dans le groupe intermediaire, indique dans la liste)."

    $accounts = @(Get-ServiceAccountCandidates)
    if ($accounts.Count -eq 0) { return }
    $accountSids = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($a in $accounts) { [void]$accountSids.Add($a.SID.Value) }

    $hits = [System.Collections.Generic.List[object]]::new()
    foreach ($g in $Script:PrivilegedGroups) {
        $ref = Resolve-ADGroupRef -Name $g
        $direct = [System.Collections.Generic.HashSet[string]]::new()
        try {
            $p = @{ Identity = $ref.Identity; ErrorAction = 'Stop' }
            if ($ref.Server) { $p['Server'] = $ref.Server }
            foreach ($m in @(Get-ADGroupMember @p)) { [void]$direct.Add($m.SID.Value) }
        } catch { Write-Log ("Lecture du groupe '{0}' impossible : {1}" -f $g, $_.Exception.Message) -Level WARN; continue }
        foreach ($m in (Get-GroupMembersSafe -Group $g -Recursive)) {
            if ($accountSids.Contains($m.SID.Value)) {
                $hits.Add([PSCustomObject]@{ Account = $m; Group = $g; Ref = $ref; Direct = $direct.Contains($m.SID.Value) })
            }
        }
    }

    if ($hits.Count -eq 0) { Write-Log "Aucun compte de service detecte dans un groupe a privileges." -Level OK; return }

    Write-Host ("{0} appartenance(s) compte de service / groupe a privileges detectee(s) :" -f $hits.Count) -ForegroundColor Yellow
    $selectable = @($hits | Where-Object { $_.Direct })
    @($hits | Where-Object { -not $_.Direct }) | ForEach-Object { Write-Host ("  (indirect) {0} -> {1} : a corriger dans le groupe imbrique" -f $_.Account.SamAccountName, $_.Group) -ForegroundColor DarkGray }
    if ($selectable.Count -eq 0) { Write-Log "Uniquement des appartenances indirectes : a corriger dans les groupes intermediaires." -Level WARN; return }

    $targets = @(Select-FromList -Items $selectable -Prompt "Appartenances directes a retirer" -Display { param($h) "{0} -> {1}" -f $h.Account.SamAccountName, $h.Group })
    if ($targets.Count -eq 0) { return }

    if (-not (Confirm-Action ("Retirer {0} appartenance(s) a un groupe a privileges" -f $targets.Count) -Strong)) { return }

    foreach ($t in $targets) {
        Invoke-Guarded -Description ("Retrait de {0} du groupe {1}" -f $t.Account.SamAccountName, $t.Group) -Action {
            $rp = @{ Identity = $t.Ref.Identity; Members = $t.Account.SID; Confirm = $false }
            if ($t.Ref.Server) { $rp['Server'] = $t.Ref.Server }
            Remove-ADGroupMember @rp
        }
    }
}

function Invoke-Remediate4RotatePassword {
    Write-Section "Reinitialiser le mot de passe de comptes de service selectionnes" Red
    Write-Host "ATTENTION : l'application/le service utilisant ce compte doit etre reconfigure(e) avec" -ForegroundColor Yellow
    Write-Host "le nouveau mot de passe, sous peine d'interruption au prochain redemarrage/renouvellement." -ForegroundColor Yellow
    Write-Info "Le nouveau mot de passe est affiche UNE SEULE FOIS a l'ecran (jamais journalise) pour" `
               "pouvoir reconfigurer l'application. Les gMSA ne sont jamais concernes."

    $accounts = @(Get-ServiceAccountCandidates)
    if ($accounts.Count -eq 0) { return }
    $selected = @(Select-FromList -Items $accounts -Prompt "Comptes a reinitialiser ('tous' deconseille)" -Display { param($a) "{0} (mdp change le {1})" -f $a.SamAccountName, $a.PasswordLastSet })
    if ($selected.Count -eq 0) { return }

    $length = Read-IntValue -Prompt "Longueur du nouveau mot de passe" -Default 32 -Min 20 -Max 128
    if (-not (Confirm-Action ("Reinitialiser le mot de passe de {0} compte(s) de service" -f $selected.Count) -Strong)) { return }

    foreach ($acc in $selected) {
        $plain = New-RandomComplexPassword -Length $length
        Invoke-Guarded -Description ("Reinitialisation du mot de passe de {0}" -f $acc.SamAccountName) -Action {
            Set-ADAccountPassword -Identity $acc.DistinguishedName -Reset -NewPassword (ConvertTo-SecureString $plain -AsPlainText -Force) -Confirm:$false
        }
        if (-not $Script:SimulationMode -and $Script:LastGuardedResult) {
            Write-Host ("  Nouveau mot de passe de {0} : " -f $acc.SamAccountName) -NoNewline -ForegroundColor Yellow
            Write-Host $plain -ForegroundColor White -BackgroundColor DarkBlue
            [void](Read-Host "  Notez-le dans votre coffre-fort de mots de passe puis appuyez sur Entree (il ne sera plus affiche)")
            Clear-Screen
        }
        Remove-Variable plain -ErrorAction SilentlyContinue
    }
    Write-OutcomeLog "Mots de passe reinitialises (jamais journalises en clair)." -Level WARN
}

function Get-OrEnsureKdsRootKey {
    <#
        Les gMSA necessitent une KDS Root Key au niveau de la foret. Verifie sa presence
        et propose de la creer si absente (aucune incidence sur l'existant).
    #>
    $existing = $null
    try { $existing = Get-KdsRootKey -ErrorAction Stop } catch { }
    if ($existing) {
        $usable = @($existing | Where-Object { $_.EffectiveTime -le (Get-Date) })
        if ($usable.Count -gt 0) {
            Write-Log "KDS Root Key presente et effective (necessaire aux gMSA)." -Level OK
        } else {
            Write-Log ("KDS Root Key presente mais pas encore effective (effective le {0}). Les gMSA ne seront utilisables qu'a partir de cette date." -f ($existing | Sort-Object EffectiveTime | Select-Object -First 1).EffectiveTime) -Level WARN
        }
        return $true
    }

    Write-Host ""
    Write-Host "Aucune KDS Root Key trouvee dans la foret. Elle est necessaire pour utiliser un gMSA." -ForegroundColor Yellow
    Write-Info "En production multi-DC : creez-la normalement et patientez ~10h (replication)." `
               "En environnement mono-DC / labo, il est courant de forcer sa disponibilite immediate."
    $forceNow = Read-YesNo -Prompt "Forcer la disponibilite immediate (mono-DC/labo uniquement) ?"

    if (-not (Confirm-Action "Creer la KDS Root Key de la foret")) { return $false }

    Invoke-Guarded -Description "Creation de la KDS Root Key" -Action {
        if ($forceNow) { Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) | Out-Null }
        else { Add-KdsRootKey -EffectiveImmediately | Out-Null }
    }
    if ($forceNow) { Write-OutcomeLog "KDS Root Key creee avec disponibilite immediate (EffectiveTime -10h)." -Level WARN }
    else { Write-OutcomeLog "KDS Root Key creee. Le gMSA ne sera utilisable qu'apres replication sur tous les DC (~10h)." -Level WARN }
    return ($Script:SimulationMode -or $Script:LastGuardedResult)
}

function Invoke-Remediate4CreateGmsa {
    Write-Section "Assistant de creation d'un compte de service gere (gMSA)" Red
    Write-Info "Cree un NOUVEAU gMSA : ne migre pas automatiquement un compte de service existant." `
               "Reconfigurez ensuite l'application pour utiliser ce compte (le gMSA gere lui-meme" `
               "la rotation de son mot de passe, sans intervention)."

    $gmsaName = Read-Host "Nom du gMSA a creer (max 15 caracteres, lettres/chiffres/-)"
    if ([string]::IsNullOrWhiteSpace($gmsaName) -or $gmsaName.Length -gt 15 -or $gmsaName -notmatch '^[A-Za-z0-9-]+$') {
        Write-Log "Nom invalide (vide, plus de 15 caracteres, ou caracteres non autorises)." -Level ERROR
        return
    }
    if (Get-ADServiceAccount -Filter "Name -eq '$gmsaName'" -ErrorAction SilentlyContinue) {
        Write-Log ("Un compte de service gere nomme '{0}' existe deja." -f $gmsaName) -Level ERROR
        return
    }

    $hostGroupName = Read-Host "Groupe AD des serveurs autorises a recuperer le mot de passe du gMSA"
    $hostGroup = $null
    if (-not [string]::IsNullOrWhiteSpace($hostGroupName)) {
        $hostGroup = Get-ADGroup -Filter "Name -eq '$($hostGroupName -replace "'", "''")'" -ErrorAction SilentlyContinue
    }
    if (-not $hostGroup) {
        Write-Log ("Groupe '{0}' introuvable. Creez-le au prealable (avec les serveurs hebergeant le service) et relancez." -f $hostGroupName) -Level ERROR
        return
    }

    if (-not (Confirm-Action ("Creer le gMSA '{0}', accessible aux membres du groupe '{1}'" -f $gmsaName, $hostGroupName) -Strong)) { return }
    if (-not (Get-OrEnsureKdsRootKey)) { return }

    $domainDNS = (Get-CachedADDomain).DNSRoot
    Invoke-Guarded -Description ("Creation du gMSA {0}" -f $gmsaName) -Action {
        New-ADServiceAccount -Name $gmsaName -DNSHostName "$gmsaName.$domainDNS" -PrincipalsAllowedToRetrieveManagedPassword $hostGroup.DistinguishedName -KerberosEncryptionType AES128, AES256 -Enabled $true
    }

    Write-OutcomeLog ("gMSA '{0}$' cree (AES uniquement). Sur chaque serveur membre de '{1}' (apres redemarrage ou 'klist -li 0x3e7 purge' pour rafraichir son appartenance) : Install-ADServiceAccount {0} puis Test-ADServiceAccount {0}." -f $gmsaName, $hostGroupName)
}

function Invoke-Audit4KerberoastableAccounts {
    Write-Section "Comptes Kerberoastables (tous comptes utilisateur porteurs d'un SPN)" Magenta
    Write-Info "Tout compte utilisateur ACTIF avec SPN peut etre Kerberoaste. Le risque depend surtout de" `
               "l'age/robustesse du mot de passe et du chiffrement (RC4 = cassage beaucoup plus rapide)." `
               "Priorite : privilegie + RC4 + mot de passe ancien."

    $privilegedSids = Get-ExpandedGroupMemberSids -GroupNames $Script:PrivilegedGroups
    $aesDate = Get-AesKeysIntroductionDate
    $accounts = @(Get-ADUser -LDAPFilter "(&(servicePrincipalName=*)(!(sAMAccountName=krbtgt*))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" -Properties ServicePrincipalName, PasswordLastSet, 'msDS-SupportedEncryptionTypes')
    if ($accounts.Count -eq 0) { Write-Log "Aucun compte utilisateur actif porteur d'un SPN." -Level OK; return }

    $rows = @($accounts | ForEach-Object {
        $enc = $_.'msDS-SupportedEncryptionTypes'
        $rc4 = (-not (Test-HasAesEncryptionType $enc)) -or ($aesDate -and $_.PasswordLastSet -and $_.PasswordLastSet -lt $aesDate)
        $ageDays = if ($_.PasswordLastSet) { [int]((Get-Date) - $_.PasswordLastSet).TotalDays } else { $null }
        $score = 0
        if ($privilegedSids.Contains($_.SID.Value)) { $score += 3 }
        if ($rc4) { $score += 2 }
        if ($ageDays -gt 365) { $score += 1 }
        if ($ageDays -gt 1825) { $score += 1 }
        [PSCustomObject]@{
            SamAccountName = $_.SamAccountName
            Privilegie     = $privilegedSids.Contains($_.SID.Value)
            RC4Probable    = $rc4
            AgeMdpJours    = $ageDays
            Chiffrement    = Get-SupportedEncryptionTypesLabel -Value $enc
            Priorite       = switch ($score) { { $_ -ge 5 } { 'CRITIQUE'; break } { $_ -ge 3 } { 'HAUTE'; break } { $_ -ge 2 } { 'MOYENNE'; break } default { 'BASSE' } }
            SPN            = $_.ServicePrincipalName -join ' | '
        }
    } | Sort-Object @{E={ switch ($_.Priorite) { 'CRITIQUE' {0} 'HAUTE' {1} 'MOYENNE' {2} default {3} } }}, SamAccountName)

    foreach ($p in 'CRITIQUE', 'HAUTE', 'MOYENNE', 'BASSE') {
        $n = @($rows | Where-Object { $_.Priorite -eq $p }).Count
        if ($n) { Write-Host ("  {0,-8} : {1} compte(s)" -f $p, $n) -ForegroundColor $(switch ($p) { 'CRITIQUE' {'Red'} 'HAUTE' {'Yellow'} default {'Gray'} }) }
    }
    Write-ListPreview -Items @($rows | Where-Object { $_.Priorite -in 'CRITIQUE', 'HAUTE' }) -Color Yellow -Format { param($r) "{0} [{1}] mdp {2} j, {3}" -f $r.SamAccountName, $r.Priorite, $r.AgeMdpJours, $r.Chiffrement }
    [void](Export-Report -Rows $rows -Name "Rapport_Kerberoastable" -Comment "Remediations : themes 2 > 3 (AES), 2 > 6 (mot de passe long), 2 > 7 (gMSA).")
}

# ============================================================
#  THEME 3 - MOTS DE PASSE ET AUTHENTIFICATION
# ============================================================

function Invoke-ReportPasswordNeverExpires {
    Write-Section "Rapport : comptes avec mot de passe n'expirant jamais" Magenta
    $privilegedSids = Get-ExpandedGroupMemberSids -GroupNames $Script:PrivilegedGroups
    $accounts = @(Get-ADUser -Filter 'PasswordNeverExpires -eq $true' -Properties PasswordNeverExpires, PasswordLastSet, Enabled, ServicePrincipalName, LastLogonDate)
    $rows = @($accounts | ForEach-Object {
        [PSCustomObject]@{
            SamAccountName    = $_.SamAccountName
            Actif             = $_.Enabled
            Privilegie        = $privilegedSids.Contains($_.SID.Value)
            PorteurSPN        = [bool]$_.ServicePrincipalName
            MdpChangeLe       = $_.PasswordLastSet
            DerniereConnexion = $_.LastLogonDate
        }
    })
    $enabled = @($rows | Where-Object { $_.Actif })
    Write-Host ("{0} compte(s) au total, dont {1} actif(s) et {2} actif(s) ET privilegie(s)." -f $rows.Count, $enabled.Count, @($enabled | Where-Object { $_.Privilegie }).Count) -ForegroundColor Yellow
    [void](Export-Report -Rows $rows -Name "Rapport_PwdNeverExpires")
}

$Script:DefaultDomainPolicyGuid = [Guid]'31B2F340-016D-11D2-945F-00C04FB984F9'

function Invoke-Audit11DefaultPasswordPolicy {
    Write-Section "Audit de la politique de mot de passe par defaut du domaine" Magenta

    try {
        $policy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
    } catch {
        Write-Log ("Impossible de lire la politique de mot de passe : {0}" -f $_.Exception.Message) -Level ERROR
        return
    }

    # Valeurs definies dans la GPO 'Default Domain Policy' (c'est ELLE qui fait foi : le PDC
    # reapplique ses valeurs sur l'objet domaine a chaque rafraichissement).
    $gpoValues = @{}
    try {
        $inf = Read-SecurityTemplate -Path (Join-Path (Get-GpoSysvolPath -GpoId $Script:DefaultDomainPolicyGuid) "MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf")
        if ($inf.Contains('System Access')) { $gpoValues = $inf['System Access'] }
    } catch { }

    $rows = @(
        [PSCustomObject]@{ Parametre = "Longueur minimale";     Effectif = $policy.MinPasswordLength;        GPO = $gpoValues['MinimumPasswordLength']; Recommandation = ">= 12 (14 max en politique de domaine ; au-dela : FGPP)" }
        [PSCustomObject]@{ Parametre = "Complexite";            Effectif = $policy.ComplexityEnabled;        GPO = $gpoValues['PasswordComplexity'];    Recommandation = "Activee" }
        [PSCustomObject]@{ Parametre = "Historique";            Effectif = $policy.PasswordHistoryCount;     GPO = $gpoValues['PasswordHistorySize'];   Recommandation = ">= 24" }
        [PSCustomObject]@{ Parametre = "Age maximal (jours)";   Effectif = [int]$policy.MaxPasswordAge.TotalDays; GPO = $gpoValues['MaximumPasswordAge']; Recommandation = "Selon politique interne (0 = jamais : uniquement avec longueur elevee)" }
        [PSCustomObject]@{ Parametre = "Age minimal (jours)";   Effectif = [int]$policy.MinPasswordAge.TotalDays; GPO = $gpoValues['MinimumPasswordAge']; Recommandation = ">= 1" }
        [PSCustomObject]@{ Parametre = "Seuil de verrouillage"; Effectif = $policy.LockoutThreshold;         GPO = $gpoValues['LockoutBadCount'];       Recommandation = "Entre 5 et 50, jamais 0" }
        [PSCustomObject]@{ Parametre = "Duree de verrouillage"; Effectif = $policy.LockoutDuration;          GPO = $gpoValues['LockoutDuration'];       Recommandation = ">= 15 min" }
        [PSCustomObject]@{ Parametre = "Chiffrement reversible"; Effectif = $policy.ReversibleEncryptionEnabled; GPO = $gpoValues['ClearTextPassword']; Recommandation = "Desactive" }
    )
    $rows | Format-Table -AutoSize | Out-String -Width 200 | Write-Host

    $issues = @()
    if ($policy.MinPasswordLength -lt 8) { $issues += "Longueur minimale < 8 (CRITIQUE)" }
    elseif ($policy.MinPasswordLength -lt 12) { $issues += "Longueur minimale < 12" }
    if (-not $policy.ComplexityEnabled) { $issues += "Complexite desactivee" }
    if ($policy.PasswordHistoryCount -lt 24) { $issues += "Historique < 24" }
    if ($policy.LockoutThreshold -eq 0) { $issues += "Verrouillage de compte DESACTIVE (LockoutThreshold=0)" }
    if ($policy.ReversibleEncryptionEnabled) { $issues += "Chiffrement reversible ACTIVE (mots de passe recuperables en clair)" }

    if ($gpoValues.Count -gt 0 -and $gpoValues['MinimumPasswordLength'] -and [int]$gpoValues['MinimumPasswordLength'] -ne $policy.MinPasswordLength) {
        Write-Log "Ecart entre la GPO 'Default Domain Policy' et la valeur effective : la GPO l'emportera au prochain rafraichissement du PDC." -Level WARN
    }

    $fgpp = @(Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue)
    if ($fgpp.Count -gt 0) {
        Write-Host ("{0} Fine-Grained Password Policy (FGPP) definie(s) :" -f $fgpp.Count) -ForegroundColor Cyan
        foreach ($f in $fgpp) {
            Write-Host ("  - {0} (precedence {1}, longueur {2}, verrouillage {3}) -> {4}" -f $f.Name, $f.Precedence, $f.MinPasswordLength, $f.LockoutThreshold, (@($f.AppliesTo | ForEach-Object { ($_ -split ',')[0] -replace '^CN=' }) -join ', '))
        }
    }

    if ($issues.Count -gt 0) {
        Write-Log ("Points a corriger : {0}" -f ($issues -join ' ; ')) -Level WARN
    } else {
        Write-Log "Politique de mot de passe par defaut conforme aux recommandations de base." -Level OK
    }
}

function Invoke-Remediate11HardenDefaultPasswordPolicy {
    Write-Section "Corriger la politique de mot de passe par defaut du domaine" Red
    Write-Info "La politique de mot de passe du domaine est portee par la GPO 'Default Domain Policy' :" `
               "modifier seulement l'objet domaine serait annule au prochain rafraichissement des GPO sur" `
               "le PDC. Le script met donc a jour LA GPO (apres sauvegarde) PUIS l'objet domaine (effet" `
               "immediat). Risque : exigences plus fortes au prochain changement de mot de passe."

    if (-not (Test-GroupPolicyModule)) { return }
    try { $current = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop } catch { Write-Log $_.Exception.Message -Level ERROR; return }

    $length   = Read-IntValue -Prompt "Longueur minimale du mot de passe (8-14 ; au-dela utilisez une FGPP)" -Default ([Math]::Max(12, [Math]::Min(14, $current.MinPasswordLength))) -Min 8 -Max 14
    $history  = Read-IntValue -Prompt "Nombre de mots de passe conserves dans l'historique (0-24)" -Default 24 -Min 0 -Max 24
    $lockout  = Read-IntValue -Prompt "Seuil de verrouillage (tentatives echouees, 3-100)" -Default 10 -Min 3 -Max 100
    $duration = Read-IntValue -Prompt "Duree de verrouillage et fenetre d'observation (minutes)" -Default 15 -Min 1 -Max 99999

    try {
        $ddp = Get-GPO -Guid $Script:DefaultDomainPolicyGuid -ErrorAction Stop
    } catch {
        Write-Log "GPO 'Default Domain Policy' introuvable (GUID standard) : modification de l'objet domaine uniquement - verifiez quelle GPO liee a la racine definit la politique de mot de passe." -Level WARN
        $ddp = $null
    }

    if (-not (Confirm-Action ("Appliquer : longueur min={0}, complexite=activee, historique={1}, verrouillage={2} tentatives/{3} min" -f $length, $history, $lockout, $duration) -Strong)) { return }

    if ($ddp) {
        Invoke-Guarded -Description "Sauvegarde puis mise a jour de la GPO 'Default Domain Policy' (modele de securite)" -Action {
            Backup-SingleGpo -GpoId $ddp.Id -Label "Default Domain Policy"
            Set-GpoSecurityTemplateValues -GpoId $ddp.Id -Section 'System Access' -Values ([ordered]@{
                'MinimumPasswordLength' = $length
                'PasswordComplexity'    = 1
                'PasswordHistorySize'   = $history
                'LockoutBadCount'       = $lockout
                'ResetLockoutCount'     = $duration
                'LockoutDuration'       = $duration
            })
        }
    }
    Invoke-Guarded -Description "Mise a jour de l'objet domaine (effet immediat)" -Action {
        Set-ADDefaultDomainPasswordPolicy -Identity (Get-CachedADDomain).DistinguishedName -MinPasswordLength $length -ComplexityEnabled $true -PasswordHistoryCount $history -LockoutThreshold $lockout -LockoutDuration ([TimeSpan]::FromMinutes($duration)) -LockoutObservationWindow ([TimeSpan]::FromMinutes($duration))
    }
    Write-OutcomeLog "Politique de mot de passe mise a jour (GPO + objet domaine). Les nouvelles regles s'appliquent au prochain changement de mot de passe."
}

function Invoke-Remediate11CreateServiceAccountFGPP {
    Write-Section "Creer une Fine-Grained Password Policy pour les comptes de service" Red
    Write-Info "S'applique UNIQUEMENT au groupe cible fourni (jamais a tout le domaine) - permet une" `
               "politique plus longue (jusqu'a 255 caracteres), adaptee aux comptes de service, sans" `
               "toucher la politique par defaut des comptes utilisateurs."

    $groupName = Read-Host "Groupe AD cible (comptes de service) - sera cree s'il n'existe pas"
    if ([string]::IsNullOrWhiteSpace($groupName)) { Write-Log "Nom de groupe vide, action annulee." -Level WARN; return }
    $length = Read-IntValue -Prompt "Longueur minimale du mot de passe pour ce groupe" -Default 24 -Min 14 -Max 255
    Write-Info "Verrouillage : 0 = jamais (evite un deni de service sur un compte applicatif, mais permet" `
               "le brute-force en ligne : a compenser par la longueur et la surveillance des echecs 4625/4771)."
    $lockout = Read-IntValue -Prompt "Seuil de verrouillage pour ce groupe (0 = desactive)" -Default 0 -Min 0 -Max 1000

    $policyName = "SEC-PSO-ComptesDeService"
    if (-not (Confirm-Action ("Creer la FGPP '{0}' (longueur min {1}, verrouillage {2}) et l'appliquer au groupe '{3}'" -f $policyName, $length, $lockout, $groupName) -Strong)) { return }

    $groupFilter = "Name -eq '$($groupName -replace "'", "''")'"
    Invoke-Guarded -Description ("Creation du groupe {0} (si absent)" -f $groupName) -Action {
        if (-not (Get-ADGroup -Filter $groupFilter -ErrorAction SilentlyContinue)) {
            New-ADGroup -Name $groupName -SamAccountName $groupName -GroupScope Global -GroupCategory Security -Description "Comptes de service - FGPP dediee (SEC)"
        }
    }

    Invoke-Guarded -Description ("Creation/MAJ de la FGPP {0} et application au groupe" -f $policyName) -Action {
        $existing = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$policyName'" -ErrorAction SilentlyContinue
        if (-not $existing) {
            New-ADFineGrainedPasswordPolicy -Name $policyName -Precedence 10 -MinPasswordLength $length -ComplexityEnabled $true -PasswordHistoryCount 24 -MaxPasswordAge ([TimeSpan]::Zero) -MinPasswordAge ([TimeSpan]::FromDays(1)) -LockoutThreshold $lockout -LockoutDuration ([TimeSpan]::FromMinutes(15)) -LockoutObservationWindow ([TimeSpan]::FromMinutes(15)) -ReversibleEncryptionEnabled $false -Description "FGPP comptes de service - deployee par le script de remediation AD"
        } else {
            Set-ADFineGrainedPasswordPolicy -Identity $policyName -MinPasswordLength $length -LockoutThreshold $lockout
        }
        $subjects = @((Get-ADFineGrainedPasswordPolicy -Identity $policyName -Properties AppliesTo).AppliesTo)
        $grp = Get-ADGroup -Filter $groupFilter -ErrorAction Stop | Select-Object -First 1
        if (-not $grp) { throw "Groupe '$groupName' introuvable." }
        if ($subjects -notcontains $grp.DistinguishedName) { Add-ADFineGrainedPasswordPolicySubject -Identity $policyName -Subjects $grp }
    }
    Write-OutcomeLog ("FGPP '{0}' appliquee au groupe '{1}'. Ajoutez-y les comptes de service concernes (la FGPP s'appliquera a leur prochain changement de mot de passe)." -f $policyName, $groupName)
}

function Invoke-Remediate11GenerateMfaRecommendations {
    Write-Section "Generer les recommandations MFA / Conditional Access (environnements hybrides)" Cyan
    Write-Info "Impact : AUCUN. Ecrit uniquement un fichier de recommandations dans Logs\Procedures." `
               "La mise en oeuvre reelle (Entra ID / Conditional Access) est hors perimetre technique" `
               "de ce script (base PowerShell/AD on-premises)."

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
9. Ne JAMAIS synchroniser les comptes a privileges AD (Domain Admins...) vers Entra ID, et ne
   pas donner de role d'administration cloud a un compte synchronise depuis l'AD (separation
   des tiers : une compromission AD ne doit pas donner le controle du tenant, et inversement).
10. Proteger le serveur Entra Connect / Cloud Sync comme un controleur de domaine (tier 0) :
   son compte de synchronisation dispose de droits de replication des secrets (DCSync).
'@

    $dir = Join-Path $Script:LogDir "Procedures"
    $file = Join-Path $dir "Recommandations_MFA_ConditionalAccess.txt"
    Invoke-Guarded -Description "Generation des recommandations MFA/Conditional Access" -Action {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath $file -Value $content -Encoding UTF8
    }
    Write-OutcomeLog ("Recommandations generees : {0}" -f $file)
}

function Invoke-SafeClearPasswordNotRequired {
    Write-Section "Retrait du flag 'Mot de passe non requis' (PASSWD_NOTREQD)" Cyan
    Write-Info "Impact : AUCUN immediat. Ne force pas de changement de mot de passe, retire simplement" `
               "l'exemption de politique de mot de passe pour le PROCHAIN changement." `
               "Les comptes avec ce flag peuvent avoir un mot de passe VIDE : a reinitialiser en priorite."

    $accounts = @(Get-ADUser -LDAPFilter "(&(userAccountControl:1.2.840.113556.1.4.803:=32)(!(userAccountControl:1.2.840.113556.1.4.803:=2048)))" -Properties Enabled, PasswordLastSet)

    if ($accounts.Count -eq 0) {
        Write-Log "Aucun compte utilisateur avec 'Mot de passe non requis'." -Level OK
        return
    }

    Write-Host ("{0} compte(s) concerne(s) (dont {1} actif(s)) :" -f $accounts.Count, @($accounts | Where-Object Enabled).Count) -ForegroundColor Yellow
    $selected = @(Select-FromList -Items $accounts -Prompt "Comptes a corriger" -Display { param($a) "{0} (actif={1}, mdp change le {2})" -f $a.SamAccountName, $a.Enabled, $a.PasswordLastSet })
    if ($selected.Count -eq 0) { return }

    if (Confirm-Action ("Retirer le flag PASSWD_NOTREQD sur {0} compte(s)" -f $selected.Count)) {
        foreach ($acc in $selected) {
            Invoke-Guarded -Description ("Retrait PASSWD_NOTREQD sur {0}" -f $acc.SamAccountName) -Action {
                Set-ADUser -Identity $acc.DistinguishedName -PasswordNotRequired $false
            }
        }
    }
}

function Invoke-Audit11GppPasswords {
    Write-Section "Mots de passe GPP (cpassword) dans SYSVOL" Magenta
    Write-Info "Les preferences de strategie de groupe (Groups.xml, Services.xml, ScheduledTasks.xml...)" `
               "pouvaient stocker un mot de passe 'cpassword' chiffre avec une cle AES PUBLIEE par" `
               "Microsoft (MS14-025) : tout utilisateur du domaine peut le dechiffrer. Lecture seule."

    $dom = Get-CachedADDomain
    $root = "\\{0}\SYSVOL\{0}\Policies" -f $dom.DNSRoot
    if (-not (Test-Path -LiteralPath $root)) { Write-Log ("SYSVOL inaccessible : {0}" -f $root) -Level ERROR; return }

    $files = @(Get-ChildItem -LiteralPath $root -Recurse -Include 'Groups.xml', 'Services.xml', 'ScheduledTasks.xml', 'DataSources.xml', 'Printers.xml', 'Drives.xml' -File -ErrorAction SilentlyContinue)
    Write-Host ("{0} fichier(s) de preferences GPO analyses..." -f $files.Count) -ForegroundColor DarkGray
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($f in $files) {
        try {
            $entries = @(Get-GppPasswordEntries -Content (Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop))
            if ($entries.Count -eq 0) { continue }
            $guid = if ($f.FullName -match '\{([0-9A-Fa-f-]{36})\}') { $Matches[1] } else { $null }
            $gpoName = $null
            if ($guid) { try { $gpoName = (Get-GPO -Guid $guid -ErrorAction Stop).DisplayName } catch { $gpoName = "(GPO $guid)" } }
            foreach ($e in $entries) {
                $rows.Add([PSCustomObject]@{ GPO = $gpoName; GUID = $guid; Fichier = $f.FullName; Element = $e.Element; Compte = $e.Compte })
            }
        } catch { Write-Log ("Lecture impossible : {0}" -f $f.FullName) -Level WARN }
    }

    if ($rows.Count -eq 0) { Write-Log "Aucun mot de passe GPP (cpassword) trouve dans SYSVOL." -Level OK; return }
    Write-Host ("{0} mot(s) de passe GPP trouve(s) - CRITIQUE :" -f $rows.Count) -ForegroundColor Red
    Write-ListPreview -Items $rows -Color Red -Format { param($r) "{0} (compte : {1}) - {2}" -f $r.GPO, $r.Compte, $r.Fichier }
    [void](Export-Report -Rows $rows -Name "Rapport_GPP_Passwords" -Comment "Supprimez ces preferences ET changez IMMEDIATEMENT les mots de passe concernes (ils doivent etre consideres comme divulgues).")
}

function Invoke-Audit11PasswordHygiene {
    Write-Section "Hygiene des mots de passe des comptes" Magenta
    Write-Info "Comptes actifs avec : chiffrement reversible, mot de passe non requis, mot de passe" `
               "jamais defini/change (pwdLastSet vide), ou DES uniquement."

    $checks = @(
        @{ Nom = 'Chiffrement reversible (mot de passe recuperable en clair)'; Filtre = '(userAccountControl:1.2.840.113556.1.4.803:=128)'; Gravite = 'CRITIQUE' }
        @{ Nom = 'Mot de passe non requis (PASSWD_NOTREQD)';                  Filtre = '(userAccountControl:1.2.840.113556.1.4.803:=32)';  Gravite = 'ALERTE' }
        @{ Nom = 'DES uniquement (USE_DES_KEY_ONLY)';                          Filtre = '(userAccountControl:1.2.840.113556.1.4.803:=2097152)'; Gravite = 'ALERTE' }
        @{ Nom = 'Mot de passe jamais defini (pwdLastSet = 0)';                Filtre = '(pwdLastSet=0)';                                   Gravite = 'INFO' }
    )
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($c in $checks) {
        $found = @(Get-ADUser -LDAPFilter ("(&{0}(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(userAccountControl:1.2.840.113556.1.4.803:=2048)))" -f $c.Filtre) -Properties PasswordLastSet)
        Write-Host ("  {0,-62} : {1}" -f $c.Nom, $found.Count) -ForegroundColor $(if ($found.Count -eq 0) { 'Green' } elseif ($c.Gravite -eq 'CRITIQUE') { 'Red' } else { 'Yellow' })
        foreach ($u in $found) { $rows.Add([PSCustomObject]@{ Controle = $c.Nom; Gravite = $c.Gravite; SamAccountName = $u.SamAccountName; MdpChangeLe = $u.PasswordLastSet }) }
    }
    if ($rows.Count -eq 0) { Write-Log "Aucun compte actif concerne." -Level OK; return }
    [void](Export-Report -Rows $rows -Name "Rapport_HygieneMotsDePasse" -Comment "Remediations : theme 3 > 3 (PASSWD_NOTREQD), 3 > 9 (chiffrement reversible), 4 > 6 (DES).")
}

function Invoke-Remediate11DisableReversibleEncryption {
    Write-Section "Retirer le chiffrement reversible des mots de passe" Red
    Write-Info "Retire le flag 'Enregistrer le mot de passe en utilisant un chiffrement reversible'." `
               "La version reversible deja stockee n'est effacee qu'au PROCHAIN changement de mot de" `
               "passe : forcez ce changement (case 'doit changer' ou reinitialisation) ensuite." `
               "Risque : casse l'authentification CHAP/Digest (IAS/NPS ancien, IIS Digest) si utilisee."

    $accounts = @(Get-ADUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=128)" -Properties Enabled, PasswordLastSet)
    if ($accounts.Count -eq 0) { Write-Log "Aucun compte avec chiffrement reversible." -Level OK; return }

    $selected = @(Select-FromList -Items $accounts -Prompt "Comptes a corriger" -Display { param($a) "{0} (actif={1})" -f $a.SamAccountName, $a.Enabled })
    if ($selected.Count -eq 0) { return }
    $forceChange = Read-YesNo -Prompt "Exiger aussi le changement du mot de passe a la prochaine ouverture de session (efface la version reversible) ?" -Default $true
    if (-not (Confirm-Action ("Retirer le chiffrement reversible sur {0} compte(s)" -f $selected.Count) -Strong)) { return }

    foreach ($acc in $selected) {
        Invoke-Guarded -Description ("Retrait du chiffrement reversible sur {0}" -f $acc.SamAccountName) -Action {
            Set-ADAccountControl -Identity $acc.DistinguishedName -AllowReversiblePasswordEncryption $false
            if ($forceChange) { Set-ADUser -Identity $acc.DistinguishedName -ChangePasswordAtLogon $true }
        }
    }
}

function Get-PasswordExcerpt {
    <#
        Heuristique : mot-cle de mot de passe SUIVI d'un separateur (":" ou "=") puis d'une valeur,
        pour limiter les faux positifs ("Mot de passe n'expire jamais" n'est pas signale).
        Retourne un extrait MASQUE (le secret n'est jamais restitue) ou $null.
    #>
    param([AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $m = [regex]::Match($Text, '(?i)\b(pass(word|wd|e)?|pwd|mdp|mot\s*de\s*passe|motdepasse|kennwort|contrase.a)\s*[:=]\s*(?=\S)')
    if (-not $m.Success) { return $null }
    $start = [Math]::Max(0, $m.Index - 15)
    return ($Text.Substring($start, $m.Index + $m.Length - $start) + '***')
}

function Get-PasswordInDescriptionCandidates {
    # Comptes (utilisateurs/ordinateurs) dont description ou info (Notes) semble contenir un mot de passe.
    $objs = @(Get-ADObject -LDAPFilter '(&(objectClass=user)(|(description=*)(info=*)))' -Properties description, info, sAMAccountName, userAccountControl -ErrorAction Stop)
    return @(foreach ($o in $objs) {
        foreach ($attr in 'description', 'info') {
            $excerpt = Get-PasswordExcerpt -Text ((@($o.$attr) | Where-Object { $_ }) -join ' ')
            if (-not $excerpt) { continue }
            [PSCustomObject]@{
                Compte   = $o.sAMAccountName
                Classe   = $o.ObjectClass
                Actif    = -not ([int]$o.userAccountControl -band 2)
                Attribut = $attr
                Extrait  = $excerpt
                DN       = $o.DistinguishedName
            }
        }
    })
}

function Invoke-Audit11PasswordInDescription {
    Write-Section "Mots de passe potentiellement stockes dans la description / les notes des comptes" Magenta
    Write-Info "Les attributs description et info sont LISIBLES PAR TOUT UTILISATEUR du domaine. Recherche" `
               "heuristique ('mdp:', 'password=', 'pwd :'...) : a confirmer au cas par cas. Le secret" `
               "eventuel n'est jamais affiche ni exporte (extrait masque)."
    try { $rows = @(Get-PasswordInDescriptionCandidates) } catch {
        Write-Log ("Recherche impossible : {0}" -f $_.Exception.Message) -Level ERROR
        return
    }
    if ($rows.Count -eq 0) { Write-Log "Aucun motif de mot de passe detecte dans les descriptions/notes." -Level OK; return }
    Write-ListPreview -Items $rows -Color Red -Format { param($r) "{0} ({1}, actif={2}) : {3}" -f $r.Compte, $r.Attribut, $r.Actif, $r.Extrait }
    [void](Export-Report -Rows $rows -Name "Rapport_MotsDePasseDescription" -Comment "Effacer l'attribut ET changer le mot de passe concerne (il doit etre considere comme divulgue).")
}

# ============================================================
#  THEME 4 - KERBEROS ET DELEGATIONS
# ============================================================

function Get-DelegationInventory {
    <#
        Inventaire des delegations Kerberos, en distinguant les controleurs de domaine
        (delegation non contrainte NORMALE et necessaire sur un DC : ne doit pas etre
        comptee comme un risque - source classique de faux positifs).
    #>
    $props = @('sAMAccountName', 'objectClass', 'userAccountControl', 'primaryGroupID', 'msDS-AllowedToDelegateTo', 'msDS-AllowedToActOnBehalfOfOtherIdentity', 'servicePrincipalName')
    $dcSids = [System.Collections.Generic.HashSet[string]]::new()
    $dcList = @(Get-DomainControllersList)
    $dcNames = @($dcList | ForEach-Object { $_.Name })
    foreach ($dc in $dcList) { try { [void]$dcSids.Add((Get-ADComputer -Identity $dc.ComputerObjectDN -ErrorAction Stop).SID.Value) } catch { } }

    $rows = [System.Collections.Generic.List[object]]::new()
    $isDcObj = { param($o) ($o.primaryGroupID -in 516, 521) -or ($o.userAccountControl -band 8192) }

    foreach ($o in @(Get-ADObject -LDAPFilter "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(sAMAccountName=krbtgt*)))" -Properties ($props + 'objectSid'))) {
        $dc = & $isDcObj $o
        $rows.Add([PSCustomObject]@{
            Compte   = $o.sAMAccountName; Classe = $o.objectClass
            Type     = 'NonContrainte'
            Actif    = -not ($o.userAccountControl -band 2)
            Cibles   = '(tout service)'
            Risque   = if ($dc) { 'Normal (controleur de domaine)' } else { 'CRITIQUE : capture des TGT de tout compte qui s''y authentifie' }
            EstDC    = [bool]$dc
            DN       = $o.DistinguishedName
        })
    }
    foreach ($o in @(Get-ADObject -LDAPFilter "(msDS-AllowedToDelegateTo=*)" -Properties $props)) {
        $pt = [bool]($o.userAccountControl -band 16777216)
        $targets = @($o.'msDS-AllowedToDelegateTo')
        $toDc = @($targets | Where-Object { $t = $_; @($dcNames | Where-Object { $t -match ("/{0}(\.|$|:)" -f [regex]::Escape($_)) }).Count -gt 0 })
        $risk = if ($toDc.Count -gt 0) { 'CRITIQUE : delegation vers un service d''un DC' }
                elseif ($pt) { 'ELEVE : transition de protocole (usurpation sans mot de passe de l''utilisateur)' }
                else { 'Modere : a justifier' }
        $rows.Add([PSCustomObject]@{
            Compte = $o.sAMAccountName; Classe = $o.objectClass
            Type   = if ($pt) { 'Contrainte+TransitionProtocole' } else { 'Contrainte (Kerberos uniquement)' }
            Actif  = -not ($o.userAccountControl -band 2)
            Cibles = $targets -join ', '
            Risque = $risk; EstDC = [bool](& $isDcObj $o); DN = $o.DistinguishedName
        })
    }
    foreach ($o in @(Get-ADObject -LDAPFilter "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" -Properties ($props + 'objectSid'))) {
        $principals = @()
        try { $principals = @($o.'msDS-AllowedToActOnBehalfOfOtherIdentity'.Access | ForEach-Object { $_.IdentityReference.Value }) } catch { }
        $onDc = (& $isDcObj $o) -or ($o.objectSid -and $dcSids.Contains($o.objectSid.Value))
        $rows.Add([PSCustomObject]@{
            Compte = $o.sAMAccountName; Classe = $o.objectClass
            Type   = 'RBCD (basee sur la ressource)'
            Actif  = -not ($o.userAccountControl -band 2)
            Cibles = "Autorises a deleguer vers ce compte : " + ($principals -join ', ')
            Risque = if ($onDc -or $o.sAMAccountName -like 'krbtgt*') { 'CRITIQUE : RBCD sur un DC/krbtgt (compromission du domaine)' } else { 'Modere : verifier les principaux autorises' }
            EstDC  = [bool]$onDc; DN = $o.DistinguishedName
        })
    }
    return @($rows)
}

function Invoke-RiskyReportDelegations {
    Write-Section "Rapport des delegations Kerberos (non contraintes / contraintes / RBCD)" Magenta
    Write-Info "RAPPORT uniquement : la suppression d'une delegation doit etre validee au cas par cas" `
               "(elle peut etre necessaire au fonctionnement d'une application). Les DC, qui disposent" `
               "NORMALEMENT de la delegation non contrainte, sont listes a part (pas de faux positif)."

    $rows = @(Get-DelegationInventory)
    if ($rows.Count -eq 0) { Write-Log "Aucune delegation Kerberos configuree." -Level OK; return }

    foreach ($type in @('NonContrainte', 'Contrainte+TransitionProtocole', 'Contrainte (Kerberos uniquement)', 'RBCD (basee sur la ressource)')) {
        $sub = @($rows | Where-Object { $_.Type -eq $type })
        if ($sub.Count -eq 0) { continue }
        $nonDc = @($sub | Where-Object { -not $_.EstDC -or $_.Risque -like 'CRITIQUE*' })
        Write-Host ("Delegation {0} : {1} (dont {2} hors DC / a risque)" -f $type, $sub.Count, $nonDc.Count) -ForegroundColor Yellow
        Write-ListPreview -Items $sub -Format { param($r) "{0} ({1}, actif={2}) - {3}" -f $r.Compte, $r.Classe, $r.Actif, $r.Risque } -Max 15
    }
    $critical = @($rows | Where-Object { $_.Risque -like 'CRITIQUE*' })
    if ($critical.Count -gt 0) { Write-Log ("{0} delegation(s) CRITIQUE(S) a traiter en priorite (theme 4 > 12 pour la non contrainte)." -f $critical.Count) -Level WARN }
    [void](Export-Report -Rows $rows -Name "Rapport_Delegations")
}

function Invoke-Remediate5RemoveUnconstrainedDelegation {
    Write-Section "Retirer la delegation NON contrainte (hors controleurs de domaine)" Red
    Write-Info "Desactive 'Approuver ce compte pour la delegation a tous les services' sur les comptes" `
               "choisis. Risque : l'application qui en depend (souvent un ancien serveur web/IIS ou" `
               "middleware) ne pourra plus deleguer : la remplacer par une delegation CONTRAINTE." `
               "Les DC ne sont jamais proposes."

    $rows = @(Get-DelegationInventory | Where-Object { $_.Type -eq 'NonContrainte' -and -not $_.EstDC })
    if ($rows.Count -eq 0) { Write-Log "Aucun compte hors DC avec delegation non contrainte." -Level OK; return }

    $selected = @(Select-FromList -Items $rows -Prompt "Comptes a corriger" -Display { param($r) "{0} ({1}, actif={2})" -f $r.Compte, $r.Classe, $r.Actif })
    if ($selected.Count -eq 0) { return }
    if (-not (Confirm-Action ("Retirer la delegation non contrainte sur {0} compte(s)" -f $selected.Count) -Strong)) { return }

    foreach ($r in $selected) {
        Invoke-Guarded -Description ("Retrait de la delegation non contrainte sur {0}" -f $r.Compte) -Action {
            Set-ADAccountControl -Identity $r.DN -TrustedForDelegation $false
        }
    }
}

function Invoke-Audit5AsRepRoasting {
    Write-Section "Audit AS-REP Roasting (comptes sans pre-authentification Kerberos)" Magenta
    Write-Info "Un compte avec 'Ne pas exiger de pre-authentification Kerberos' permet a n'importe qui" `
               "(meme sans compte) de recuperer une reponse chiffree avec son mot de passe et de" `
               "l'attaquer hors ligne."

    $privilegedSids = Get-ExpandedGroupMemberSids -GroupNames $Script:PrivilegedGroups
    $accounts = @(Get-ADUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" -Properties Enabled, PasswordLastSet)
    if ($accounts.Count -eq 0) { Write-Log "Aucun compte avec pre-authentification Kerberos desactivee." -Level OK; return }

    $rows = @($accounts | ForEach-Object {
        [PSCustomObject]@{ SamAccountName = $_.SamAccountName; Actif = $_.Enabled; Privilegie = $privilegedSids.Contains($_.SID.Value); MdpChangeLe = $_.PasswordLastSet }
    })
    Write-Host ("{0} compte(s) sans pre-authentification Kerberos (dont {1} actif(s)) :" -f $rows.Count, @($rows | Where-Object Actif).Count) -ForegroundColor Red
    Write-ListPreview -Items $rows -Color Red -Format { param($r) "{0} (actif={1}{2})" -f $r.SamAccountName, $r.Actif, $(if ($r.Privilegie) { ', PRIVILEGIE' } else { '' }) }
    [void](Export-Report -Rows $rows -Name "Rapport_AsRepRoasting")
}

function Invoke-Remediate5FixAsRepRoasting {
    Write-Section "Corriger l'exposition AS-REP Roasting" Red
    Write-Info "Reactive la pre-authentification Kerberos sur les comptes selectionnes." `
               "Risque : si ce parametre etait positionne intentionnellement pour un usage specifique" `
               "(client Kerberos tres ancien / non-Windows, rare), cet usage cessera de fonctionner."

    $accounts = @(Get-ADUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" -Properties Enabled)
    if ($accounts.Count -eq 0) { Write-Log "Aucun compte concerne." -Level OK; return }

    $selected = @(Select-FromList -Items $accounts -Prompt "Comptes a corriger" -Display { param($a) "{0} (actif={1})" -f $a.SamAccountName, $a.Enabled })
    if ($selected.Count -eq 0) { return }

    if (-not (Confirm-Action ("Reactiver la pre-authentification Kerberos sur {0} compte(s)" -f $selected.Count) -Strong)) { return }

    foreach ($acc in $selected) {
        Invoke-Guarded -Description ("Reactivation pre-authentification sur {0}" -f $acc.SamAccountName) -Action {
            Set-ADAccountControl -Identity $acc.DistinguishedName -DoesNotRequirePreAuth $false
        }
    }
}

function Invoke-Audit5TrustsEncryption {
    Write-Section "Audit des relations d'approbation (trusts) : filtrage SID, delegation TGT, chiffrement" Magenta
    Write-Info "Evaluation a partir des bits trustAttributes :" `
               "- intra-foret : pas de filtrage SID par conception (frontiere de securite = la foret) ;" `
               "- approbation de foret : risque si 'TREAT_AS_EXTERNAL' (SID History accepte) ;" `
               "- approbation externe : risque si la quarantaine (filtrage SID) est desactivee ;" `
               "- seules les approbations sortantes/bidirectionnelles exposent CE domaine."

    try {
        $trusts = @(Get-ADTrust -Filter * -Properties TrustAttributes, 'msDS-SupportedEncryptionTypes', whenChanged -ErrorAction Stop)
    } catch {
        Write-Log ("Impossible de lire les relations d'approbation : {0}" -f $_.Exception.Message) -Level ERROR
        return
    }
    if ($trusts.Count -eq 0) { Write-Log "Aucune relation d'approbation configuree sur ce domaine." -Level OK; return }

    $rows = @($trusts | ForEach-Object {
        $attr = [int]$_.TrustAttributes
        $dir = [string]$_.Direction
        $exposes = $dir -in @('Outbound', 'BiDirectional')
        $sidFiltering =
            if ($attr -band 0x20) { 'N/A (intra-foret)' }
            elseif (-not $exposes) { 'N/A (approbation entrante uniquement)' }
            elseif ($attr -band 0x8) { if ($attr -band 0x40) { 'RELACHE (SID History accepte - TREAT_AS_EXTERNAL)' } else { 'Actif (foret)' } }
            elseif ($attr -band 0x4) { 'Actif (quarantaine)' }
            else { 'DESACTIVE' }
        $enc = $_.'msDS-SupportedEncryptionTypes'
        $encLabel = if (-not $enc) { 'Non defini : RC4 possible selon les DC (cocher AES sur l''approbation)' } else { Get-SupportedEncryptionTypesLabel -Value $enc }
        $issues = @()
        if ($sidFiltering -like 'RELACHE*' -or $sidFiltering -eq 'DESACTIVE') { $issues += 'filtrage SID' }
        if ($attr -band 0x800) { $issues += 'delegation TGT autorisee' }
        if (-not (Test-HasAesEncryptionType $enc) -and -not ($attr -band 0x20)) { $issues += 'pas d''AES' }
        [PSCustomObject]@{
            Domaine             = $_.Name
            Direction           = $dir
            Type                = $(if ($attr -band 0x20) { 'Intra-foret' } elseif ($attr -band 0x8) { 'Foret' } else { "Externe ($($_.TrustType))" })
            FiltrageSID         = $sidFiltering
            DelegationTGT       = [bool]($attr -band 0x800)
            AuthSelective       = [bool]($attr -band 0x10)
            Chiffrement         = $encLabel
            TrustAttributes     = ('0x{0:X}' -f $attr)
            DerniereModification = $_.whenChanged
            PointsAttention     = $issues -join ', '
        }
    })

    foreach ($r in $rows) {
        $color = if ($r.PointsAttention -match 'filtrage SID|TGT') { 'Red' } elseif ($r.PointsAttention) { 'Yellow' } else { 'Green' }
        Write-Host ("  - {0} [{1}, {2}] filtrage SID : {3} ; chiffrement : {4}{5}" -f $r.Domaine, $r.Type, $r.Direction, $r.FiltrageSID, $r.Chiffrement, $(if ($r.PointsAttention) { " ; A TRAITER : $($r.PointsAttention)" } else { '' })) -ForegroundColor $color
    }
    [void](Export-Report -Rows $rows -Name "Rapport_Trusts" -Comment "Correction : netdom trust <domaine> /domain:<autre> /quarantine:yes (externe) ou /enablesidhistory:no (foret), apres validation des migrations en cours.")
}

function Invoke-Audit5KrbtgtStatus {
    Write-Section "Etat du compte krbtgt (age du mot de passe, RODC) et de la replication" Magenta
    Write-Info "Un mot de passe krbtgt ancien prolonge la validite de tout Golden Ticket forge apres une" `
               "compromission. Rotation recommandee : au moins tous les 180 jours, et toujours apres un" `
               "incident ou le depart d'un administrateur du domaine."

    $rows = @(Get-ADUser -LDAPFilter "(sAMAccountName=krbtgt*)" -Properties PasswordLastSet, 'msDS-KrbTgtLinkBl', Enabled | ForEach-Object {
        $age = if ($_.PasswordLastSet) { [int]((Get-Date) - $_.PasswordLastSet).TotalDays } else { $null }
        [PSCustomObject]@{
            Compte       = $_.SamAccountName
            Type         = if ($_.SamAccountName -eq 'krbtgt') { 'Domaine' }
                           elseif ($_.SamAccountName -ieq 'krbtgt_AzureAD') { 'Entra Kerberos (rotation : Set-AzureADKerberosServer -RotateServerKey)' }
                           elseif (@($_.'msDS-KrbTgtLinkBl').Count -gt 0) { 'RODC : ' + ((@($_.'msDS-KrbTgtLinkBl') | ForEach-Object { $_ -replace '^CN=([^,]+).*', '$1' }) -join ',') }
                           else { 'krbtgt de RODC orphelin (RODC supprime ?)' }
            MdpChangeLe  = $_.PasswordLastSet
            AgeJours     = $age
            Evaluation   = if ($null -eq $age) { 'Inconnu' } elseif ($age -gt 365) { 'CRITIQUE (> 1 an)' } elseif ($age -gt 180) { 'ALERTE (> 180 j)' } else { 'OK' }
        }
    })
    foreach ($r in $rows) {
        $color = switch -Wildcard ($r.Evaluation) { 'CRITIQUE*' { 'Red' } 'ALERTE*' { 'Yellow' } 'OK' { 'Green' } default { 'Gray' } }
        Write-Host ("  - {0} ({1}) : mot de passe change le {2} ({3} j) -> {4}" -f $r.Compte, $r.Type, $r.MdpChangeLe, $r.AgeJours, $r.Evaluation) -ForegroundColor $color
    }

    $health = Test-ADReplicationHealth
    if ($health.Healthy) { Write-Log "Replication AD saine (aucune erreur sur les partenaires du domaine) : prerequis a une rotation krbtgt satisfait." -Level OK }
    else {
        Write-Log "Replication AD NON saine ou non verifiable : ne PAS lancer de rotation krbtgt avant correction." -Level WARN
        $health.Details | ForEach-Object { Write-Host ("    {0}" -f $_) -ForegroundColor Yellow }
    }
    [void](Export-Report -Rows $rows -Name "Rapport_Krbtgt")
}

function Invoke-RiskyResetKrbtgt {
    Write-Section "Reinitialisation du mot de passe KRBTGT" Red
    Write-Info "Rappel PingCastle : mot de passe krbtgt jamais/peu change = risque Golden Ticket." `
               "PROCEDURE : reinitialiser 2 FOIS, avec un ecart >= duree de vie max des tickets Kerberos" `
               "(10 h par defaut) + delai de convergence de la replication entre tous les DC." `
               "Un 2e reset trop rapproche invalide TOUS les tickets en cours (echecs d'authentification" `
               "massifs) : le script le bloque sauf saisie explicite (scenario de compromission averee)."

    $dom = Get-CachedADDomain
    $pdc = $dom.PDCEmulator
    try {
        $krbtgt = Get-ADUser -Identity "krbtgt" -Properties PasswordLastSet -Server $pdc -ErrorAction Stop
    } catch {
        Write-Log "Impossible de lire le compte krbtgt : $($_.Exception.Message)" -Level ERROR
        return
    }
    $ageHours = if ($krbtgt.PasswordLastSet) { ((Get-Date) - $krbtgt.PasswordLastSet).TotalHours } else { [double]::MaxValue }
    Write-Host ("Dernier changement du mot de passe krbtgt : {0} (il y a {1:N1} h / {2:N0} j)" -f $krbtgt.PasswordLastSet, $ageHours, ($ageHours / 24)) -ForegroundColor Yellow

    Write-Host "Verification de la replication AD..." -ForegroundColor DarkGray
    $health = Test-ADReplicationHealth
    if (-not $health.Healthy) {
        Write-Log "Replication AD NON saine : un reset maintenant risque de desynchroniser les DC (echecs Kerberos)." -Level ERROR
        $health.Details | ForEach-Object { Write-Host ("    {0}" -f $_) -ForegroundColor Yellow }
        if ((Read-Host "Tapez FORCER pour continuer malgre tout (deconseille), ou Entree pour annuler") -cne 'FORCER') { return }
        Write-Log "Reset krbtgt force malgre une replication non saine." -Level WARN
    } else {
        Write-Log "Replication AD saine." -Level OK
    }

    if ($ageHours -lt 10) {
        Write-Host ""
        Write-Host "!!! Le mot de passe krbtgt a ete change il y a MOINS DE 10 HEURES !!!" -ForegroundColor White -BackgroundColor DarkRed
        Write-Host "Un nouveau reset maintenant invalidera tous les tickets Kerberos en circulation." -ForegroundColor Red
        Write-Host "A reserver a une compromission averee (Golden Ticket) avec plan de redemarrage des services." -ForegroundColor Red
        if ((Read-Host "Tapez FORCER pour continuer, ou Entree pour annuler") -cne 'FORCER') { return }
        Write-Log "Double reset krbtgt rapproche force par l'operateur (scenario de compromission)." -Level WARN
    } elseif ($ageHours -lt 24) {
        Write-Log "Dernier reset il y a moins de 24 h : assurez-vous que la replication a converge sur TOUS les DC (repadmin /showobjmeta * \"CN=krbtgt,...\")." -Level WARN
    }

    if (-not (Confirm-Action "Reinitialiser le mot de passe KRBTGT MAINTENANT (1 des 2 executions requises)" -Strong)) { return }

    Invoke-Guarded -Description ("Reset du mot de passe krbtgt (sur le PDC {0})" -f $pdc) -Action {
        $newPwd = ConvertTo-SecureString (New-RandomComplexPassword -Length 64) -AsPlainText -Force
        Set-ADAccountPassword -Identity "krbtgt" -Reset -NewPassword $newPwd -Server $pdc -Confirm:$false
        $trackFile = Join-Path $Script:LogDir "krbtgt_reset_tracking.log"
        Add-Content -LiteralPath $trackFile -Value ("{0} - Reset krbtgt effectue sur {1} par {2}." -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $pdc, (Get-CurrentUserName))
    }
    Write-OutcomeLog "Reset effectue. Planifiez le 2e reset au plus tot 10 h (idealement 24 h) plus tard, apres verification de la replication (theme 4 > 9)." -Level WARN

    $rodc = @(Get-ADUser -LDAPFilter "(sAMAccountName=krbtgt_*)" -ErrorAction SilentlyContinue)
    if ($rodc.Count -gt 0) {
        Write-Log ("{0} compte(s) krbtgt de RODC detecte(s) : ils se reinitialisent separement (Set-ADAccountPassword krbtgt_<n>), en particulier si un RODC a ete compromis." -f $rodc.Count) -Level INFO
    }

    Write-Host ""
    if (Read-YesNo -Prompt "Configurer maintenant la rotation KRBTGT automatique et planifiee ?") {
        Invoke-RiskySetupKrbtgtScheduledRotation
    }
}

function Get-KrbtgtRotationScriptContent {
    # Script autonome deploye sur le DC cible et execute par la tache planifiee (SYSTEM).
    # Ne depend d'aucune variable/fonction du script menu (execution differee et decouplee).
    param([int]$MinHoursSinceLastReset = 24)
    $header = "`$MinHoursSinceLastReset = $MinHoursSinceLastReset`r`n"
    return $header + @'
# Reset-KrbtgtScheduled.ps1
# Deploye et execute automatiquement par la tache planifiee "SEC - Rotation KRBTGT" (compte SYSTEM
# du controleur de domaine : seul SYSTEM local a un DC dispose du droit de reinitialiser krbtgt sans
# delegation - une delegation sur krbtgt serait de toute facon effacee par AdminSDHolder/SDProp).
# Ne PAS executer manuellement sans avoir verifie l'etat de replication AD au prealable.

$logFile = "C:\SEC-Scripts\Krbtgt-Rotation.log"

function Write-RotLog {
    param([string]$Message, [string]$Type = "Information")
    $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Add-Content -Path $logFile -Value $line -Encoding UTF8
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("SEC-KrbtgtRotation")) {
            New-EventLog -LogName Application -Source "SEC-KrbtgtRotation" -ErrorAction SilentlyContinue
        }
        $id = if ($Type -eq "Error") { 1001 } else { 1000 }
        Write-EventLog -LogName Application -Source "SEC-KrbtgtRotation" -EventId $id -EntryType $Type -Message $Message -ErrorAction SilentlyContinue
    } catch { }
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $domain = Get-ADDomain -ErrorAction Stop
} catch {
    Write-RotLog ("Module AD / domaine indisponible : {0}. Rotation annulee." -f $_.Exception.Message) "Error"
    exit 1
}
Write-RotLog "Debut de verification avant rotation KRBTGT planifiee."

# --- Garde-fou 1 : replication AD saine (cmdlets AD, independantes de la langue de l'OS) ---
try {
    $bad = @(Get-ADReplicationPartnerMetadata -Target $domain.DNSRoot -Scope Domain -ErrorAction Stop | Where-Object { $_.LastReplicationResult -ne 0 })
    $fail = @(Get-ADReplicationFailure -Target $domain.DNSRoot -Scope Domain -ErrorAction Stop | Where-Object { $_.FailureCount -gt 0 })
} catch {
    Write-RotLog ("Etat de replication non verifiable ({0}). Rotation ANNULEE par securite." -f $_.Exception.Message) "Error"
    exit 1
}
if ($bad.Count -gt 0 -or $fail.Count -gt 0) {
    $detail = (@($bad | ForEach-Object { "{0}<-{1} erreur {2}" -f $_.Server, $_.Partner, $_.LastReplicationResult }) + @($fail | ForEach-Object { "{0}<-{1} {2} echec(s)" -f $_.Server, $_.Partner, $_.FailureCount })) -join ' ; '
    Write-RotLog ("Replication AD en erreur ({0}). Rotation KRBTGT ANNULEE par securite." -f $detail) "Error"
    exit 1
}

# --- Garde-fou 2 : jamais deux resets rapproches (invaliderait tous les tickets en cours) ---
$krbtgt = Get-ADUser -Identity krbtgt -Properties PasswordLastSet -Server $env:COMPUTERNAME
if ($krbtgt.PasswordLastSet -and ((Get-Date) - $krbtgt.PasswordLastSet).TotalHours -lt $MinHoursSinceLastReset) {
    Write-RotLog ("Dernier reset le {0} (< {1} h). Rotation reportee." -f $krbtgt.PasswordLastSet, $MinHoursSinceLastReset) "Warning"
    exit 0
}

Write-RotLog "Replication saine. Poursuite de la rotation planifiee du mot de passe KRBTGT."

# --- Mot de passe aleatoire (jamais stocke ; AD le remplace de toute facon par une valeur aleatoire) ---
$sets = @('ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!@#$%^&*()-_=+')
$all = -join $sets
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
$b = New-Object byte[] 1
$chars = foreach ($i in 1..64) {
    $set = if ($i -le 4) { $sets[$i - 1] } else { $all }
    $limit = 256 - (256 % $set.Length)
    do { $rng.GetBytes($b) } while ($b[0] -ge $limit)
    $set[$b[0] % $set.Length]
}
$newPwd = ConvertTo-SecureString (-join $chars) -AsPlainText -Force
Remove-Variable chars

try {
    # Reset sur le DC local (SYSTEM local dispose du controle total via AdminSDHolder) ; la
    # replication propage ensuite la modification a tous les DC du domaine.
    Set-ADAccountPassword -Identity "krbtgt" -Reset -NewPassword $newPwd -Server $env:COMPUTERNAME -Confirm:$false -ErrorAction Stop
    Write-RotLog "Rotation planifiee du mot de passe KRBTGT effectuee avec succes."
} catch {
    Write-RotLog ("ECHEC de la rotation planifiee KRBTGT : {0}" -f $_.Exception.Message) "Error"
    exit 1
}
'@
}

function Protect-RemoteScriptFolderScript {
    # Scriptblock (execute sur le DC) qui cree C:\SEC-Scripts et restreint son ACL a SYSTEM et
    # Administrateurs : un script execute en SYSTEM ne doit pas etre modifiable par d'autres.
    return {
        param($dir, $fileName, $content)
        if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
        & icacls.exe $dir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "icacls a echoue sur $dir (code $LASTEXITCODE)." }
        Set-Content -Path (Join-Path $dir $fileName) -Value $content -Encoding UTF8 -ErrorAction Stop
    }
}

function Invoke-RiskySetupKrbtgtScheduledRotation {
    Write-Section "Configuration de la rotation KRBTGT automatique et planifiee" Red
    Write-Info "Principe : un reset unique repete a intervalle regulier, largement superieur a la duree" `
               "de vie des tickets + convergence de la replication, maintient en continu la protection" `
               "du 'double reset' manuel. Recommandation usuelle : tous les 180 jours au plus." `
               "" `
               "Architecture : tache planifiee sous le compte SYSTEM d'un DC inscriptible. (Une" `
               "delegation 'Reset Password' sur krbtgt a un gMSA ne tient pas : krbtgt est protege par" `
               "AdminSDHolder, qui reecrit son ACL toutes les 60 min.) Le dossier du script est" `
               "restreint a SYSTEM/Administrateurs ; chaque execution verifie la replication avant d'agir."

    $days = Read-IntValue -Prompt "Intervalle de rotation en jours" -Default 180 -Min 1 -Max 3650
    if ($days -lt 30) {
        Write-Host "Intervalle inferieur a 30 jours : deconseille hors contexte de compromission averee." -ForegroundColor Yellow
        if (-not (Read-YesNo -Prompt "Confirmez-vous cet intervalle court ?")) { return }
    }

    $dcs = @(Get-DomainControllersList | Where-Object { -not $_.IsReadOnly })
    if ($dcs.Count -eq 0) { return }
    $pdc = (Get-CachedADDomain).PDCEmulator
    Write-Host "Controleurs de domaine inscriptibles :"
    for ($i = 0; $i -lt $dcs.Count; $i++) { Write-Host ("  [{0}] {1}{2}" -f $i, $dcs[$i].HostName, $(if ($dcs[$i].HostName -eq $pdc) { ' (PDC)' } else { '' })) }
    $defaultIdx = [Math]::Max(0, [array]::IndexOf(@($dcs | ForEach-Object { $_.HostName }), $pdc))
    $targetDC = $dcs[(Read-IntValue -Prompt "DC qui hebergera la tache planifiee" -Default $defaultIdx -Min 0 -Max ($dcs.Count - 1))].HostName

    if (-not (Confirm-Action ("Deployer le script et creer la tache planifiee (SYSTEM, tous les {0} jours) sur {1}" -f $days, $targetDC) -Strong)) { return }

    $wr = Test-WinRmConnectivity -ComputerNames @($targetDC)
    if ($wr.Reachable.Count -eq 0) { Write-Log "DC cible injoignable en WinRM : configuration annulee." -Level ERROR; return }

    Invoke-Guarded -Description ("Deploiement du script de rotation (dossier protege) sur {0}" -f $targetDC) -Action {
        Invoke-OnDC -ComputerName $targetDC -ScriptBlock (Protect-RemoteScriptFolderScript) -ArgumentList $Script:RemoteScriptDir, "Reset-KrbtgtScheduled.ps1", (Get-KrbtgtRotationScriptContent) -ErrorAction Stop
    }

    Invoke-Guarded -Description ("Creation de la tache planifiee (tous les {0} jours) sur {1}" -f $days, $targetDC) -Action {
        Invoke-OnDC -ComputerName $targetDC -ScriptBlock {
            param($intervalDays)
            $taskName = "SEC - Rotation KRBTGT"
            $act = New-ScheduledTaskAction -Execute "powershell.exe" -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "C:\SEC-Scripts\Reset-KrbtgtScheduled.ps1"'
            $trg = New-ScheduledTaskTrigger -Daily -DaysInterval $intervalDays -At "02:00"
            $prn = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            $set = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd -ExecutionTimeLimit (New-TimeSpan -Hours 1)
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            Register-ScheduledTask -TaskName $taskName -Action $act -Trigger $trg -Principal $prn -Settings $set -Description "Rotation automatique du mot de passe KRBTGT - deployee par le script de remediation AD" -ErrorAction Stop | Out-Null
        } -ArgumentList $days -ErrorAction Stop
    }

    Write-OutcomeLog ("Tache 'SEC - Rotation KRBTGT' creee sur {0} : tous les {1} jours a 02:00 (SYSTEM). Journal : {2}\Krbtgt-Rotation.log + journal Application (source SEC-KrbtgtRotation, ID 1001 = echec : a superviser)." -f $targetDC, $days, $Script:RemoteScriptDir)
}

function Invoke-RiskyDisableDesForceAes {
    Write-Section "Desactivation DES / forcage AES sur les comptes concernes" Red
    Write-Info "Risque : casse l'authentification Kerberos de comptes de service/applications qui" `
               "dependent explicitement de DES ou qui ne supportent pas AES. krbtgt n'est jamais traite."

    $desAccounts = @(Get-ADUser -LDAPFilter "(&(userAccountControl:1.2.840.113556.1.4.803:=2097152)(!(sAMAccountName=krbtgt*)))" -Properties PasswordLastSet)
    $noAesAccounts = @(Get-ADUser -LDAPFilter "(&(servicePrincipalName=*)(!(sAMAccountName=krbtgt*))(!(userAccountControl:1.2.840.113556.1.4.803:=2048)))" -Properties 'msDS-SupportedEncryptionTypes', PasswordLastSet |
                      Where-Object { -not (Test-HasAesEncryptionType $_.'msDS-SupportedEncryptionTypes') })

    Write-Host ("Comptes avec 'DES uniquement' : {0}" -f $desAccounts.Count) -ForegroundColor Yellow
    Write-ListPreview -Items $desAccounts -Format { param($a) $a.SamAccountName }
    Write-Host ("Comptes de service (SPN) sans type de chiffrement AES declare : {0}" -f $noAesAccounts.Count) -ForegroundColor Yellow
    Write-ListPreview -Items $noAesAccounts -Format { param($a) "{0} ({1})" -f $a.SamAccountName, (Get-SupportedEncryptionTypesLabel -Value $a.'msDS-SupportedEncryptionTypes') }

    if ($desAccounts.Count -gt 0) {
        $selDes = @(Select-FromList -Items $desAccounts -Prompt "Comptes sur lesquels retirer 'DES uniquement'")
        if ($selDes.Count -gt 0 -and (Confirm-Action ("Retirer 'DES uniquement' sur {0} compte(s)" -f $selDes.Count) -Strong)) {
            foreach ($acc in $selDes) {
                Invoke-Guarded -Description ("Desactivation DES sur {0}" -f $acc.SamAccountName) -Action {
                    Set-ADAccountControl -Identity $acc.DistinguishedName -UseDESKeyOnly $false
                }
            }
        }
    }
    if ($noAesAccounts.Count -gt 0) {
        $selAes = @(Select-FromList -Items $noAesAccounts -Prompt "Comptes sur lesquels forcer AES")
        if ($selAes.Count -gt 0) { Set-AesEncryptionOnAccounts -Accounts $selAes }
    }
}

function Invoke-Remediate5EnableKerberosArmoring {
    Write-Section "Activer Kerberos Armoring (FAST)" Red
    Write-Info "Necessite un niveau fonctionnel de domaine Windows Server 2012 minimum, et que TOUS les" `
               "DC soient Windows Server 2012 ou plus. Deploiement en 2 temps : DC en mode 'Pris en" `
               "charge' (Supported) d'abord, clients ensuite. Ne jamais passer en 'Echec des requetes" `
               "non blindees' sans validation complete (clients non-Windows, appliances)."

    if (-not (Test-GroupPolicyModule)) { return }

    try { $level = [string](Get-CachedADDomain).DomainMode } catch { $level = $null }
    if ($level -and $level -match '2000|2003|2008') {
        Write-Log ("Niveau fonctionnel de domaine actuel ({0}) insuffisant pour Kerberos Armoring (2012 minimum)." -f $level) -Level ERROR
        if (-not (Read-YesNo -Prompt "Continuer malgre tout (creation des GPO sans effet tant que le niveau n'est pas releve) ?")) { return }
    }

    $ouDCs = Get-DomainControllersOU
    $targetOUs = @(Select-OUsInteractive -Label "les clients Kerberos Armoring" -Verb "CIBLER (en plus des DC)")

    $gpoNameDc = "SEC - Kerberos Armoring (DC)"
    $gpoNameClient = "SEC - Kerberos Armoring (Clients)"
    if (-not (Confirm-Action ("Creer/lier '{0}' sur l'OU Domain Controllers, et '{1}' sur {2} UO client(s)" -f $gpoNameDc, $gpoNameClient, $targetOUs.Count) -Strong)) { return }

    Invoke-Guarded -Description ("Creation/MAJ de la GPO {0}" -f $gpoNameDc) -Action {
        $null = Get-OrCreateGpo -Name $gpoNameDc
        # Strategie "Prise en charge par le KDC des revendications, de l'authentification composee
        # et du blindage Kerberos" : EnableCbacAndArmor=1 + CbacAndArmorLevel=1 (Pris en charge).
        $key = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters"
        Set-GPRegistryValue -Name $gpoNameDc -Key $key -ValueName "EnableCbacAndArmor" -Type DWord -Value 1 | Out-Null
        Set-GPRegistryValue -Name $gpoNameDc -Key $key -ValueName "CbacAndArmorLevel" -Type DWord -Value 1 | Out-Null
        Add-GpoLinkSafe -Name $gpoNameDc -Targets $ouDCs
    }

    if ($targetOUs.Count -gt 0) {
        Invoke-Guarded -Description ("Creation/MAJ de la GPO {0}" -f $gpoNameClient) -Action {
            $null = Get-OrCreateGpo -Name $gpoNameClient
            # Strategie "Prise en charge du client Kerberos pour les revendications, l'authentification
            # composee et le blindage Kerberos".
            Set-GPRegistryValue -Name $gpoNameClient -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -ValueName "EnableCbacAndArmor" -Type DWord -Value 1 | Out-Null
            Add-GpoLinkSafe -Name $gpoNameClient -Targets $targetOUs
        }
    }
    Write-OutcomeLog "Kerberos Armoring active en mode 'Pris en charge'. Ne passez en mode exigeant qu'apres validation que tous les clients concernes le supportent."
}

function Get-SidHistoryRisk {
    <#
        Evaluation d'une entree sIDHistory (logique unique pour l'audit ET le diagnostic) :
        CRITIQUE si SID du domaine courant, SID integre (S-1-5-32-*) ou RID privilegie de
        n'importe quel domaine (500, 512, 516, 518, 519, 520, 521, 498, 526, 527).
    #>
    param([Parameter(Mandatory)][string]$Sid, [Parameter(Mandatory)][string]$DomainSid)
    if ($Sid -like "$DomainSid-*") { return 'CRITIQUE : SID du domaine courant' }
    if ($Sid -like 'S-1-5-32-*' -or $Sid -match '-(500|512|516|518|519|520|521|498|526|527)$') { return 'CRITIQUE : SID privilegie' }
    return 'A verifier : migration terminee ?'
}

function Invoke-Audit5SidHistory {
    Write-Section "Comptes porteurs d'un sIDHistory" Magenta
    Write-Info "Le sIDHistory (heritage de migrations) donne au compte les droits des SID qu'il contient." `
               "CRITIQUE si un SID du MEME domaine ou un SID privilegie (RID 500/512/518/519...) y figure :" `
               "technique de persistance classique apres compromission."

    $domainSid = (Get-CachedADDomain).DomainSID.Value
    $objs = @(Get-ADObject -LDAPFilter "(sIDHistory=*)" -Properties sIDHistory, sAMAccountName, objectClass -ErrorAction SilentlyContinue)
    if ($objs.Count -eq 0) { Write-Log "Aucun objet porteur d'un sIDHistory." -Level OK; return }

    $rows = @(foreach ($o in $objs) {
        foreach ($sid in @($o.sIDHistory)) {
            $s = $sid.Value
            $eval = Get-SidHistoryRisk -Sid $s -DomainSid $domainSid
            [PSCustomObject]@{ Compte = $o.sAMAccountName; Classe = $o.objectClass; SIDHistory = $s; Evaluation = $eval; DN = $o.DistinguishedName }
        }
    })
    $crit = @($rows | Where-Object { $_.Evaluation -like 'CRITIQUE*' })
    Write-Host ("{0} entree(s) sIDHistory sur {1} objet(s), dont {2} CRITIQUE(S)." -f $rows.Count, $objs.Count, $crit.Count) -ForegroundColor $(if ($crit.Count) { 'Red' } else { 'Yellow' })
    Write-ListPreview -Items $rows -Format { param($r) "{0} : {1} ({2})" -f $r.Compte, $r.SIDHistory, $r.Evaluation }
    [void](Export-Report -Rows $rows -Name "Rapport_SIDHistory")
}

function Invoke-Remediate5RemoveSidHistory {
    Write-Section "Supprimer des entrees sIDHistory" Red
    Write-Info "Risque : si une migration inter-domaines n'est pas terminee (ACL de ressources encore" `
               "basees sur les anciens SID), l'utilisateur perdra l'acces a ces ressources. Une entree" `
               "supprimee ne peut PAS etre recreee (l'ajout de sIDHistory est reserve aux outils de migration)."

    $domainSid = (Get-CachedADDomain).DomainSID.Value
    $entries = @(foreach ($o in @(Get-ADObject -LDAPFilter "(sIDHistory=*)" -Properties sIDHistory, sAMAccountName -ErrorAction SilentlyContinue)) {
        foreach ($sid in @($o.sIDHistory)) { [PSCustomObject]@{ Compte = $o.sAMAccountName; DN = $o.DistinguishedName; SID = $sid.Value; Risque = (Get-SidHistoryRisk -Sid $sid.Value -DomainSid $domainSid) } }
    })
    if ($entries.Count -eq 0) { Write-Log "Aucun sIDHistory a supprimer." -Level OK; return }

    $selected = @(Select-FromList -Items $entries -Prompt "Entrees a supprimer" -Display { param($e) "{0} : {1}  ({2})" -f $e.Compte, $e.SID, $e.Risque })
    if ($selected.Count -eq 0) { return }
    if (-not (Confirm-Action ("Supprimer {0} entree(s) sIDHistory (irreversible)" -f $selected.Count) -Strong)) { return }

    foreach ($e in $selected) {
        Invoke-Guarded -Description ("Suppression du sIDHistory {0} sur {1}" -f $e.SID, $e.Compte) -Action {
            Set-ADObject -Identity $e.DN -Remove @{ sIDHistory = $e.SID }
        }
    }
}

# ============================================================
#  THEME 5 - NTLM / LM
# ============================================================

function Invoke-SafeEnableNtlmAudit {
    Write-Section "Activation de l'audit NTLM (detection NTLMv1/LM avant tout blocage)" Cyan
    Write-Info "Impact : AUCUN sur le fonctionnement. Active uniquement la JOURNALISATION (jamais de" `
               "blocage) afin d'identifier QUI utilise encore NTLM avant d'en restreindre l'usage." `
               "Laissez tourner plusieurs jours (cycle metier complet), puis consultez le rapport (item 2)" `
               "et le journal 'Microsoft-Windows-NTLM/Operational' des DC (evenements 8001 a 8004)."

    $dcs = @(Get-ReachableDCs)
    if ($dcs.Count -eq 0) { return }
    Write-ListPreview -Items $dcs -Format { param($d) $d.HostName }

    if (-not (Confirm-Action "Activer l'audit NTLM (registre + journal NTLM Operational) sur ces DC")) { return }

    foreach ($dc in $dcs) {
        Invoke-Guarded -Description ("Activation de l'audit NTLM sur {0}" -f $dc.HostName) -Action {
            Invoke-OnDC -ComputerName $dc.HostName -ScriptBlock {
                $msv = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
                New-Item -Path $msv -Force -ErrorAction SilentlyContinue | Out-Null
                # AuditReceivingNTLMTraffic = 2 : journalise le NTLM RECU pour tous les comptes (audit seul).
                Set-ItemProperty -Path $msv -Name "AuditReceivingNTLMTraffic" -Value 2 -Type DWord -ErrorAction Stop
                # RestrictSendingNTLMTraffic = 1 : "Auditer tout" pour le NTLM EMIS - ne remplace pas une
                # valeur 2 (Refuser tout) deja en place, qui est plus restrictive.
                $cur = (Get-ItemProperty -Path $msv -Name RestrictSendingNTLMTraffic -ErrorAction SilentlyContinue).RestrictSendingNTLMTraffic
                if ($cur -ne 2) { Set-ItemProperty -Path $msv -Name "RestrictSendingNTLMTraffic" -Value 1 -Type DWord -ErrorAction Stop }

                $netlogon = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
                # AuditNTLMInDomain = 7 : "Activer tout" (comptes ET serveurs du domaine). La valeur 1 ne
                # couvre que "comptes du domaine vers serveurs du domaine" : visibilite partielle.
                Set-ItemProperty -Path $netlogon -Name "AuditNTLMInDomain" -Value 7 -Type DWord -ErrorAction Stop

                & wevtutil.exe set-log "Microsoft-Windows-NTLM/Operational" /enabled:true /quiet
                if ($LASTEXITCODE -ne 0) { throw "wevtutil n'a pas pu activer le journal NTLM/Operational (code $LASTEXITCODE)." }
            } -ErrorAction Stop
        }
    }

    Write-OutcomeLog "Audit NTLM active (journalisation uniquement, aucun blocage applique)."
    Write-Log "Rappel : l'audit 'Ouverture de session' (theme 15 > 2) doit aussi etre actif pour alimenter le rapport NTLMv1/LM (theme 5 > 2). Note : une GPO definissant ces parametres l'emporte sur cette configuration locale." -Level INFO
}

function Invoke-ReportNtlmV1Usage {
    Write-Section "Rapport : usage NTLMv1/LM detecte (journal Securite des DC)" Magenta
    Write-Info "Lit les evenements 4624/4625 dont le champ 'LmPackageName' vaut NTLM V1 ou LM." `
               "Les ouvertures de session ANONYMES (S-1-5-7), signalees 'NTLM V1' par Windows sans" `
               "reel usage NTLMv1, sont EXCLUES (faux positif classique)." `
               "Necessite l'audit 'Ouverture de session' actif sur les DC (theme 15 > 2)."
    Write-Host "Analyse potentiellement longue sur un DC charge (lecture du journal Securite)." -ForegroundColor Yellow

    $days = Read-IntValue -Prompt "Nombre de jours a analyser en arriere" -Default 7 -Min 1 -Max 365
    $dcs = @(Get-ReachableDCs)
    if ($dcs.Count -eq 0) { return }

    $allRows = [System.Collections.Generic.List[object]]::new()
    $analyzed = 0
    foreach ($dc in $dcs) {
        Write-Host ("Analyse de {0}..." -f $dc.HostName) -ForegroundColor DarkGray
        try {
            $res = Invoke-OnDC -ComputerName $dc.HostName -ScriptBlock {
                param($sinceDays)
                # Filtre XPath applique cote serveur ; champs XML (Name=...) lus a la place du texte
                # du message, qui est localise selon la langue de l'OS.
                $ms = [int64]$sinceDays * 86400000
                $xpath = "*[System[(EventID=4624 or EventID=4625) and TimeCreated[timediff(@SystemTime) <= $ms]]] and *[EventData[(Data[@Name='LmPackageName']='NTLM V1' or Data[@Name='LmPackageName']='LM') and Data[@Name='TargetUserSid']!='S-1-5-7']]"
                $events = @()
                try {
                    $events = @(Get-WinEvent -LogName Security -FilterXPath $xpath -ErrorAction Stop)
                } catch {
                    if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
                }
                $oldest = $null
                try { $oldest = (Get-WinEvent -LogName Security -MaxEvents 1 -Oldest -ErrorAction Stop).TimeCreated } catch { }
                $rows = foreach ($e in $events) {
                    $d = @{}
                    foreach ($x in ([xml]$e.ToXml()).Event.EventData.Data) { $d[$x.Name] = $x.'#text' }
                    [PSCustomObject]@{
                        DC          = $env:COMPUTERNAME
                        TimeCreated = $e.TimeCreated
                        EventId     = $e.Id
                        Version     = $d['LmPackageName']
                        Account     = ("{0}\{1}" -f $d['TargetDomainName'], $d['TargetUserName'])
                        Workstation = $d['WorkstationName']
                        SourceIP    = $d['IpAddress']
                    }
                }
                [PSCustomObject]@{ Rows = @($rows); Oldest = $oldest }
            } -ArgumentList $days -ErrorAction Stop
            $analyzed++
            foreach ($r in @($res.Rows)) { $allRows.Add($r) }
            if ($res.Oldest -and $res.Oldest -gt (Get-Date).AddDays(-$days)) {
                Write-Log ("{0} : le journal Securite ne remonte qu'au {1} (taille insuffisante pour couvrir {2} j)." -f $dc.HostName, $res.Oldest, $days) -Level WARN
            }
        } catch {
            Write-Log ("Impossible d'analyser le journal Securite de {0} : {1}" -f $dc.HostName, $_.Exception.Message) -Level WARN
        }
    }

    if ($analyzed -eq 0) { Write-Log "Aucun DC n'a pu etre analyse : aucune conclusion possible." -Level ERROR; return }
    if ($allRows.Count -eq 0) {
        Write-Log ("Aucune authentification NTLMv1/LM detectee sur {0}/{1} DC analyse(s) et {2} jour(s) (verifiez que l'audit des ouvertures de session est actif)." -f $analyzed, $dcs.Count, $days) -Level OK
        return
    }

    [void](Export-Report -Rows ($allRows | Sort-Object TimeCreated -Descending) -Name ("Rapport_NTLMv1_LM_{0}j" -f $days))
    Write-Host ("{0} evenement(s) NTLMv1/LM detecte(s) sur {1} jour(s). Sources les plus frequentes :" -f $allRows.Count, $days) -ForegroundColor Yellow
    $allRows | Group-Object Account, Workstation, SourceIP | Sort-Object Count -Descending | Select-Object -First 15 | ForEach-Object {
        Write-Host ("  - {0} : {1} evenement(s)" -f ($_.Name -replace ', ', ' | '), $_.Count)
    }
    Write-Log "Corrigez ces sources (mise a jour, configuration NTLMv2) AVANT d'appliquer 'Desactiver NTLMv1/LM' (theme 5 > 3)." -Level WARN
}

function Invoke-RiskyDisableNtlmV1 {
    Write-Section "Desactivation NTLMv1/LM (LmCompatibilityLevel) via GPO" Red
    Write-Info "Risque : casse l'authentification de materiels/applications tres anciens (vieux NAS," `
               "imprimantes, appliances) qui ne savent parler qu'en NTLMv1/LM." `
               "Niveau 3 : les CLIENTS n'emettent plus que du NTLMv2 (les DC acceptent encore v1)." `
               "Niveau 5 : en plus, les DC/serveurs REFUSENT LM et NTLMv1. Deployer 3 puis 5."
    Write-Host "Avant de continuer : l'audit NTLM (item 1) et le rapport NTLMv1/LM (item 2) ont-ils ete consultes ?" -ForegroundColor Yellow
    if (-not (Read-YesNo -Prompt "Continuer sans avoir verifie ce rapport est deconseille. Continuer ?")) { return }

    $level = Read-Host "Niveau LmCompatibilityLevel a appliquer [3/5]"
    if ($level -notin @("3", "5")) { Write-Log "Valeur invalide, action annulee." -Level WARN; return }

    if (-not (Test-GroupPolicyModule)) { return }

    $gpoName = "SEC - Durcissement NTLM (LmCompatibilityLevel=$level)"
    Write-Host "Liaison de la GPO : choisissez une UO PILOTE (vide = GPO creee sans lien, a lier manuellement)." -ForegroundColor Yellow
    $targets = @(Select-OUsInteractive -Label "la GPO LmCompatibilityLevel=$level" -Verb "CIBLER (lien pilote)")
    if (-not (Confirm-Action ("Creer la GPO '{0}'{1}" -f $gpoName, $(if ($targets) { " et la lier sur $($targets.Count) UO" } else { " (non liee)" })) -Strong)) { return }

    Invoke-Guarded -Description ("GPO LmCompatibilityLevel=$level") -Action {
        $null = Get-OrCreateGpo -Name $gpoName
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\System\CurrentControlSet\Control\Lsa" -ValueName "LmCompatibilityLevel" -Type DWord -Value ([int]$level) | Out-Null
        if ($targets.Count -gt 0) { Add-GpoLinkSafe -Name $gpoName -Targets $targets }
    }
    if ($targets.Count -eq 0) { Write-OutcomeLog "GPO creee mais NON liee : liez-la a une UO pilote avant tout deploiement large." -Level WARN }
    else { Write-OutcomeLog "GPO liee aux UO pilotes. Surveillez les echecs d'authentification avant d'etendre." -Level WARN }
}

function Invoke-Remediate6RestrictNtlmOutgoing {
    Write-Section "Restriction de NTLM sortant depuis les DC (Refuser tout + exceptions)" Red
    Write-Info "Bloque TOUTE authentification NTLM sortante (v1 ET v2) emise PAR les DC, sauf vers les" `
               "serveurs explicitement exceptes. Necessite l'audit NTLM actif depuis un moment (item 1)" `
               "pour batir la liste d'exceptions a partir des usages reellement observes (evenement 8001)."

    if (-not (Test-GroupPolicyModule)) { return }

    $exceptions = Read-Host "Serveurs exceptes (NTLM autorise vers eux, ex : srv01,*.legacy.local), separes par une virgule (vide = aucune)"
    $exceptionList = @($exceptions -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })

    $gpoName = "SEC - Restriction NTLM sortant (Deny)"
    if (-not (Confirm-Action ("Creer/lier la GPO '{0}' sur l'OU Domain Controllers (NTLM sortant refuse, {1} exception(s))" -f $gpoName, $exceptionList.Count) -Strong)) { return }

    $ouDCs = Get-DomainControllersOU
    Invoke-Guarded -Description ("Creation/MAJ de la GPO {0}" -f $gpoName) -Action {
        $null = Get-OrCreateGpo -Name $gpoName
        $key = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
        # RestrictSendingNTLMTraffic = 2 -> "Refuser tout" (sauf exceptions ClientAllowedNTLMServers).
        Set-GPRegistryValue -Name $gpoName -Key $key -ValueName "RestrictSendingNTLMTraffic" -Type DWord -Value 2 | Out-Null
        if ($exceptionList.Count -gt 0) {
            Set-GPRegistryValue -Name $gpoName -Key $key -ValueName "ClientAllowedNTLMServers" -Type MultiString -Value $exceptionList | Out-Null
        }
        Add-GpoLinkSafe -Name $gpoName -Targets $ouDCs
    }
    Write-OutcomeLog "GPO liee sur l'OU Domain Controllers. Surveillez le journal NTLM/Operational (evenement 4001 = blocage) plusieurs jours apres application." -Level WARN
}

function Invoke-Audit6NtlmConfiguration {
    Write-Section "Configuration NTLM effective sur les DC (registre)" Magenta
    Write-Info "Lecture seule : LmCompatibilityLevel, audit et restrictions NTLM, sur chaque DC joignable."

    $dcs = @(Get-ReachableDCs)
    if ($dcs.Count -eq 0) { return }
    $rows = @(foreach ($dc in $dcs) {
        try {
            Invoke-OnDC -ComputerName $dc.HostName -ScriptBlock {
                $lsa = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue
                $msv = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -ErrorAction SilentlyContinue
                $net = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -ErrorAction SilentlyContinue
                $lm = $lsa.LmCompatibilityLevel
                [PSCustomObject]@{
                    DC                         = $env:COMPUTERNAME
                    LmCompatibilityLevel       = if ($null -eq $lm) { '3 (defaut OS, non defini)' } else { $lm }
                    NoLMHash                   = $lsa.NoLMHash
                    AuditReceivingNTLMTraffic  = $msv.AuditReceivingNTLMTraffic
                    RestrictSendingNTLMTraffic = $msv.RestrictSendingNTLMTraffic
                    AuditNTLMInDomain          = $net.AuditNTLMInDomain
                    RestrictNTLMInDomain       = $net.RestrictNTLMInDomain
                    NtlmMinServerSec           = $msv.NtlmMinServerSec
                }
            } -ErrorAction Stop
        } catch { Write-Log ("Lecture impossible sur {0} : {1}" -f $dc.HostName, $_.Exception.Message) -Level WARN }
    })
    foreach ($r in $rows) {
        $lmVal = [string]$r.LmCompatibilityLevel
        $color = if ($lmVal -eq '5') { 'Green' } else { 'Yellow' }
        Write-Host ("  - {0} : LmCompatibilityLevel={1}, audit NTLM domaine={2}, audit NTLM recu={3}, NTLM sortant={4}" -f $r.DC, $lmVal, $r.AuditNTLMInDomain, $r.AuditReceivingNTLMTraffic, $r.RestrictSendingNTLMTraffic) -ForegroundColor $color
    }
    if (@($rows | Where-Object { [string]$_.LmCompatibilityLevel -ne '5' }).Count -gt 0) {
        Write-Log "Au moins un DC accepte encore NTLMv1/LM (LmCompatibilityLevel < 5) : objectif 5 apres audit des usages." -Level WARN
    }
    [void](Export-Report -Rows $rows -Name "Rapport_ConfigNTLM_DC")
}

# ============================================================
#  THEME 6 - SMB, SYSVOL ET NETLOGON
# ============================================================

function Invoke-Audit7Smb1Usage {
    Write-Section "Detection de l'usage SMBv1" Magenta
    Write-Info "Propose d'activer l'audit SMBv1 (journalisation uniquement) sur les DC joignables, puis" `
               "lit le journal Microsoft-Windows-SMBServer/Audit (evenement 3000) pour lister les" `
               "clients qui se sont connectes en SMBv1 depuis l'activation de l'audit."

    $dcs = @(Get-ReachableDCs)
    if ($dcs.Count -eq 0) { return }

    if (Read-YesNo -Prompt "Activer/verifier l'audit SMBv1 sur ces DC avant lecture du journal ?") {
        foreach ($dc in $dcs) {
            Invoke-Guarded -Description ("Activation de l'audit SMBv1 sur {0}" -f $dc.HostName) -Action {
                Invoke-OnDC -ComputerName $dc.HostName -ScriptBlock {
                    Set-SmbServerConfiguration -AuditSmb1Access $true -Force -ErrorAction Stop
                } -ErrorAction Stop
            }
        }
    }

    $allRows = [System.Collections.Generic.List[object]]::new()
    foreach ($dc in $dcs) {
        try {
            $res = Invoke-OnDC -ComputerName $dc.HostName -ScriptBlock {
                $smb1 = $null
                try { $smb1 = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch { }
                $events = @()
                try {
                    $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-SMBServer/Audit'; Id = 3000 } -ErrorAction Stop)
                } catch {
                    if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
                }
                [PSCustomObject]@{
                    Smb1Enabled = $smb1
                    Rows = @($events | ForEach-Object {
                        [PSCustomObject]@{ DC = $env:COMPUTERNAME; TimeCreated = $_.TimeCreated; Client = [string]$_.Properties[0].Value }
                    })
                }
            } -ErrorAction Stop
            if ($res.Smb1Enabled -eq $false) { Write-Host ("  {0} : SMBv1 serveur deja desactive." -f $dc.HostName) -ForegroundColor Green }
            foreach ($r in @($res.Rows)) { $allRows.Add($r) }
        } catch {
            Write-Log ("Impossible de lire le journal SMBServer/Audit sur {0} : {1}" -f $dc.HostName, $_.Exception.Message) -Level WARN
        }
    }

    if ($allRows.Count -eq 0) {
        Write-Log "Aucune connexion SMBv1 journalisee (ou audit active trop recemment)." -Level OK
        return
    }

    $byClient = @($allRows | Group-Object Client | Sort-Object Count -Descending | ForEach-Object {
        [PSCustomObject]@{ Client = $_.Name; Connexions = $_.Count; Derniere = ($_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated; DC = (($_.Group.DC | Sort-Object -Unique) -join ', ') }
    })
    Write-Host ("{0} connexion(s) SMBv1 depuis {1} client(s) distinct(s) :" -f $allRows.Count, $byClient.Count) -ForegroundColor Yellow
    Write-ListPreview -Items $byClient -Format { param($c) "{0} : {1} connexion(s), derniere le {2}" -f $c.Client, $c.Connexions, $c.Derniere }
    [void](Export-Report -Rows $byClient -Name "Rapport_SMB1_Clients" -Comment "Identifiez ces equipements AVANT de desactiver SMBv1.")
}

function Invoke-Audit7SmbSigningStatus {
    Write-Section "Etat de la signature SMB (client/serveur) sur les DC" Magenta

    $dcs = @(Get-ReachableDCs)
    if ($dcs.Count -eq 0) { return }

    $rows = @(foreach ($dc in $dcs) {
        try {
            Invoke-OnDC -ComputerName $dc.HostName -ScriptBlock {
                $srv = Get-SmbServerConfiguration
                $cli = Get-SmbClientConfiguration
                [PSCustomObject]@{
                    DC                      = $env:COMPUTERNAME
                    ServeurSignatureRequise = $srv.RequireSecuritySignature
                    ClientSignatureRequise  = $cli.RequireSecuritySignature
                    SMB1Actif               = $srv.EnableSMB1Protocol
                    ChiffrementSMB          = $srv.EncryptData
                }
            } -ErrorAction Stop
        } catch {
            Write-Log ("Impossible de lire la configuration SMB de {0} : {1}" -f $dc.HostName, $_.Exception.Message) -Level WARN
        }
    })

    foreach ($r in $rows) {
        $color = if ($r.ServeurSignatureRequise -and -not $r.SMB1Actif) { 'Green' } else { 'Yellow' }
        Write-Host ("  - {0} : signature serveur requise={1}, client requise={2}, SMBv1 actif={3}" -f $r.DC, $r.ServeurSignatureRequise, $r.ClientSignatureRequise, $r.SMB1Actif) -ForegroundColor $color
    }
    [void](Export-Report -Rows $rows -Name "Rapport_SMB_Signing")
}

function Invoke-Remediate7DisableSmb1 {
    Write-Section "Desactivation de SMBv1 (client et serveur) sur les DC" Red
    Write-Info "Risque : casse l'acces des vieux NAS/scanners/imprimantes/applications qui ne parlent" `
               "QUE SMBv1. Consultez le rapport d'usage SMBv1 (item 1) avant de continuer."
    if (-not (Read-YesNo -Prompt "Le rapport d'usage SMBv1 a-t-il ete consulte ?")) { return }

    $dcs = @(Get-ReachableDCs)
    if ($dcs.Count -eq 0) { return }

    if (-not (Confirm-Action "Desactiver SMBv1 (client + serveur) sur tous les DC listes" -Strong)) { return }

    foreach ($dc in $dcs) {
        Invoke-Guarded -Description ("Desactivation SMBv1 sur {0}" -f $dc.HostName) -Action {
            Invoke-OnDC -ComputerName $dc.HostName -ScriptBlock $Script:DisableSmb1ScriptBlock -ErrorAction Stop
        }
    }
    Write-OutcomeLog "SMBv1 desactive. Un redemarrage peut etre necessaire pour retirer completement le composant." -Level WARN
}

# Desactivation SMBv1 (serveur + composant client), compatible 2012 R2 -> 2025.
$Script:DisableSmb1ScriptBlock = {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
    $feat = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if ($feat -and $feat.State -ne 'Disabled') {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null
    } elseif (-not $feat) {
        # Pilote client mrxsmb10 (systemes sans fonctionnalite optionnelle SMB1Protocol).
        & sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi | Out-Null
        & sc.exe config mrxsmb10 start= disabled | Out-Null
    }
}

function Invoke-Remediate7DisableSmb1OnComputers {
    Write-Section "Desactivation de SMBv1 sur des postes/serveurs choisis" Red
    Write-Info "Complementaire a la desactivation SMBv1 sur les DC (item 4) : cible ici des" `
               "postes/serveurs membres. Consultez le rapport d'usage SMBv1 avant de continuer."

    $targets = @(Get-TargetComputers -Label "la desactivation SMBv1")
    if ($targets.Count -eq 0) { return }

    Write-Host ("Machines ciblees : {0}" -f ($targets -join ', ')) -ForegroundColor Yellow
    if (-not (Confirm-Action ("Desactiver SMBv1 (client + serveur) sur {0} machine(s)" -f $targets.Count) -Strong)) { return }

    foreach ($name in $targets) {
        Invoke-Guarded -Description ("Desactivation SMBv1 sur {0}" -f $name) -Action {
            Invoke-OnDC -ComputerName $name -ScriptBlock $Script:DisableSmb1ScriptBlock -ErrorAction Stop
        }
    }
    Write-OutcomeLog "SMBv1 desactive sur les machines ciblees. Un redemarrage peut etre necessaire." -Level WARN
}

function Invoke-Remediate7EnforceSmbSigning {
    Write-Section "Forcer la signature SMB (client et serveur) via GPO" Red
    Write-Info "Risque : casse les clients/serveurs SMB tres anciens ne supportant pas la signature" `
               "(rare, mais possible sur des NAS/appliances obsoletes). Impact performance faible sur" `
               "un materiel recent. La GPO est liee aux DC ; vous pouvez ajouter des UO pilotes."

    if (-not (Test-GroupPolicyModule)) { return }

    $extra = @(Select-OUsInteractive -Label "la signature SMB (en plus des DC)" -Verb "CIBLER (lien supplementaire)")
    $gpoName = "SEC - Signature SMB obligatoire"
    $targets = @(Get-DomainControllersOU) + $extra
    if (-not (Confirm-Action ("Creer/lier la GPO '{0}' sur {1} cible(s) (signature client+serveur obligatoire)" -f $gpoName, $targets.Count) -Strong)) { return }

    Invoke-Guarded -Description ("Creation/MAJ de la GPO {0}" -f $gpoName) -Action {
        $null = Get-OrCreateGpo -Name $gpoName
        foreach ($svc in 'LanmanServer', 'LanmanWorkstation') {
            foreach ($v in 'RequireSecuritySignature', 'EnableSecuritySignature') {
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\System\CurrentControlSet\Services\$svc\Parameters" -ValueName $v -Type DWord -Value 1 | Out-Null
            }
        }
        Add-GpoLinkSafe -Name $gpoName -Targets $targets
    }
    Write-OutcomeLog "GPO liee. Etendez-la aux serveurs/postes apres validation sur les UO pilotes." -Level WARN
}

function Invoke-Remediate7HardenedUncPaths {
    Write-Section "Durcissement des chemins UNC SYSVOL et NETLOGON (Hardened UNC Paths)" Red
    Write-Info "Exige l'integrite et l'authentification mutuelle sur les acces \\*\SYSVOL et \\*\NETLOGON" `
               "(protection MS15-011 contre l'usurpation de DC lors de l'application des GPO)." `
               "Impact large (tous les postes/serveurs) mais risque residuel tres faible sur un parc a jour."

    if (-not (Test-GroupPolicyModule)) { return }

    $gpoName = "SEC - Hardened UNC Paths (SYSVOL-NETLOGON)"
    Write-Host "Liaison : choisissez des UO PILOTES (vide = GPO creee sans lien)." -ForegroundColor Yellow
    $targets = @(Select-OUsInteractive -Label "les Hardened UNC Paths" -Verb "CIBLER (lien pilote)" -IncludeDomainRoot)
    if (-not (Confirm-Action ("Creer la GPO '{0}'{1}" -f $gpoName, $(if ($targets) { " et la lier sur $($targets.Count) cible(s)" } else { " (non liee)" })) -Strong)) { return }

    Invoke-Guarded -Description ("Creation/MAJ de la GPO {0}" -f $gpoName) -Action {
        $null = Get-OrCreateGpo -Name $gpoName
        $key = "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
        Set-GPRegistryValue -Name $gpoName -Key $key -ValueName '\\*\SYSVOL' -Type String -Value "RequireMutualAuthentication=1, RequireIntegrity=1" | Out-Null
        Set-GPRegistryValue -Name $gpoName -Key $key -ValueName '\\*\NETLOGON' -Type String -Value "RequireMutualAuthentication=1, RequireIntegrity=1" | Out-Null
        if ($targets.Count -gt 0) { Add-GpoLinkSafe -Name $gpoName -Targets $targets }
    }
    if ($targets.Count -eq 0) { Write-OutcomeLog "GPO creee mais NON liee. Testez d'abord sur une UO pilote avant deploiement domaine entier." -Level WARN }
}

function Invoke-Audit7SensitiveShares {
    Write-Section "Audit des partages SMB sur des postes/serveurs choisis" Magenta
    Write-Info "Signale les partages (hors partages administratifs) accordant Modification ou Controle" `
               "total a un groupe LARGE : Tout le monde, Utilisateurs authentifies, Utilisateurs (BUILTIN)," `
               "Utilisateurs du domaine, Anonyme. Comparaison par SID (independante de la langue)."

    $targets = @(Get-TargetComputers -Label "l'audit des partages SMB" -IncludeDCs)
    if ($targets.Count -eq 0) { return }
    $domainUsersSid = "{0}-513" -f (Get-CachedADDomain).DomainSID.Value

    $rows = @(foreach ($name in $targets) {
        try {
            Invoke-OnDC -ComputerName $name -ScriptBlock {
                param($domUsers)
                $broad = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-7', $domUsers)
                Get-SmbShare -ErrorAction Stop | Where-Object { -not $_.Special -and $_.Name -notmatch '\$$' } | ForEach-Object {
                    $share = $_
                    Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.AccessRight -in @('Full', 'Change') } | ForEach-Object {
                        $sid = $null
                        try { $sid = (New-Object Security.Principal.NTAccount($_.AccountName)).Translate([Security.Principal.SecurityIdentifier]).Value } catch { }
                        if ($sid -and $broad -contains $sid) {
                            [PSCustomObject]@{ Machine = $env:COMPUTERNAME; Partage = $share.Name; Chemin = $share.Path; Principal = $_.AccountName; Droit = $_.AccessRight }
                        }
                    }
                }
            } -ArgumentList $domainUsersSid -ErrorAction Stop
        } catch {
            Write-Log ("Impossible de lire les partages de {0} : {1}" -f $name, $_.Exception.Message) -Level WARN
        }
    })

    if ($rows.Count -eq 0) { Write-Log "Aucun partage accordant Modification/Controle total a un groupe large." -Level OK; return }
    Write-ListPreview -Items $rows -Color Red -Format { param($r) "{0}\{1} ({2}) : {3} -> {4}" -f $r.Machine, $r.Partage, $r.Chemin, $r.Principal, $r.Droit }
    [void](Export-Report -Rows $rows -Name "Rapport_PartagesSensibles" -Comment "Pensez aussi aux permissions NTFS (le droit effectif est le plus restrictif des deux).")
}

# ============================================================
#  THEME 7 - LDAP / LDAPS
# ============================================================

function Invoke-Audit8LdapsCertificates {
    Write-Section "Audit des certificats LDAPS sur les DC" Magenta
    Write-Info "Verifie un certificat 'Authentification du serveur' correspondant au nom du DC dans le" `
               "magasin Ordinateur local, sa chaine de confiance, son expiration, et teste une vraie" `
               "negociation TLS sur le port 636 (pas seulement l'ouverture du port)."

    $dcs = @(Get-ReachableDCs)
    if ($dcs.Count -eq 0) { return }

    $rows = @(foreach ($dc in $dcs) {
        $tls = $null; $tlsErr = $null
        try {
            $tcp = New-Object Net.Sockets.TcpClient
            $iar = $tcp.BeginConnect($dc.HostName, 636, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(3000) -and $tcp.Connected) {
                $ssl = New-Object Net.Security.SslStream($tcp.GetStream(), $false, { $true })
                $ssl.AuthenticateAsClient($dc.HostName)
                $remote = New-Object Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
                $tls = [PSCustomObject]@{ Protocole = [string]$ssl.SslProtocol; CertSujet = $remote.Subject; CertExpiration = $remote.NotAfter }
                $ssl.Dispose()
            } else { $tlsErr = "port 636 injoignable" }
            $tcp.Close()
        } catch { $tlsErr = $_.Exception.Message }

        $certInfo = $null
        try {
            $certInfo = Invoke-OnDC -ComputerName $dc.HostName -ScriptBlock {
                param($fqdn)
                $certs = @(Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {
                    $_.HasPrivateKey -and
                    (-not $_.EnhancedKeyUsageList -or $_.EnhancedKeyUsageList.ObjectId -contains '1.3.6.1.5.5.7.3.1') -and
                    ($_.DnsNameList.Unicode -contains $fqdn -or $_.Subject -match ('CN=' + [regex]::Escape($fqdn)))
                })
                if ($certs.Count -eq 0) { return $null }
                $best = $certs | Sort-Object NotAfter -Descending | Select-Object -First 1
                # Chaine validee hors revocation (CRL/OCSP externe souvent injoignable depuis un DC).
                $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
                $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
                [PSCustomObject]@{ Sujet = $best.Subject; Expiration = $best.NotAfter; ChaineValide = $chain.Build($best) }
            } -ArgumentList $dc.HostName -ErrorAction Stop
        } catch { }

        [PSCustomObject]@{
            DC               = $dc.HostName
            TLS636           = if ($tls) { $tls.Protocole } else { "ECHEC ($tlsErr)" }
            CertificatTrouve = [bool]$certInfo
            Sujet            = if ($certInfo) { $certInfo.Sujet } elseif ($tls) { $tls.CertSujet } else { $null }
            Expiration       = if ($certInfo) { $certInfo.Expiration } elseif ($tls) { $tls.CertExpiration } else { $null }
            ChaineValide     = if ($certInfo) { $certInfo.ChaineValide } else { $null }
        }
    })

    foreach ($r in $rows) {
        $soon = $r.Expiration -and $r.Expiration -lt (Get-Date).AddDays(60)
        $color = if ($r.TLS636 -like 'ECHEC*' -or $r.ChaineValide -eq $false) { 'Red' } elseif ($soon) { 'Yellow' } else { 'Green' }
        Write-Host ("  - {0} : TLS 636={1}, certificat={2}, chaine valide={3}, expiration={4}{5}" -f $r.DC, $r.TLS636, $r.CertificatTrouve, $r.ChaineValide, $r.Expiration, $(if ($soon) { ' (< 60 j)' } else { '' })) -ForegroundColor $color
    }
    [void](Export-Report -Rows $rows -Name "Rapport_LDAPS_Certificats")
}

function Invoke-Audit8LdapSimpleBinds {
    Write-Section "Audit des binds LDAP non signes / simples en clair" Magenta
    Write-Info "- Evenement 2887 : RESUME quotidien du nombre de binds non signes / simples en clair." `
               "- Evenement 2889 : DETAIL par client (adresse IP + compte), genere quand le diagnostic" `
               "  '16 LDAP Interface Events' est >= 2. C'est la liste a corriger avant d'exiger la signature."

    $dcs = @(Get-ReachableDCs)
    if ($dcs.Count -eq 0) { return }

    if (Read-YesNo -Prompt "Activer le diagnostic LDAP Interface Events (niveau 2) sur ces DC ?") {
        foreach ($dc in $dcs) {
            Invoke-Guarded -Description ("Activation du diagnostic LDAP Interface Events sur {0}" -f $dc.HostName) -Action {
                Invoke-OnDC -ComputerName $dc.HostName -ScriptBlock {
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" -Name "16 LDAP Interface Events" -Value 2 -Type DWord -ErrorAction Stop
                } -ErrorAction Stop
            }
        }
        Write-OutcomeLog "Diagnostic active : les evenements 2889 apparaissent au fil des binds, le resume 2887 toutes les 24 h. Relancez cet audit apres un cycle d'activite." -Level WARN
    }

    $summary = [System.Collections.Generic.List[object]]::new()
    $clients = [System.Collections.Generic.List[object]]::new()
    foreach ($dc in $dcs) {
        try {
            $res = Invoke-OnDC -ComputerName $dc.HostName -ScriptBlock {
                $out = [PSCustomObject]@{ Summary = $null; Clients = @() }
                try {
                    $e = Get-WinEvent -FilterHashtable @{ LogName = 'Directory Service'; Id = 2887 } -MaxEvents 1 -ErrorAction Stop
                    $out.Summary = [PSCustomObject]@{ DC = $env:COMPUTERNAME; Date = $e.TimeCreated; BindsSimplesClair = [string]$e.Properties[0].Value; BindsNonSignes = [string]$e.Properties[1].Value }
                } catch { }
                try {
                    $out.Clients = @(Get-WinEvent -FilterHashtable @{ LogName = 'Directory Service'; Id = 2889 } -MaxEvents 5000 -ErrorAction Stop | ForEach-Object {
                        [PSCustomObject]@{
                            DC       = $env:COMPUTERNAME
                            Date     = $_.TimeCreated
                            ClientIP = ([string]$_.Properties[0].Value -replace ':\d+$', '')
                            Compte   = [string]$_.Properties[1].Value
                            TypeBind = switch ([string]$_.Properties[2].Value) { '0' { 'Non signe (SASL)' } '1' { 'Simple en clair' } default { [string]$_.Properties[2].Value } }
                        }
                    })
                } catch { }
                $out
            } -ErrorAction Stop
            if ($res.Summary) { $summary.Add($res.Summary) }
            foreach ($c in @($res.Clients)) { $clients.Add($c) }
        } catch {
            Write-Log ("Lecture du journal Directory Service impossible sur {0} : {1}" -f $dc.HostName, $_.Exception.Message) -Level WARN
        }
    }

    foreach ($s in $summary) {
        Write-Host ("  {0} (resume du {1}) : {2} bind(s) non signe(s), {3} bind(s) simple(s) en clair" -f $s.DC, $s.Date, $s.BindsNonSignes, $s.BindsSimplesClair) -ForegroundColor Yellow
    }
    if ($clients.Count -eq 0) {
        Write-Log "Aucun evenement 2889 (detail par client) : diagnostic inactif, trop recent, ou aucun client non conforme." -Level INFO
    } else {
        $grouped = @($clients | Group-Object ClientIP, Compte, TypeBind | Sort-Object Count -Descending | ForEach-Object {
            $f = $_.Group[0]
            [PSCustomObject]@{ ClientIP = $f.ClientIP; Compte = $f.Compte; TypeBind = $f.TypeBind; Occurrences = $_.Count; DC = (($_.Group.DC | Sort-Object -Unique) -join ', ') }
        })
        Write-Host ("{0} client(s) LDAP non conforme(s) :" -f $grouped.Count) -ForegroundColor Yellow
        Write-ListPreview -Items $grouped -Format { param($g) "{0} ({1}) : {2} x {3}" -f $g.ClientIP, $g.Compte, $g.Occurrences, $g.TypeBind }
        [void](Export-Report -Rows $grouped -Name "Rapport_LDAP_ClientsNonSignes" -Comment "A corriger avant d'exiger la signature LDAP (item 3).")
    }
    [void](Export-Report -Rows $summary -Name "Rapport_LDAP_Resume2887")
}

function Invoke-RiskyEnforceLdapSigning {
    Write-Section "Signature LDAP / channel binding sur les DC" Red
    Write-Info "Risque : casse les clients/appliances LDAP qui ne supportent pas la signature (NAS," `
               "supervision, vieux annuaires synchronises...). Prerequis : audit des clients (item 2)." `
               "Note : si une GPO (souvent 'Default Domain Controllers Policy') definit deja 'Controleur" `
               "de domaine : conditions requises pour la signature de serveur LDAP', elle ECRASERA cette" `
               "valeur au prochain rafraichissement : modifiez alors la GPO elle-meme."

    $dcs = @(Get-ReachableDCs)
    if ($dcs.Count -eq 0) { return }

    Write-Host "Niveau de channel binding (LDAPS) :" -ForegroundColor Cyan
    Write-Host "  [1] 'Lorsque pris en charge' (valeur 1) - etape de transition recommandee"
    Write-Host "  [2] 'Toujours' (valeur 2) - cible finale"
    $cb = if ((Read-Host "Choix [1/2] (defaut 1)") -eq '2') { 2 } else { 1 }

    if (-not (Confirm-Action ("Exiger la signature LDAP (LDAPServerIntegrity=2) et LdapEnforceChannelBinding={0} sur {1} DC" -f $cb, $dcs.Count) -Strong)) { return }

    foreach ($dc in $dcs) {
        Invoke-Guarded -Description ("LDAP signing/channel binding sur {0}" -f $dc.HostName) -Action {
            Invoke-OnDC -ComputerName $dc.HostName -ScriptBlock {
                param($cbValue)
                $p = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
                Set-ItemProperty -Path $p -Name "LDAPServerIntegrity" -Value 2 -Type DWord -ErrorAction Stop
                Set-ItemProperty -Path $p -Name "LdapEnforceChannelBinding" -Value $cbValue -Type DWord -ErrorAction Stop
            } -ArgumentList $cb -ErrorAction Stop
        }
    }
    Write-OutcomeLog "Parametres appliques (pris en compte sans redemarrage sur les OS recents ; redemarrer NTDS en cas de doute). Verifiez ensuite les evenements 2889/3039." -Level WARN
}

function Invoke-Remediate8DisableWeakTls {
    Write-Section "Desactivation TLS 1.0/1.1 et activation TLS 1.2+ sur les DC (SCHANNEL + .NET)" Red
    Write-Info "Risque : casse les clients LDAPS/RDP/applicatifs qui ne negocient qu'en TLS 1.0/1.1" `
               "(rare sur un parc a jour, frequent sur des appliances tres anciennes). Configure aussi" `
               ".NET Framework (SchUseStrongCrypto/SystemDefaultTlsVersions) pour que les applications" `
               ".NET hebergees (ex : Entra Connect, outils d'admin) restent fonctionnelles en TLS 1.2."

    $dcs = @(Get-ReachableDCs)
    if ($dcs.Count -eq 0) { return }

    if (-not (Confirm-Action "Desactiver TLS 1.0/1.1 (client+serveur), activer TLS 1.2 et le TLS fort .NET sur tous les DC" -Strong)) { return }

    foreach ($dc in $dcs) {
        Invoke-Guarded -Description ("Durcissement SCHANNEL/.NET (TLS) sur {0}" -f $dc.HostName) -Action {
            Invoke-OnDC -ComputerName $dc.HostName -ScriptBlock {
                $base = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
                foreach ($proto in @('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2')) {
                    foreach ($role in @('Client', 'Server')) {
                        $path = "$base\$proto\$role"
                        New-Item -Path $path -Force | Out-Null
                        $enabled = if ($proto -eq 'TLS 1.2') { 1 } else { 0 }
                        Set-ItemProperty -Path $path -Name "Enabled" -Value $enabled -Type DWord -ErrorAction Stop
                        Set-ItemProperty -Path $path -Name "DisabledByDefault" -Value (1 - $enabled) -Type DWord -ErrorAction Stop
                    }
                }
                foreach ($net in @("HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319",
                                   "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727")) {
                    if (-not (Test-Path $net)) { continue }
                    Set-ItemProperty -Path $net -Name "SchUseStrongCrypto" -Value 1 -Type DWord -ErrorAction Stop
                    Set-ItemProperty -Path $net -Name "SystemDefaultTlsVersions" -Value 1 -Type DWord -ErrorAction Stop
                }
            } -ErrorAction Stop
        }
    }
    Write-OutcomeLog "Redemarrage des DC requis pour la prise en compte complete des parametres SCHANNEL." -Level WARN
}

function Get-DsHeuristicsState {
    $configNC = (Get-ADRootDSE -ErrorAction Stop).configurationNamingContext
    $dn = "CN=Directory Service,CN=Windows NT,CN=Services,$configNC"
    $value = [string](Get-ADObject -Identity $dn -Properties dSHeuristics -ErrorAction Stop).dSHeuristics
    $c7 = if ($value.Length -ge 7) { $value[6] } else { '0' }
    $c16 = if ($value.Length -ge 16) { $value[15] } else { '0' }
    return [PSCustomObject]@{
        DN              = $dn
        Value           = $value
        AnonymousLdap   = ($c7 -eq '2')     # 7e caractere = 2 : operations LDAP anonymes AUTORISEES
        AdminSDExMask   = $c16              # 16e caractere : groupes d'operateurs exclus d'AdminSDHolder
    }
}

function Invoke-Audit8DsHeuristicsAndLdapConfig {
    Write-Section "dSHeuristics et configuration LDAP des DC" Magenta
    Write-Info "- dSHeuristics, 7e caractere = 2 : operations LDAP ANONYMES autorisees (KB326690) ;" `
               "- 16e caractere (dwAdminSDExMask) <> 0 : des groupes d'operateurs sont SORTIS de la" `
               "  protection AdminSDHolder ;" `
               "- registre des DC : LDAPServerIntegrity (2 = signature exigee), LdapEnforceChannelBinding."

    try {
        $st = Get-DsHeuristicsState
        Write-Host ("dSHeuristics = '{0}'" -f $(if ($st.Value) { $st.Value } else { '(vide - valeurs par defaut securisees)' })) -ForegroundColor Cyan
        if ($st.AnonymousLdap) { Write-Log "Operations LDAP anonymes AUTORISEES (7e caractere = 2) : a corriger (item 5)." -Level ERROR }
        else { Write-Log "Operations LDAP anonymes interdites (comportement par defaut)." -Level OK }
        if ($st.AdminSDExMask -notin @('0', [char]'0')) { Write-Log ("AdminSDExMask = {0} : certains groupes d'operateurs ne sont plus proteges par AdminSDHolder." -f $st.AdminSDExMask) -Level WARN }
    } catch {
        Write-Log ("Lecture de dSHeuristics impossible : {0}" -f $_.Exception.Message) -Level ERROR
    }

    $dcs = @(Get-ReachableDCs)
    if ($dcs.Count -eq 0) { return }
    $rows = @(foreach ($dc in $dcs) {
        try {
            Invoke-OnDC -ComputerName $dc.HostName -ScriptBlock {
                $p = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -ErrorAction SilentlyContinue
                [PSCustomObject]@{ DC = $env:COMPUTERNAME; LDAPServerIntegrity = $p.LDAPServerIntegrity; LdapEnforceChannelBinding = $p.LdapEnforceChannelBinding }
            } -ErrorAction Stop
        } catch { Write-Log ("Lecture impossible sur {0} : {1}" -f $dc.HostName, $_.Exception.Message) -Level WARN }
    })
    foreach ($r in $rows) {
        $ok = ($r.LDAPServerIntegrity -eq 2) -and ($r.LdapEnforceChannelBinding -ge 1)
        Write-Host ("  - {0} : signature LDAP exigee={1}, channel binding={2}" -f $r.DC, ($r.LDAPServerIntegrity -eq 2), $(if ($null -eq $r.LdapEnforceChannelBinding) { '0 (non defini)' } else { $r.LdapEnforceChannelBinding })) -ForegroundColor $(if ($ok) { 'Green' } else { 'Yellow' })
    }
    [void](Export-Report -Rows $rows -Name "Rapport_ConfigLDAP_DC")
}

function Invoke-Remediate8RestrictAnonymousLdap {
    Write-Section "Interdire les operations LDAP anonymes (dSHeuristics)" Red
    Write-Info "Depuis Windows Server 2003, les operations LDAP anonymes (hors rootDSE) sont INTERDITES" `
               "par defaut. Elles ne sont autorisees que si le 7e caractere de dSHeuristics vaut '2'" `
               "(KB326690). Cette action remet ce caractere a '0' (comportement par defaut)." `
               "Risque : casse les applications qui s'appuient sciemment sur un acces LDAP anonyme."

    try { $st = Get-DsHeuristicsState } catch {
        Write-Log ("Impossible de lire dSHeuristics : {0}" -f $_.Exception.Message) -Level ERROR
        return
    }
    Write-Host ("Valeur actuelle de dSHeuristics : {0}" -f $(if ($st.Value) { $st.Value } else { '(vide - valeurs par defaut)' })) -ForegroundColor Yellow

    if (-not $st.AnonymousLdap) {
        Write-Log "Les operations LDAP anonymes sont deja interdites (7e caractere different de '2') : rien a faire." -Level OK
        return
    }

    $chars = $st.Value.ToCharArray()
    $chars[6] = '0'
    $newValue = -join $chars
    # Valeur 'neutre' (que des 0 sans caractere de controle) : vider l'attribut = comportement par defaut.
    if ($newValue.Length -lt 10 -and $newValue -match '^0+$') { $newValue = $null }

    if (-not (Confirm-Action ("Positionner dSHeuristics = '{0}' (operations LDAP anonymes interdites)" -f $(if ($newValue) { $newValue } else { '(vide)' })) -Strong)) { return }

    Invoke-Guarded -Description "Mise a jour de dSHeuristics" -Action {
        if ($newValue) { Set-ADObject -Identity $st.DN -Replace @{ dSHeuristics = $newValue } }
        else { Set-ADObject -Identity $st.DN -Clear dSHeuristics }
    }
    Write-OutcomeLog "Propagation vers tous les DC de la foret par la replication AD standard." -Level INFO
}

# ============================================================
#  THEME 8 - CONTROLEURS DE DOMAINE
# ============================================================

function Invoke-ReportDCHotfixes {
    Write-Section "Rapport : correctifs installes sur les DC" Magenta
    Write-Info "Interroge chaque DC (WMI) et signale ceux dont le dernier correctif date de plus de 45 jours" `
               "(cycle mensuel Microsoft manque). La date d'installation peut etre absente pour certains" `
               "correctifs : l'indicateur repose sur la plus recente disponible."
    $dcs = @(Get-DomainControllersList)
    $rows = [System.Collections.Generic.List[object]]::new()
    $summary = [System.Collections.Generic.List[object]]::new()
    foreach ($dc in $dcs) {
        try {
            $hf = @(Get-HotFix -ComputerName $dc.HostName -ErrorAction Stop)
            foreach ($h in $hf) { $rows.Add([PSCustomObject]@{ DC = $dc.HostName; HotFixID = $h.HotFixID; Description = $h.Description; InstalledOn = $h.InstalledOn }) }
            $last = ($hf | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn
            $summary.Add([PSCustomObject]@{ DC = $dc.HostName; OS = $dc.OperatingSystem; Correctifs = $hf.Count; DernierCorrectif = $last })
            $color = if (-not $last -or $last -lt (Get-Date).AddDays(-45)) { 'Yellow' } else { 'Green' }
            Write-Host ("  - {0} ({1}) : {2} correctif(s), dernier le {3}" -f $dc.HostName, $dc.OperatingSystem, $hf.Count, $(if ($last) { $last.ToString('dd/MM/yyyy') } else { 'inconnu' })) -ForegroundColor $color
        } catch {
            Write-Log ("Impossible de lire les correctifs de {0} : {1}" -f $dc.HostName, $_.Exception.Message) -Level WARN
        }
    }
    $late = @($summary | Where-Object { -not $_.DernierCorrectif -or $_.DernierCorrectif -lt (Get-Date).AddDays(-45) })
    if ($late.Count -gt 0) { Write-Log ("{0} DC sans correctif depuis plus de 45 jours (ou date inconnue)." -f $late.Count) -Level WARN }
    [void](Export-Report -Rows $summary -Name "Rapport_Hotfix_Synthese")
    [void](Export-Report -Rows $rows -Name "Rapport_Hotfix_Detail")
}

function Invoke-Audit9TimeSyncStatus {
    Write-Section "Etat de la synchronisation horaire (NTP) sur les DC" Magenta
    Write-Info "Le PDC Emulator du domaine RACINE de la foret doit se synchroniser sur une source externe" `
               "fiable (Type=NTP) ; tous les autres DC suivent la hierarchie du domaine (Type=NT5DS)." `
               "Sur un DC virtualise, la synchronisation avec l'hote (VMICTimeProvider) doit etre coupee."

    $dcs = @(Get-ReachableDCs)
    if ($dcs.Count -eq 0) { return }
    $pdc = (Get-CachedADDomain).PDCEmulator
    $isRootDomain = ((Get-CachedADForest).RootDomain -ieq (Get-CachedADDomain).DNSRoot)

    $rows = @(foreach ($dc in $dcs) {
        try {
            $r = Invoke-OnDC -ComputerName $dc.HostName -ScriptBlock {
                $p = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -ErrorAction SilentlyContinue
                $vmic = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\VMICTimeProvider" -ErrorAction SilentlyContinue
                [PSCustomObject]@{
                    Source    = (& w32tm.exe /query /source 2>&1 | Out-String).Trim()
                    Type      = $p.Type
                    NtpServer = $p.NtpServer
                    VMIC      = $vmic.Enabled
                }
            } -ErrorAction Stop
            $isPdc = $dc.HostName -ieq $pdc
            $issues = @()
            if ($isPdc -and $isRootDomain) {
                if ($r.Type -notin @('NTP', 'AllSync')) { $issues += "PDC racine non configure en NTP externe (Type=$($r.Type))" }
                if ($r.Source -match 'Local CMOS Clock|Horloge CMOS|Free-running|Free running|VM IC Time') { $issues += "source = horloge locale/hote" }
            } elseif ($r.Type -ne 'NT5DS') {
                $issues += "Type=$($r.Type) (NT5DS attendu : hierarchie du domaine)"
            }
            if ($r.VMIC -eq 1 -and $r.Source -match 'VM IC Time') { $issues += "synchronisation sur l'hote de virtualisation" }
            [PSCustomObject]@{ DC = $dc.HostName; PDC = $isPdc; Type = $r.Type; Source = $r.Source; NtpServer = $r.NtpServer; VMICActif = $r.VMIC; Anomalies = $issues -join ' ; ' }
        } catch {
            Write-Log ("Impossible d'interroger w32time sur {0} : {1}" -f $dc.HostName, $_.Exception.Message) -Level WARN
        }
    })
    foreach ($r in $rows) {
        Write-Host ("  - {0}{1} : Type={2}, source={3}{4}" -f $r.DC, $(if ($r.PDC) { ' (PDC)' } else { '' }), $r.Type, $r.Source, $(if ($r.Anomalies) { " -> $($r.Anomalies)" } else { '' })) -ForegroundColor $(if ($r.Anomalies) { 'Yellow' } else { 'Green' })
    }
    if (@($rows | Where-Object Anomalies).Count -gt 0) { Write-Log "Anomalie(s) de synchronisation horaire : un ecart > 5 min fait echouer Kerberos (item 9 pour le PDC)." -Level WARN }
    [void](Export-Report -Rows $rows -Name "Rapport_SynchroHoraire")
}

function Invoke-Remediate9ConfigurePdcTimeSource {
    Write-Section "Configurer la source NTP externe du PDC Emulator" Red
    Write-Info "S'applique uniquement au PDC Emulator (les autres DC se synchronisent sur la hierarchie" `
               "du domaine, ce qui est correct). Note : si une GPO 'Serveur de temps Windows' cible le" `
               "PDC, elle l'emportera sur cette configuration locale."

    $pdc = (Get-CachedADDomain).PDCEmulator
    if ((Get-CachedADForest).RootDomain -ine (Get-CachedADDomain).DNSRoot) {
        Write-Log "Ce domaine n'est pas le domaine racine de la foret : son PDC doit normalement suivre la hierarchie (NT5DS). Action deconseillee." -Level WARN
        if (-not (Read-YesNo -Prompt "Continuer malgre tout ?")) { return }
    }
    $ntpServers = Read-Host "Serveurs NTP externes (separes par une virgule) [defaut 0.fr.pool.ntp.org,1.fr.pool.ntp.org]"
    if ([string]::IsNullOrWhiteSpace($ntpServers)) { $ntpServers = "0.fr.pool.ntp.org,1.fr.pool.ntp.org" }
    # Flag 0x8 = mode client NTP standard (recommande pour des serveurs publics).
    $peerList = (@($ntpServers -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | ForEach-Object { if ($_ -match ',0x') { $_ } else { "$_,0x8" } })) -join ' '

    if (-not (Confirm-Action ("Configurer {0} (PDC Emulator) pour se synchroniser sur : {1}" -f $pdc, $peerList) -Strong)) { return }

    Invoke-Guarded -Description ("Configuration NTP sur {0}" -f $pdc) -Action {
        Invoke-OnDC -ComputerName $pdc -ScriptBlock {
            param($peers)
            & w32tm.exe /config /manualpeerlist:"$peers" /syncfromflags:manual /reliable:yes /update | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "w32tm /config a echoue (code $LASTEXITCODE)." }
            $vmic = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\VMICTimeProvider"
            if (Test-Path $vmic) { Set-ItemProperty -Path $vmic -Name Enabled -Value 0 -Type DWord }
            Restart-Service w32time -Force -ErrorAction Stop
            & w32tm.exe /resync /force | Out-Null
        } -ArgumentList $peerList -ErrorAction Stop
    }
    Write-OutcomeLog "Configuration appliquee. Verifiez apres quelques minutes avec 'w32tm /query /status' sur le PDC (et l'ouverture du port UDP 123 sortant)."
}

function Invoke-Audit9InstalledRoles {
    Write-Section "Roles et fonctionnalites installes sur les DC" Magenta
    Write-Info "Lecture seule : signale les ROLES/SERVICES DE ROLE hors socle DC (AD DS, DNS, services de" `
               "fichiers de base) et une liste de FONCTIONNALITES a risque. Les fonctionnalites installees" `
               "par defaut (.NET, Defender, PowerShell...) ne sont plus signalees (faux positifs)."

    $dcs = @(Get-ReachableDCs)
    if ($dcs.Count -eq 0) { return }

    $expectedRoles = @('AD-Domain-Services', 'DNS', 'FileAndStorage-Services', 'File-Services', 'FS-FileServer', 'Storage-Services', 'FS-DFS-Replication', 'FS-DFS-Namespace')
    $riskyFeatures = @('PowerShell-V2', 'FS-SMB1', 'FS-SMB1-CLIENT', 'FS-SMB1-SERVER', 'Telnet-Client', 'TFTP-Client', 'Web-Server', 'Web-Ftp-Server', 'Print-Services', 'Remote-Desktop-Services', 'Hyper-V', 'DHCP', 'ADCS-Cert-Authority', 'ADFS-Federation', 'WDS', 'UpdateServices', 'NPAS', 'RemoteAccess', 'Fax')
    $rows = @(foreach ($dc in $dcs) {
        try {
            Invoke-OnDC -ComputerName $dc.HostName -ScriptBlock {
                param($expected, $risky)
                Get-WindowsFeature | Where-Object { $_.InstallState -eq 'Installed' -and (
                    (($_.FeatureType -in 'Role', 'Role Service') -and $_.Name -notin $expected -and $_.Name -notlike 'RSAT*') -or ($_.Name -in $risky)) } |
                    Select-Object @{N='DC';E={$env:COMPUTERNAME}}, Name, DisplayName, FeatureType
            } -ArgumentList $expectedRoles, $riskyFeatures -ErrorAction Stop
        } catch {
            Write-Log ("Impossible de lire les roles installes sur {0} : {1}" -f $dc.HostName, $_.Exception.Message) -Level WARN
        }
    })

    if ($rows.Count -eq 0) { Write-Log "Aucun role/fonctionnalite a risque hors du socle DC standard detecte." -Level OK; return }
    Write-ListPreview -Items $rows -Color Yellow -Format { param($r) "{0} : {1} ({2})" -f $r.DC, $r.DisplayName, $r.FeatureType } -Max 40
    [void](Export-Report -Rows ($rows | Select-Object DC, Name, DisplayName, FeatureType) -Name "Rapport_RolesInstalles" -Comment "Un DC doit rester dedie : AD CS, IIS, RDS, DHCP... augmentent sa surface d'attaque (a migrer si possible).")
}

function Invoke-SafeEnableWinRmViaGPO {
    <#
        Active PowerShell Remoting (WinRM) sur les DC via une GPO liee a l'OU Domain
        Controllers : fonctionne MEME SI WinRM est actuellement desactive sur la cible
        (GPO recuperee via SYSVOL/LDAP). Prise en compte : prochain rafraichissement de
        GPO puis redemarrage du service WinRM (ou du serveur).
    #>
    if (-not (Test-GroupPolicyModule)) { return }

    $gpoName = "SEC - Activation WinRM sur les DC"
    $ouDCs = Get-DomainControllersOU

    if (-not (Confirm-Action ("Creer/lier la GPO '{0}' sur l'OU Domain Controllers (service WinRM + listener + regle de pare-feu)" -f $gpoName))) { return }

    Invoke-Guarded -Description "Creation/MAJ GPO activation WinRM" -Action {
        $null = Get-OrCreateGpo -Name $gpoName
        # Demarrage automatique du service WinRM (Preferences de strategie de groupe - registre).
        Set-GPPrefRegistryValue -Name $gpoName -Context Computer -Key "HKLM\SYSTEM\CurrentControlSet\Services\WinRM" -ValueName "Start" -Type DWord -Value 2 -Action Update | Out-Null
        # "Autoriser la gestion a distance du serveur via WinRM" : cree le listener HTTP.
        $k = "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
        Set-GPRegistryValue -Name $gpoName -Key $k -ValueName "AllowAutoConfig" -Type DWord -Value 1 | Out-Null
        Set-GPRegistryValue -Name $gpoName -Key $k -ValueName "IPv4Filter" -Type String -Value "*" | Out-Null
        Set-GPRegistryValue -Name $gpoName -Key $k -ValueName "IPv6Filter" -Type String -Value "*" | Out-Null

        try {
            $gpoSession = Open-NetGPO -PolicyStore ("{0}\{1}" -f (Get-CachedADDomain).DNSRoot, $gpoName) -ErrorAction Stop
            if (-not (Get-NetFirewallRule -GPOSession $gpoSession -Name "SEC-WINRM-HTTP-In-TCP" -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule -GPOSession $gpoSession -Name "SEC-WINRM-HTTP-In-TCP" -DisplayName "Windows Remote Management (HTTP-In) - SEC" -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow -Profile Domain, Private -Enabled True | Out-Null
            }
            Save-NetGPO -GPOSession $gpoSession
        } catch {
            Write-Log ("Regle de pare-feu non creee automatiquement : {0}. A activer manuellement dans la GPO (Pare-feu Windows avec fonctions avancees > Regles de trafic entrant > groupe predefini 'Gestion a distance de Windows')." -f $_.Exception.Message) -Level WARN
        }
        Add-GpoLinkSafe -Name $gpoName -Targets $ouDCs
    }
    Write-OutcomeLog "GPO liee sur l'OU Domain Controllers. Prise en compte au prochain gpupdate de chaque DC, puis redemarrage du service WinRM (ou du serveur)." -Level WARN
}

function Invoke-SafeEnableWinRmViaWmi {
    <#
        Active WinRM IMMEDIATEMENT sur les DC indiques, via WMI/DCOM (RPC) plutot que via
        WinRM lui-meme. Attente active (jusqu'a 60 s) de la disponibilite effective.
    #>
    param([Parameter(Mandatory)][string[]]$ComputerNames)

    foreach ($name in $ComputerNames) {
        Invoke-Guarded -Description ("Activation immediate de WinRM sur {0} via WMI/DCOM" -f $name) -Action {
            $cim = New-CimSession -ComputerName $name -SessionOption (New-CimSessionOption -Protocol Dcom) -ErrorAction Stop
            try {
                foreach ($cmd in @('cmd.exe /c winrm.cmd quickconfig -quiet -force', 'powershell.exe -NoProfile -Command "Enable-NetFirewallRule -Name WINRM-HTTP-In-TCP,WINRM-HTTP-In-TCP-PUBLIC -ErrorAction SilentlyContinue"')) {
                    $r = Invoke-CimMethod -CimSession $cim -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd } -ErrorAction Stop
                    if ($r.ReturnValue -ne 0) { throw "Lancement distant refuse (code $($r.ReturnValue)) : $cmd" }
                }
            } finally {
                Remove-CimSession -CimSession $cim
            }
            $deadline = (Get-Date).AddSeconds(60)
            $ok = $false
            while (-not $ok -and (Get-Date) -lt $deadline) {
                Start-Sleep -Seconds 5
                $ok = [bool](Test-WSMan -ComputerName $name -ErrorAction SilentlyContinue)
            }
            if (-not $ok) { throw "WinRM reste injoignable sur $name apres 60 s (commande lancee, resultat non confirme)." }
        }
    }
}

function Invoke-SafeEnableWinRmOnDCs {
    Write-Section "Activer PowerShell Remoting (WinRM) sur les controleurs de domaine" Cyan
    Write-Info "Impact : AUCUN sur l'existant. Active uniquement la gestion a distance, necessaire pour" `
               "les actions distantes de ce script (auditpol, audit NTLM, Spooler, LDAP, NTP...)."

    $dcs = @(Get-DomainControllersList)
    if ($dcs.Count -eq 0) { return }

    $wr = Test-WinRmConnectivity -ComputerNames @($dcs | ForEach-Object { $_.HostName })
    if ($wr.Unreachable.Count -eq 0) {
        Write-Log "WinRM est deja joignable sur tous les DC." -Level OK
        return
    }

    Write-Host ("DC actuellement INJOIGNABLES en WinRM : {0}" -f ($wr.Unreachable -join ', ')) -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Deux methodes disponibles (non exclusives) :" -ForegroundColor Yellow
    Write-Info "  [1] Via GPO (recommande) : fonctionne meme si WinRM est totalement a l'arret (diffusion" `
               "      par SYSVOL/LDAP). Prise en compte DIFFEREE : gpupdate + redemarrage du service WinRM." `
               "  [2] Immediate via WMI/DCOM : active WinRM tout de suite, si WMI/DCOM (RPC) est joignable." `
               "  [3] Les deux."
    $method = Read-Host "Methode a utiliser [1/2/3] (defaut 1)"
    if ([string]::IsNullOrWhiteSpace($method)) { $method = "1" }

    if ($method -in @("1", "3")) { Invoke-SafeEnableWinRmViaGPO }

    if ($method -in @("2", "3")) {
        if (-not (Confirm-Action ("Tenter l'activation IMMEDIATE de WinRM via WMI/DCOM sur : {0}" -f ($wr.Unreachable -join ', ')))) { return }
        Invoke-SafeEnableWinRmViaWmi -ComputerNames $wr.Unreachable
        if (-not $Script:SimulationMode) {
            $recheck = Test-WinRmConnectivity -ComputerNames $wr.Unreachable
            if ($recheck.Unreachable.Count -eq 0) {
                Write-Log "WinRM est maintenant joignable sur tous les DC precedemment injoignables." -Level OK
            } else {
                Write-Log ("Toujours injoignables : {0}. WMI/DCOM peut etre bloque par le pare-feu, ou le compte manque de droits sur ces DC." -f ($recheck.Unreachable -join ', ')) -Level WARN
            }
        }
    }
}

function Invoke-SafeDisableGuest {
    Write-Section "Desactivation du compte Invite (Guest)" Cyan
    Write-Info "Impact : AUCUN si le compte Invite n'est pas utilise en production (cas normal)."
    try {
        $guest = Get-ADUser -Identity ("{0}-501" -f (Get-CachedADDomain).DomainSID.Value) -Properties Enabled -ErrorAction Stop
    } catch {
        Write-Log "Compte Invite introuvable ou inaccessible : $($_.Exception.Message)" -Level ERROR
        return
    }
    if (-not $guest.Enabled) { Write-Log "Le compte Invite est deja desactive." -Level OK; return }

    Write-Host ("Compte trouve (ACTIF) : {0}" -f $guest.SamAccountName) -ForegroundColor Yellow
    if (Confirm-Action "Desactiver le compte Invite (Guest)") {
        Invoke-Guarded -Description "Disable-ADAccount sur le compte Invite" -Action {
            Disable-ADAccount -Identity $guest.DistinguishedName
        }
    }
}

function Invoke-SafeProtectOUs {
    Write-Section "Protection des OU contre la suppression accidentelle" Cyan
    Write-Info "Impact : AUCUN sur les droits d'acces existants. Ajoute uniquement une ACE 'Refuser la" `
               "suppression' (une OU protegee devra etre deprotegee avant d'etre deplacee/supprimee)."

    $ous = @(Get-ADOrganizationalUnit -Filter * -Properties ProtectedFromAccidentalDeletion | Where-Object { -not $_.ProtectedFromAccidentalDeletion })
    if ($ous.Count -eq 0) { Write-Log "Toutes les OU sont deja protegees contre la suppression accidentelle." -Level OK; return }

    Write-Host ("{0} OU non protegee(s) :" -f $ous.Count) -ForegroundColor Yellow
    Write-ListPreview -Items $ous -Format { param($o) $o.DistinguishedName } -Max 40

    if (Confirm-Action ("Proteger ces {0} OU contre la suppression accidentelle" -f $ous.Count)) {
        foreach ($ou in $ous) {
            Invoke-Guarded -Description ("Protection de l'OU {0}" -f $ou.DistinguishedName) -Action {
                Set-ADObject -Identity $ou.DistinguishedName -ProtectedFromAccidentalDeletion $true
            }
        }
    }
}

function Invoke-SafeSetMachineAccountQuotaZero {
    Write-Section "Limitation du quota de creation d'ordinateurs (ms-DS-MachineAccountQuota)" Cyan
    Write-Info "Impact : AUCUN sur les machines deja jointes. Empeche les utilisateurs STANDARDS de joindre" `
               "eux-memes de nouvelles machines (10 par defaut) - vecteur d'attaques RBCD/relais connu." `
               "Si le support joint des postes avec des comptes non-admin, deleguez-lui d'abord le droit" `
               "'Creer des objets Ordinateur' sur l'UO des postes."

    try {
        $domainDN = (Get-CachedADDomain).DistinguishedName
        $current = (Get-ADObject -Identity $domainDN -Properties "ms-DS-MachineAccountQuota" -ErrorAction Stop)."ms-DS-MachineAccountQuota"
    } catch {
        Write-Log "Impossible de lire ms-DS-MachineAccountQuota : $($_.Exception.Message)" -Level ERROR
        return
    }

    Write-Host ("Valeur actuelle : {0}" -f $current) -ForegroundColor Yellow
    if ($current -eq 0) { Write-Log "Le quota est deja a 0." -Level OK; return }

    $recent = @(Get-ADComputer -LDAPFilter "(ms-DS-CreatorSID=*)" -Properties 'ms-DS-CreatorSID', whenCreated -ErrorAction SilentlyContinue | Where-Object { $_.whenCreated -gt (Get-Date).AddDays(-90) })
    if ($recent.Count -gt 0) {
        Write-Log ("{0} machine(s) jointe(s) via le quota utilisateur ces 90 derniers jours : identifiez ce processus avant de le couper." -f $recent.Count) -Level WARN
    }

    if (Confirm-Action "Mettre ms-DS-MachineAccountQuota a 0 (jonction au domaine reservee aux comptes autorises)") {
        Invoke-Guarded -Description "Set-ADObject ms-DS-MachineAccountQuota = 0" -Action {
            Set-ADObject -Identity $domainDN -Replace @{ "ms-DS-MachineAccountQuota" = 0 }
        }
    }
}

function Invoke-RiskyDisableSpoolerOnDCs {
    Write-Section "Arret et desactivation du service Spooler sur les controleurs de domaine" Red
    Write-Info "Risque : si un DC est utilise (a tort) comme serveur d'impression PARTAGE, les postes clients" `
               "perdront l'acces a ses imprimantes. Les imprimantes virtuelles locales (PDF, XPS, OneNote," `
               "Fax) ne sont pas un usage serveur d'impression : elles ne declenchent pas d'alerte."

    $dcs = @(Get-ReachableDCs)
    if ($dcs.Count -eq 0) { return }

    Write-Host ""
    Write-Host "Verification prealable : imprimantes et etat du Spooler sur chaque DC..." -ForegroundColor DarkGray
    $virtualRegex = 'Microsoft (Print to PDF|XPS Document Writer)|OneNote|^Fax$|Send To OneNote'
    $report = @{}
    foreach ($dc in $dcs) {
        try {
            $info = Invoke-OnDC -ComputerName $dc.HostName -ScriptBlock {
                $svc = Get-Service -Name Spooler -ErrorAction SilentlyContinue
                $printers = @()
                if ($svc -and $svc.Status -eq 'Running') { $printers = @(Get-Printer -ErrorAction Stop | Select-Object Name, Shared, PortName, DriverName) }
                [PSCustomObject]@{ Status = [string]$svc.Status; StartType = [string]$svc.StartType; Printers = $printers }
            } -ErrorAction Stop
            $real = @($info.Printers | Where-Object { $_.Shared -or $_.Name -notmatch $virtualRegex })
            $report[$dc.HostName] = @{ Ok = $true; Info = $info; Real = $real }
            $color = if ($real.Count -gt 0) { 'Yellow' } elseif ($info.Status -eq 'Running') { 'Gray' } else { 'Green' }
            Write-Host ("  {0} : Spooler {1} ({2}), {3} imprimante(s) reelle(s)/partagee(s)" -f $dc.HostName, $info.Status, $info.StartType, $real.Count) -ForegroundColor $color
        } catch {
            Write-Log ("Impossible de verifier les imprimantes sur {0} : {1}" -f $dc.HostName, $_.Exception.Message) -Level WARN
            $report[$dc.HostName] = @{ Ok = $false; Real = @() }
        }
    }

    $todo = @($dcs | Where-Object { -not ($report[$_.HostName].Ok -and $report[$_.HostName].Info.Status -eq 'Stopped' -and $report[$_.HostName].Info.StartType -eq 'Disabled') })
    if ($todo.Count -eq 0) { Write-Log "Le Spooler est deja arrete et desactive sur tous les DC joignables." -Level OK; return }

    if (-not (Confirm-Action ("Arreter et desactiver le service Spooler sur {0} DC (verification imprimante par DC ci-apres)" -f $todo.Count) -Strong)) { return }

    foreach ($dc in $todo) {
        $info = $report[$dc.HostName]
        if (-not $info.Ok) {
            Write-Host ("Attention : impossible de verifier si {0} sert aussi de serveur d'impression." -f $dc.HostName) -ForegroundColor Yellow
            if (-not (Read-YesNo -Prompt ("Arreter quand meme le Spooler sur {0}, sans certitude ?" -f $dc.HostName))) {
                Write-Log ("Arret du Spooler ignore sur {0} (verification impossible, non confirme)." -f $dc.HostName) -Level WARN
                continue
            }
        } elseif ($info.Real.Count -gt 0) {
            Write-Host ""
            Write-Host ("!!! IMPRIMANTE(S) REELLE(S)/PARTAGEE(S) SUR {0} !!!" -f $dc.HostName) -ForegroundColor White -BackgroundColor DarkRed
            $info.Real | ForEach-Object { Write-Host ("    - {0} (partagee : {1}, port : {2})" -f $_.Name, $_.Shared, $_.PortName) }
            Write-Host "  Arreter le Spooler coupera l'acces a ces imprimantes pour les postes clients." -ForegroundColor Yellow
            if ((Read-Host ("Tapez ARRETER pour confirmer l'arret sur {0}" -f $dc.HostName)) -cne "ARRETER") {
                Write-Log ("Arret du Spooler ANNULE sur {0} (imprimante(s) detectee(s), non confirme)." -f $dc.HostName) -Level WARN
                continue
            }
        }

        Invoke-Guarded -Description ("Arret + desactivation du Spooler sur {0}" -f $dc.HostName) -Action {
            Invoke-OnDC -ComputerName $dc.HostName -ScriptBlock {
                Stop-Service -Name Spooler -Force -ErrorAction Stop
                Set-Service -Name Spooler -StartupType Disabled -ErrorAction Stop
            } -ErrorAction Stop
        }
    }
}

function Invoke-Remediate9EnableFirewallBaseline {
    Write-Section "Activer le pare-feu Windows (3 profils) sur les DC via GPO" Red
    Write-Info "Risque : si des flux legitimes ne sont pas couverts par les regles predefinies actives (ou" `
               "par vos regles personnalisees), ils seront bloques. Testez sur un DC pilote." `
               "La restriction de l'acces Internet des DC releve du pare-feu perimetrique/proxy : un" `
               "blocage sortant local mal cible casse Windows Update, CRL/OCSP ou NTP (non automatise)."

    if (-not (Test-GroupPolicyModule)) { return }

    $gpoName = "SEC - Pare-feu Windows actif (DC)"
    if (-not (Confirm-Action ("Creer/lier la GPO '{0}' sur l'OU Domain Controllers (pare-feu actif, entrant bloque par defaut, 3 profils)" -f $gpoName) -Strong)) { return }

    Invoke-Guarded -Description ("Creation/MAJ de la GPO {0}" -f $gpoName) -Action {
        $null = Get-OrCreateGpo -Name $gpoName
        Set-FirewallProfilesInGpo -GpoName $gpoName
        Add-GpoLinkSafe -Name $gpoName -Targets (Get-DomainControllersOU)
    }
    Write-OutcomeLog "GPO liee sur l'OU Domain Controllers. Verifiez que les regles predefinies necessaires (AD DS, DNS, DFSR, Kerberos, RPC...) sont actives avant redemarrage des DC." -Level WARN
}

function Set-FirewallProfilesInGpo {
    param([Parameter(Mandatory)][string]$GpoName)
    foreach ($fwProfile in @('DomainProfile', 'PrivateProfile', 'PublicProfile')) {
        $key = "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\$fwProfile"
        Set-GPRegistryValue -Name $GpoName -Key $key -ValueName "EnableFirewall" -Type DWord -Value 1 | Out-Null
        Set-GPRegistryValue -Name $GpoName -Key $key -ValueName "DefaultInboundAction" -Type DWord -Value 1 | Out-Null
        Set-GPRegistryValue -Name $GpoName -Key $key -ValueName "DefaultOutboundAction" -Type DWord -Value 0 | Out-Null
        Set-GPRegistryValue -Name $GpoName -Key "$key\Logging" -ValueName "LogDroppedPackets" -Type DWord -Value 1 | Out-Null
    }
}

function Invoke-Audit9DCHardeningMatrix {
    Write-Section "Matrice de durcissement des DC (une passe sur tous les DC)" Magenta
    Write-Info "Lecture seule, sur chaque DC joignable : OS, dernier demarrage, Spooler, SMBv1, signature" `
               "SMB, signature LDAP / channel binding, LmCompatibilityLevel, pare-feu, journal Securite."

    $dcs = @(Get-ReachableDCs)
    if ($dcs.Count -eq 0) { return }
    $rows = @(foreach ($dc in $dcs) {
        try {
            $r = Invoke-OnDC -ComputerName $dc.HostName -ScriptBlock {
                $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
                $spool = Get-Service Spooler -ErrorAction SilentlyContinue
                $smb = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
                $ntds = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -ErrorAction SilentlyContinue
                $lsa = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue
                $fw = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Name })
                $secLog = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
                [PSCustomObject]@{
                    DC                 = $env:COMPUTERNAME
                    OS                 = $os.Caption
                    DernierDemarrage   = $os.LastBootUpTime
                    Spooler            = "{0}/{1}" -f $spool.Status, $spool.StartType
                    SMB1               = $smb.EnableSMB1Protocol
                    SignatureSMB       = $smb.RequireSecuritySignature
                    SignatureLDAP      = $ntds.LDAPServerIntegrity
                    ChannelBinding     = $ntds.LdapEnforceChannelBinding
                    LmCompatibility    = $lsa.LmCompatibilityLevel
                    ProfilsFWInactifs  = $fw -join ','
                    JournalSecuriteMo  = if ($secLog) { [int]($secLog.MaximumSizeInBytes / 1MB) } else { $null }
                }
            } -ErrorAction Stop
            $issues = @()
            if ($r.Spooler -like 'Running*') { $issues += 'Spooler actif' }
            if ($r.SMB1) { $issues += 'SMBv1' }
            if (-not $r.SignatureSMB) { $issues += 'signature SMB non exigee' }
            if ($r.SignatureLDAP -ne 2) { $issues += 'signature LDAP non exigee' }
            if (-not $r.ChannelBinding) { $issues += 'channel binding LDAP inactif' }
            if ([string]$r.LmCompatibility -ne '5') { $issues += "LmCompatibilityLevel=$(if ($null -eq $r.LmCompatibility) { '3 (defaut)' } else { $r.LmCompatibility })" }
            if ($r.ProfilsFWInactifs) { $issues += "pare-feu inactif ($($r.ProfilsFWInactifs))" }
            if ($r.JournalSecuriteMo -and $r.JournalSecuriteMo -lt 1024) { $issues += "journal Securite $($r.JournalSecuriteMo) Mo (< 1 Go)" }
            if ($r.DernierDemarrage -and $r.DernierDemarrage -lt (Get-Date).AddDays(-60)) { $issues += 'pas de redemarrage depuis 60 j (correctifs en attente ?)' }
            $r | Add-Member -NotePropertyName Ecarts -NotePropertyValue ($issues -join ' ; ') -PassThru
        } catch { Write-Log ("Lecture impossible sur {0} : {1}" -f $dc.HostName, $_.Exception.Message) -Level WARN }
    })
    foreach ($r in $rows) {
        Write-Host ("  - {0} ({1})" -f $r.DC, $r.OS) -ForegroundColor Cyan
        if ($r.Ecarts) { Write-Host ("      Ecarts : {0}" -f $r.Ecarts) -ForegroundColor Yellow } else { Write-Host "      Aucun ecart sur les points controles." -ForegroundColor Green }
    }
    [void](Export-Report -Rows $rows -Name "Rapport_MatriceDurcissementDC")
}

function Invoke-Audit9ReplicationAndFsmo {
    Write-Section "Sante de la replication, niveaux fonctionnels et roles FSMO" Magenta
    $dom = Get-CachedADDomain
    $forest = Get-CachedADForest
    Write-Host ("Niveau fonctionnel domaine : {0}  |  foret : {1}" -f $dom.DomainMode, $forest.ForestMode) -ForegroundColor Cyan
    Write-Host ("FSMO : PDC={0}, RID={1}, Infrastructure={2}, Schema={3}, Nommage={4}" -f $dom.PDCEmulator, $dom.RIDMaster, $dom.InfrastructureMaster, $forest.SchemaMaster, $forest.DomainNamingMaster) -ForegroundColor Gray
    if ([string]$dom.DomainMode -match '2003|2008|2012Domain$') {
        Write-Log ("Niveau fonctionnel {0} : bloque des protections (Protected Users complet, FAST, chiffrement LAPS...). Visez 2016 apres retrait des DC anciens." -f $dom.DomainMode) -Level WARN
    }

    $dcs = @(Get-DomainControllersList)
    foreach ($dc in $dcs) {
        Write-Host ("  - {0} (site {1}, {2}{3}, GC={4})" -f $dc.HostName, $dc.Site, $dc.OperatingSystem, $(if ($dc.IsReadOnly) { ', RODC' } else { '' }), $dc.IsGlobalCatalog) -ForegroundColor Gray
    }

    $health = Test-ADReplicationHealth
    if ($health.Healthy) { Write-Log "Replication AD saine sur l'ensemble des partenaires du domaine." -Level OK }
    else {
        Write-Log "Replication AD en erreur ou non verifiable :" -Level WARN
        $health.Details | ForEach-Object { Write-Host ("    {0}" -f $_) -ForegroundColor Yellow }
    }
    try {
        $rows = @(Get-ADReplicationPartnerMetadata -Target $dom.DNSRoot -Scope Domain -ErrorAction Stop | Select-Object Server, Partner, Partition, LastReplicationSuccess, LastReplicationResult, ConsecutiveReplicationFailures)
        [void](Export-Report -Rows $rows -Name "Rapport_Replication")
    } catch { }
}

function Get-DCOwnership {
    <#
        Proprietaire de l'objet ordinateur de chaque DC. Attendu : Domain Admins, Enterprise
        Admins, Administrateurs ou SYSTEM. Un autre proprietaire (compte ayant pre-cree ou joint
        le DC) peut modifier l'objet, donc prendre le controle du DC (RBCD, msDS-KeyCredentialLink).
        Legitime = $null si le proprietaire n'a pas pu etre lu (jamais conclu "conforme").
    #>
    $dom = Get-CachedADDomain
    $sid = $dom.DomainSID.Value
    $legit = @("$sid-512", "$(Get-RootDomainSid)-519", 'S-1-5-32-544', 'S-1-5-18')
    return @(foreach ($c in @(Get-ADComputer -LDAPFilter '(|(primaryGroupID=516)(primaryGroupID=521))' -Properties nTSecurityDescriptor -ErrorAction Stop)) {
        $ownerSid = $null
        try { $ownerSid = $c.nTSecurityDescriptor.GetOwner([System.Security.Principal.SecurityIdentifier]).Value } catch { }
        $ownerName = if ($ownerSid) { try { (New-Object System.Security.Principal.SecurityIdentifier($ownerSid)).Translate([System.Security.Principal.NTAccount]).Value } catch { $ownerSid } } else { '(illisible)' }
        [PSCustomObject]@{
            DC           = $c.Name
            Proprietaire = $ownerName
            SID          = $ownerSid
            Legitime     = if ($ownerSid) { $legit -contains $ownerSid } else { $null }
        }
    })
}

function Invoke-Audit9DCOwnership {
    Write-Section "Proprietaires des objets ordinateur des controleurs de domaine" Magenta
    Write-Info "Le proprietaire d'un objet peut toujours modifier ses permissions. Un DC dont l'objet" `
               "appartient a un compte non administrateur (compte de jonction, technicien) est un chemin" `
               "de compromission du domaine. Correction : proprietaire = Admins du domaine."
    try { $rows = @(Get-DCOwnership) } catch {
        Write-Log ("Lecture des proprietaires impossible : {0}" -f $_.Exception.Message) -Level ERROR
        return
    }
    foreach ($r in $rows) {
        $color = if ($r.Legitime -eq $true) { 'Green' } elseif ($r.Legitime -eq $false) { 'Red' } else { 'Yellow' }
        Write-Host ("  - {0} : proprietaire {1}" -f $r.DC, $r.Proprietaire) -ForegroundColor $color
    }
    $bad = @($rows | Where-Object { $_.Legitime -eq $false })
    if ($bad.Count -gt 0) { Write-Log ("{0} DC appartenant a un principal non administrateur : redonnez la propriete a 'Admins du domaine' (onglet Securite > Avance > Proprietaire)." -f $bad.Count) -Level ERROR }
    elseif (@($rows | Where-Object { $null -eq $_.Legitime }).Count -gt 0) { Write-Log "Certains proprietaires n'ont pas pu etre lus : resultat incomplet." -Level WARN }
    else { Write-Log "Tous les objets DC appartiennent a un groupe d'administration." -Level OK }
    [void](Export-Report -Rows $rows -Name "Rapport_ProprietairesDC")
}

# ============================================================
#  THEME 9 - WINDOWS LAPS
# ============================================================

function Test-LapsModuleAvailable {
    if (-not (Get-Module -ListAvailable -Name LAPS)) {
        Write-Log "Le module PowerShell 'LAPS' (Windows LAPS) n'est pas installe sur ce poste (inclus dans Windows Server 2019+/Windows 10-11 a jour depuis avril 2023)." -Level ERROR
        return $false
    }
    Import-Module LAPS -ErrorAction SilentlyContinue
    return $true
}

function Test-SchemaAttribute {
    param([Parameter(Mandatory)][string]$LdapDisplayName)
    try {
        $schemaNC = (Get-ADRootDSE -ErrorAction Stop).schemaNamingContext
        return [bool](Get-ADObject -SearchBase $schemaNC -LDAPFilter "(lDAPDisplayName=$LdapDisplayName)" -ErrorAction Stop)
    } catch { return $false }
}

function Test-LapsSchemaPresent { return (Test-SchemaAttribute -LdapDisplayName 'msLAPS-PasswordExpirationTime') }

function Get-LapsCoverage {
    <#
        Couverture LAPS des ordinateurs Windows ACTIFS (Windows LAPS ou LAPS legacy), et
        detection des mots de passe dont l'expiration est depassee de plus de 7 jours : le
        client LAPS ne fonctionne plus sur ces machines (ou elles sont eteintes).
        Sont EXCLUS du calcul (aucun compte local a gerer -> faux "non couvert") : DC, comptes
        de service geres (gMSA/MSA), objets de cluster (CNO/VCO), compte AZUREADSSOACC et
        machines non-Windows. Ils sont comptes a part (propriete Exclus).
    #>
    $winLaps = Test-LapsSchemaPresent
    $legacy = Test-SchemaAttribute -LdapDisplayName 'ms-Mcs-AdmPwdExpirationTime'
    $props = @('OperatingSystem', 'PrimaryGroupID', 'LastLogonDate', 'ServicePrincipalName')
    if ($winLaps) { $props += 'msLAPS-PasswordExpirationTime' }
    if ($legacy) { $props += 'ms-Mcs-AdmPwdExpirationTime' }
    $excluded = @{}
    $computers = @(Get-ADComputer -Filter 'Enabled -eq $true' -Properties $props | Where-Object {
        $kind = Get-ComputerAccountKind -Computer $_
        if ($kind -eq 'Computer') { $true } else { $excluded[$kind] = 1 + [int]$excluded[$kind]; $false }
    })
    $now = Get-Date
    $rows = @($computers | ForEach-Object {
        $w = if ($winLaps) { ConvertFrom-FileTimeSafe $_.'msLAPS-PasswordExpirationTime' } else { $null }
        $l = if ($legacy) { ConvertFrom-FileTimeSafe $_.'ms-Mcs-AdmPwdExpirationTime' } else { $null }
        $exp = @($w, $l) | Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1
        [PSCustomObject]@{
            Name              = $_.Name
            OS                = $_.OperatingSystem
            DerniereConnexion = $_.LastLogonDate
            LAPS              = if ($w) { 'Windows LAPS' } elseif ($l) { 'LAPS legacy' } else { 'Absent' }
            Expiration        = $exp
            ExpireDepuis7j    = [bool]($exp -and $exp -lt $now.AddDays(-7))
            DN                = $_.DistinguishedName
        }
    })
    return [PSCustomObject]@{ WindowsLapsSchema = $winLaps; LegacySchema = $legacy; Rows = $rows; Exclus = $excluded }
}

function Invoke-Audit10LapsDeployment {
    Write-Section "Etat du deploiement LAPS (schema, couverture, mots de passe perimes)" Magenta

    $cov = Get-LapsCoverage
    if ($cov.WindowsLapsSchema) { Write-Log "Schema Windows LAPS present." -Level OK } else { Write-Log "Schema Windows LAPS ABSENT (item 3)." -Level WARN }
    if ($cov.LegacySchema) { Write-Log "Schema LAPS legacy (ms-Mcs-AdmPwd) present : migration vers Windows LAPS recommandee." -Level INFO }
    if (Get-Module -ListAvailable -Name LAPS) { Write-Log "Module PowerShell LAPS present sur ce poste." -Level OK }
    else { Write-Log "Module PowerShell LAPS absent de ce poste (necessaire pour les remediations dediees)." -Level WARN }

    $rows = @($cov.Rows)
    if ($rows.Count -eq 0) { Write-Log "Aucun ordinateur actif (hors DC) dans le domaine." -Level INFO; return }
    $covered = @($rows | Where-Object { $_.LAPS -ne 'Absent' })
    $stale = @($rows | Where-Object { $_.ExpireDepuis7j })
    $pct = [math]::Round(($covered.Count / $rows.Count) * 100, 1)
    Write-Host ("Couverture LAPS (ordinateurs Windows actifs hors DC) : {0}/{1} ({2} %) - Windows LAPS : {3}, legacy : {4}" -f $covered.Count, $rows.Count, $pct, @($rows | Where-Object LAPS -eq 'Windows LAPS').Count, @($rows | Where-Object LAPS -eq 'LAPS legacy').Count) -ForegroundColor $(if ($pct -ge 95) { 'Green' } else { 'Yellow' })
    if ($cov.Exclus.Count -gt 0) {
        $labels = @{ DC = 'DC'; MSA = 'comptes de service geres'; Cluster = 'objets de cluster'; EntraSSO = 'AZUREADSSOACC'; NonWindows = 'non-Windows' }
        Write-Host ("  Hors perimetre LAPS (non comptes) : {0}" -f (($cov.Exclus.GetEnumerator() | ForEach-Object { "{0} {1}" -f $_.Value, $labels[$_.Key] }) -join ', ')) -ForegroundColor DarkGray
    }
    if ($stale.Count -gt 0) {
        Write-Log ("{0} machine(s) avec un mot de passe LAPS expire depuis plus de 7 jours : client LAPS en echec (droits d'ecriture, GPO non appliquee) ou machine eteinte." -f $stale.Count) -Level WARN
    }
    Write-Info "Note : les DC n'ont pas de compte local ; Windows LAPS peut y sauvegarder le mot de passe DSRM (BackupDirectory=2 + 'Enable password backup for DSRM accounts')."
    [void](Export-Report -Rows $rows -Name "Rapport_LAPS_Couverture")
}

function Invoke-Audit10LapsPermissions {
    Write-Section "Audit des droits de lecture du mot de passe LAPS" Magenta
    if (-not (Test-LapsModuleAvailable)) { return }

    $targetOUs = @(Select-OUsInteractive -Label "l'audit des permissions LAPS" -Verb "CIBLER")
    if ($targetOUs.Count -eq 0) { Write-Log "Aucune UO ciblee, action annulee." -Level WARN; return }

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($ou in $targetOUs) {
        try {
            foreach ($r in @(Find-LapsADExtendedRights -Identity $ou -ErrorAction Stop)) {
                foreach ($holder in @($r.ExtendedRightHolders)) { $rows.Add([PSCustomObject]@{ OU = $r.ObjectDN; Principal = $holder }) }
            }
        } catch {
            Write-Log ("Impossible d'auditer les droits LAPS sur {0} : {1}" -f $ou, $_.Exception.Message) -Level WARN
        }
    }
    if ($rows.Count -eq 0) { Write-Log "Aucun detenteur de droit etendu trouve (ou cmdlet indisponible)." -Level WARN; return }

    $expected = 'SYSTEM|SYST.ME|Domain Admins|Admins du domaine'
    Write-Host "Principaux disposant d'un droit etendu (lecture du mot de passe LAPS) :" -ForegroundColor Yellow
    $rows | Sort-Object Principal -Unique | ForEach-Object {
        Write-Host ("  - {0}" -f $_.Principal) -ForegroundColor $(if ($_.Principal -match $expected) { 'DarkGray' } else { 'Yellow' })
    }
    [void](Export-Report -Rows $rows -Name "Rapport_LAPS_Permissions" -Comment "Comparez avec la liste des groupes qui DEVRAIENT avoir ce droit.")
}

function Invoke-Remediate10PrepareSchema {
    Write-Section "Preparation du schema Active Directory pour Windows LAPS" Red
    Write-Host "Modification du SCHEMA de la foret (irreversible). Necessite Schema Admins, depuis un" -ForegroundColor Yellow
    Write-Host "poste joignant le Schema Master." -ForegroundColor Yellow

    if (-not (Test-LapsModuleAvailable)) { return }
    if (Test-LapsSchemaPresent) { Write-Log "Le schema Windows LAPS est deja present." -Level OK; return }

    if (-not (Confirm-Action "Executer Update-LapsADSchema (modification du schema de la foret)" -Strong)) { return }
    Invoke-Guarded -Description "Update-LapsADSchema" -Action {
        Update-LapsADSchema -Confirm:$false -ErrorAction Stop
    }
}

function Invoke-Remediate10DeployGpo {
    Write-Section "Deploiement de la GPO Windows LAPS" Red
    Write-Info "Cree la GPO de configuration ET accorde aux ordinateurs des UO ciblees le droit d'ecrire" `
               "leur propre mot de passe (Set-LapsADComputerSelfPermission) : sans ce droit, le client" `
               "LAPS echoue silencieusement (evenement 10027) et aucun mot de passe n'est sauvegarde."

    if (-not (Test-GroupPolicyModule)) { return }
    if (-not (Test-LapsSchemaPresent)) {
        Write-Log "Schema Windows LAPS absent : executez d'abord 'Preparer le schema' (item 3)." -Level ERROR
        return
    }

    $length = Read-IntValue -Prompt "Longueur du mot de passe" -Default 20 -Min 14 -Max 64
    $age = Read-IntValue -Prompt "Age maximal du mot de passe en jours" -Default 30 -Min 1 -Max 365
    $hybrid = Read-YesNo -Prompt "Sauvegarder dans Microsoft Entra ID plutot que dans Active Directory (hybride) ?"
    # BackupDirectory : 1 = Entra ID, 2 = Active Directory.
    $backupDirectory = if ($hybrid) { 1 } else { 2 }
    $encrypt = $false
    if (-not $hybrid -and [string](Get-CachedADDomain).DomainMode -match '2016|2025|Windows20[2-9]') {
        $encrypt = Read-YesNo -Prompt "Chiffrer le mot de passe dans l'AD (niveau fonctionnel 2016+) ?" -Default $true
    }

    $targetOUs = @(Select-OUsInteractive -Label "la GPO Windows LAPS" -Verb "CIBLER (lien de la GPO)")
    if ($targetOUs.Count -eq 0) { Write-Log "Aucune UO ciblee, action annulee." -Level WARN; return }
    $selfPerm = $false
    if (-not $hybrid -and (Test-LapsModuleAvailable)) { $selfPerm = Read-YesNo -Prompt "Accorder aux ordinateurs de ces UO le droit d'ecrire leur mot de passe LAPS ?" -Default $true }

    $gpoName = "SEC - Windows LAPS"
    $backupLabel = if ($hybrid) { 'Entra ID' } else { 'Active Directory' }
    if (-not (Confirm-Action ("Creer/MAJ la GPO '{0}' (longueur={1}, age max={2} j, sauvegarde={3}{4}) et la lier sur {5} UO" -f $gpoName, $length, $age, $backupLabel, $(if ($encrypt) { ', chiffre' } else { '' }), $targetOUs.Count) -Strong)) { return }

    if ($selfPerm) {
        foreach ($ou in $targetOUs) {
            Invoke-Guarded -Description ("Droit d'auto-mise a jour LAPS des ordinateurs de {0}" -f $ou) -Action {
                Set-LapsADComputerSelfPermission -Identity $ou -ErrorAction Stop | Out-Null
            }
        }
    }

    Invoke-Guarded -Description ("Creation/MAJ de la GPO {0}" -f $gpoName) -Action {
        $null = Get-OrCreateGpo -Name $gpoName
        $key = "HKLM\Software\Microsoft\Policies\LAPS"
        Set-GPRegistryValue -Name $gpoName -Key $key -ValueName "BackupDirectory" -Type DWord -Value $backupDirectory | Out-Null
        Set-GPRegistryValue -Name $gpoName -Key $key -ValueName "PasswordComplexity" -Type DWord -Value 4 | Out-Null
        Set-GPRegistryValue -Name $gpoName -Key $key -ValueName "PasswordLength" -Type DWord -Value $length | Out-Null
        Set-GPRegistryValue -Name $gpoName -Key $key -ValueName "PasswordAgeDays" -Type DWord -Value $age | Out-Null
        if ($encrypt) { Set-GPRegistryValue -Name $gpoName -Key $key -ValueName "ADPasswordEncryptionEnabled" -Type DWord -Value 1 | Out-Null }
        Add-GpoLinkSafe -Name $gpoName -Targets $targetOUs
    }
    Write-OutcomeLog "GPO Windows LAPS deployee et liee. Verifiez la couverture (item 1) apres le prochain cycle de GPO des machines ciblees."
}

function Invoke-Remediate10SetPermissions {
    Write-Section "Configuration des droits de lecture/reset du mot de passe LAPS" Red
    Write-Info "Modifie les ACL Active Directory : reservez ce droit au strict necessaire (equipe" `
               "support/securite habilitee), jamais a un groupe large."

    if (-not (Test-LapsModuleAvailable)) { return }

    $targetOUs = @(Select-OUsInteractive -Label "la delegation des droits LAPS" -Verb "CIBLER")
    if ($targetOUs.Count -eq 0) { return }

    $readGroup = Read-Host "Groupe autorise a LIRE le mot de passe LAPS (vide = ne pas modifier ce droit)"
    $resetGroup = Read-Host "Groupe autorise a FORCER le renouvellement du mot de passe LAPS (vide = ne pas modifier ce droit)"
    if ([string]::IsNullOrWhiteSpace($readGroup) -and [string]::IsNullOrWhiteSpace($resetGroup)) { Write-Log "Aucun groupe fourni, action annulee." -Level WARN; return }
    foreach ($g in @($readGroup, $resetGroup) | Where-Object { $_ }) {
        if (-not (Get-ADGroup -Filter "Name -eq '$($g -replace "'", "''")'" -ErrorAction SilentlyContinue)) {
            Write-Log ("Groupe '{0}' introuvable : action annulee." -f $g) -Level ERROR
            return
        }
    }

    $readLabel = if ($readGroup) { $readGroup } else { 'inchange' }
    $resetLabel = if ($resetGroup) { $resetGroup } else { 'inchange' }
    if (-not (Confirm-Action ("Deleguer les droits LAPS sur {0} UO (lecture={1}, reset={2})" -f $targetOUs.Count, $readLabel, $resetLabel) -Strong)) { return }

    foreach ($ou in $targetOUs) {
        if ($readGroup) {
            Invoke-Guarded -Description ("Delegation lecture LAPS sur {0} a {1}" -f $ou, $readGroup) -Action {
                Set-LapsADReadPasswordPermission -Identity $ou -AllowedPrincipals $readGroup -ErrorAction Stop | Out-Null
            }
        }
        if ($resetGroup) {
            Invoke-Guarded -Description ("Delegation reset LAPS sur {0} a {1}" -f $ou, $resetGroup) -Action {
                Set-LapsADResetPasswordPermission -Identity $ou -AllowedPrincipals $resetGroup -ErrorAction Stop | Out-Null
            }
        }
    }
}

# ============================================================
#  THEME 10 - GPO DE DURCISSEMENT (socle GPO-SEC-*)
# ============================================================

$Script:GpoSecBaselineNames = @(
    "GPO-SEC-DomainControllers", "GPO-SEC-Servers", "GPO-SEC-Workstations",
    "GPO-SEC-Authentication", "GPO-SEC-WindowsLAPS", "GPO-SEC-Audit",
    "GPO-SEC-Defender", "GPO-SEC-RDP", "GPO-SEC-Network"
)

function Invoke-Audit12GpoBaselineStatus {
    Write-Section "Etat du socle GPO-SEC-* et des sauvegardes de GPO" Magenta
    if (-not (Test-GroupPolicyModule)) { return }

    $rows = @(foreach ($name in $Script:GpoSecBaselineNames) {
        $gpo = Get-GPO -Name $name -ErrorAction SilentlyContinue
        [PSCustomObject]@{ GPO = $name; Presente = [bool]$gpo; Vide = if ($gpo) { ($gpo.Computer.DSVersion -eq 0 -and $gpo.User.DSVersion -eq 0) } else { $null } }
    })
    foreach ($r in $rows) {
        $txt = if (-not $r.Presente) { 'absente' } elseif ($r.Vide) { 'presente (vide)' } else { 'presente (parametree)' }
        Write-Host ("  - {0} : {1}" -f $r.GPO, $txt) -ForegroundColor $(if ($r.Presente -and -not $r.Vide) { 'Green' } else { 'Yellow' })
    }

    $backupRoot = Join-Path $Script:LogDir "GPO_Backups"
    $lastBackup = if (Test-Path -LiteralPath $backupRoot) { Get-ChildItem -LiteralPath $backupRoot -Directory -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1 }
    if ($lastBackup) { Write-Log ("Derniere sauvegarde de GPO : {0} ({1})" -f $lastBackup.FullName, $lastBackup.LastWriteTime) -Level OK }
    else { Write-Log "Aucune sauvegarde de GPO trouvee dans Logs\GPO_Backups. A faire avant tout changement sensible (item 2)." -Level WARN }

    [void](Export-Report -Rows $rows -Name "Rapport_GPOBaseline")
}

function Invoke-Remediate12BackupAllGpos {
    Write-Section "Sauvegarde de TOUTES les GPO du domaine" Cyan
    Write-Info "Impact : AUCUN (lecture seule des GPO, ecriture uniquement dans Logs\GPO_Backups)." `
               "A faire avant tout changement sensible, pour disposer d'un retour arriere (Restore-GPO)."

    if (-not (Test-GroupPolicyModule)) { return }
    $backupPath = Join-Path (Join-Path $Script:LogDir "GPO_Backups") ("{0}_ToutesGPO" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    if (-not (Confirm-Action ("Sauvegarder toutes les GPO du domaine vers {0}" -f $backupPath))) { return }

    # Lecture seule cote AD : execute meme en mode simulation (aucun risque, utile en audit).
    try {
        New-Item -Path $backupPath -ItemType Directory -Force | Out-Null
        $results = @(Backup-GPO -All -Path $backupPath -ErrorAction Stop)
        Write-Log ("{0} GPO sauvegardee(s) dans {1}." -f $results.Count, $backupPath) -Level OK
    } catch {
        Write-Log ("Echec de la sauvegarde des GPO : {0}" -f $_.Exception.Message) -Level ERROR
    }
}

function Invoke-Remediate12CreateBaselineGpoShells {
    Write-Section "Creation du socle GPO-SEC-* (coquilles vides)" Cyan
    Write-Info "Impact : AUCUN sur l'existant. Cree uniquement les GPO manquantes, SANS parametre et SANS" `
               "lien (donc sans effet tant qu'elles ne sont pas remplies et liees deliberement)."

    if (-not (Test-GroupPolicyModule)) { return }

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

function Invoke-Audit12GpoHygiene {
    Write-Section "Hygiene des GPO (non liees, vides, droits de modification delegues)" Magenta
    Write-Info "- GPO non liees ou vides : bruit, et risque de liaison accidentelle." `
               "- Droit de MODIFIER une GPO accorde a un compte/groupe non administrateur : chemin" `
               "  d'elevation direct (une GPO liee aux DC ou a la racine = controle du domaine)."

    if (-not (Test-GroupPolicyModule)) { return }

    $linked = [System.Collections.Generic.HashSet[string]]::new()
    $linkSources = @(Get-ADObject -LDAPFilter "(gPLink=*)" -Properties gPLink -ErrorAction SilentlyContinue)
    try {
        $sitesDN = "CN=Sites,{0}" -f (Get-ADRootDSE).configurationNamingContext
        $linkSources += @(Get-ADObject -SearchBase $sitesDN -LDAPFilter "(gPLink=*)" -Properties gPLink -ErrorAction SilentlyContinue)
    } catch { }
    foreach ($o in $linkSources) {
        foreach ($m in [regex]::Matches([string]$o.gPLink, '\{([0-9A-Fa-f-]{36})\}')) { [void]$linked.Add($m.Groups[1].Value.ToUpper()) }
    }

    $adminSids = @(
        (Resolve-ADGroupRef 'Domain Admins').Identity, (Resolve-ADGroupRef 'Enterprise Admins').Identity,
        'S-1-5-18', 'S-1-5-9', 'S-1-3-0', 'S-1-5-32-544'
    )
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($gpo in @(Get-GPO -All -ErrorAction SilentlyContinue)) {
        $id = $gpo.Id.ToString().ToUpper()
        $issues = @()
        if (-not $linked.Contains($id)) { $issues += 'non liee' }
        if ($gpo.Computer.DSVersion -eq 0 -and $gpo.User.DSVersion -eq 0) { $issues += 'vide' }
        if ($gpo.GpoStatus -eq 'AllSettingsDisabled') { $issues += 'tous parametres desactives' }
        $editors = @()
        try {
            foreach ($p in @(Get-GPPermission -Guid $gpo.Id -All -ErrorAction Stop | Where-Object { $_.Permission -in 'GpoEdit', 'GpoEditDeleteModifySecurity' })) {
                $sid = $null
                try { $sid = $p.Trustee.Sid.Value } catch { }
                if ($sid -and $adminSids -notcontains $sid) { $editors += ("{0} ({1})" -f $p.Trustee.Name, $p.Permission) }
            }
        } catch { }
        if ($editors) { $issues += ('modifiable par : ' + ($editors -join ', ')) }
        if ($issues) {
            $rows.Add([PSCustomObject]@{ GPO = $gpo.DisplayName; GUID = $id; Modifiee = $gpo.ModificationTime; Constats = $issues -join ' ; ' })
        }
    }
    if ($rows.Count -eq 0) { Write-Log "Aucune anomalie d'hygiene detectee sur les GPO." -Level OK; return }
    Write-ListPreview -Items $rows -Max 40 -Color Yellow -Format { param($r) "{0} : {1}" -f $r.GPO, $r.Constats }
    $deleg = @($rows | Where-Object { $_.Constats -like '*modifiable par*' })
    if ($deleg.Count -gt 0) { Write-Log ("{0} GPO modifiable(s) par des principaux non administrateurs : verifiez qu'aucune n'est liee aux DC ou a la racine du domaine." -f $deleg.Count) -Level WARN }
    [void](Export-Report -Rows $rows -Name "Rapport_HygieneGPO")
}

# ============================================================
#  THEME 11 - POSTES ET SERVEURS MEMBRES
# ============================================================

function Invoke-Audit13DefenderStatus {
    Write-Section "Etat de Microsoft Defender sur des postes/serveurs choisis" Magenta
    Write-Info "Interroge les machines choisies (Get-MpComputerStatus/Get-MpPreference) via WinRM."

    $targets = @(Get-TargetComputers -Label "l'audit Defender" -IncludeDCs)
    if ($targets.Count -eq 0) { return }

    $rows = @(foreach ($name in $targets) {
        try {
            Invoke-OnDC -ComputerName $name -ScriptBlock {
                $status = Get-MpComputerStatus -ErrorAction Stop
                $pref = Get-MpPreference -ErrorAction Stop
                $asrModes = @($pref.AttackSurfaceReductionRules_Actions)
                [PSCustomObject]@{
                    Machine              = $env:COMPUTERNAME
                    ProtectionTempsReel  = $status.RealTimeProtectionEnabled
                    AntivirusActif       = $status.AntivirusEnabled
                    SignaturesAgeJours   = $status.AntivirusSignatureAge
                    ProtectionCloud      = switch ([int]$pref.MAPSReporting) { 0 { 'Desactivee' } 1 { 'Basique' } 2 { 'Avancee' } default { $pref.MAPSReporting } }
                    ProtectionReseau     = switch ([int]$pref.EnableNetworkProtection) { 0 { 'Desactivee' } 1 { 'Bloquer' } 2 { 'Audit' } default { $pref.EnableNetworkProtection } }
                    ProtectionFalsification = $status.IsTamperProtected
                    ReglesASR_Bloquer    = @($asrModes | Where-Object { $_ -eq 1 }).Count
                    ReglesASR_Audit      = @($asrModes | Where-Object { $_ -eq 2 }).Count
                    ReglesASR_Avertir    = @($asrModes | Where-Object { $_ -eq 6 }).Count
                }
            } -ErrorAction Stop
        } catch {
            Write-Log ("Impossible d'interroger Defender sur {0} (Defender absent/remplace par un autre EDR ?) : {1}" -f $name, $_.Exception.Message) -Level WARN
        }
    })
    foreach ($r in $rows) {
        $bad = (-not $r.ProtectionTempsReel) -or $r.SignaturesAgeJours -gt 3
        Write-Host ("  - {0} : temps reel={1}, signatures={2} j, cloud={3}, reseau={4}, ASR bloquer/audit/avertir={5}/{6}/{7}" -f $r.Machine, $r.ProtectionTempsReel, $r.SignaturesAgeJours, $r.ProtectionCloud, $r.ProtectionReseau, $r.ReglesASR_Bloquer, $r.ReglesASR_Audit, $r.ReglesASR_Avertir) -ForegroundColor $(if ($bad) { 'Red' } else { 'Gray' })
    }
    [void](Export-Report -Rows $rows -Name "Rapport_Defender")
}

# Lecture/modification du groupe Administrateurs LOCAL par son SID (S-1-5-32-544), independamment
# de la langue de l'OS ; repli ADSI si Get-LocalGroupMember echoue (bug connu avec les SID orphelins).
$Script:GetLocalAdminsScriptBlock = {
    try {
        @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{ Machine = $env:COMPUTERNAME; Membre = $_.Name; Type = [string]$_.ObjectClass; Source = [string]$_.PrincipalSource; SID = $_.SID.Value }
        })
    } catch {
        $name = (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
        $grp = [ADSI]"WinNT://./$name,group"
        @($grp.Invoke('Members') | ForEach-Object {
            $path = $_.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $_, $null)
            $cls = $_.GetType().InvokeMember('Class', 'GetProperty', $null, $_, $null)
            [PSCustomObject]@{ Machine = $env:COMPUTERNAME; Membre = ($path -replace '^WinNT://', '' -replace '/', '\'); Type = $cls; Source = 'ADSI'; SID = $null }
        })
    }
}

function Invoke-Audit13LocalAdmins {
    Write-Section "Audit des administrateurs locaux sur des postes/serveurs choisis" Magenta
    $targets = @(Get-TargetComputers -Label "l'audit des administrateurs locaux")
    if ($targets.Count -eq 0) { return }

    $rows = @(foreach ($name in $targets) {
        try { Invoke-OnDC -ComputerName $name -ScriptBlock $Script:GetLocalAdminsScriptBlock -ErrorAction Stop }
        catch { Write-Log ("Impossible de lire les administrateurs locaux de {0} : {1}" -f $name, $_.Exception.Message) -Level WARN }
    })
    if ($rows.Count -eq 0) { Write-Log "Aucun resultat (verifiez les droits d'acces distant aux machines ciblees)." -Level WARN; return }

    # Membres les plus repandus en tete : un compte/groupe present partout merite une attention particuliere.
    $rows | Group-Object Membre | Sort-Object Count -Descending | Select-Object -First 20 | ForEach-Object {
        Write-Host ("  - {0} : administrateur sur {1} machine(s)" -f $_.Name, $_.Count) -ForegroundColor $(if ($_.Count -gt 1 -and $_.Name -notmatch '\\(Administra|Admins du domaine|Domain Admins)') { 'Yellow' } else { 'Gray' })
    }
    [void](Export-Report -Rows $rows -Name "Rapport_AdminsLocaux" -Comment "Comparez avec les comptes/groupes qui devraient legitimement etre administrateurs locaux.")
}

function Invoke-Remediate13EnableDefenderProtections {
    Write-Section "Renforcement Microsoft Defender via GPO (Cloud, Reseau, SmartScreen, ASR)" Red
    Write-Info "Risque : le mode Bloquer des regles ASR peut bloquer une application legitime au" `
               "comportement proche d'une menace (faux positif). Deploiement PROGRESSIF : Audit, puis" `
               "Avertir, puis Bloquer. Sans effet si Defender est remplace par un autre antivirus/EDR."

    if (-not (Test-GroupPolicyModule)) { return }

    Write-Host "Mode des regles ASR : [1] Audit (defaut)  [2] Avertir  [3] Bloquer" -ForegroundColor Cyan
    $modeInput = Read-Host "Choix"
    $asrValue = switch ($modeInput) { "2" { "6" } "3" { "1" } default { "2" } }
    $modeLabel = switch ($modeInput) { "2" { "Avertir" } "3" { "Bloquer" } default { "Audit" } }

    $targetOUs = @(Select-OUsInteractive -Label "la GPO de durcissement Defender" -Verb "CIBLER (lien de la GPO)")
    if ($targetOUs.Count -eq 0) { Write-Log "Aucune UO ciblee, action annulee." -Level WARN; return }

    # Regles ASR couramment recommandees (faible taux de faux positifs) :
    $asrRules = [ordered]@{
        "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = "Bloquer les appels d'API Win32 depuis les macros Office"
        "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "Bloquer l'execution de scripts potentiellement obfusques"
        "C1DB55AB-C21A-4637-BB3F-A12568109D35" = "Protection avancee contre les ransomwares"
        "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = "Bloquer le vol d'identifiants depuis lsass.exe"
        "3B576869-A4EC-4529-8536-B80A7769E899" = "Bloquer la creation de contenu executable par Office"
        "D3E037E1-3EB8-44C8-A917-57927947596D" = "Bloquer le lancement de contenu telecharge par JavaScript/VBScript"
        "56A863A9-875E-4185-98A7-B882C64B5CE5" = "Bloquer l'abus de pilotes vulnerables signes"
        "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = "Bloquer le contenu executable des clients de messagerie"
    }
    $asrRules.GetEnumerator() | ForEach-Object { Write-Host ("  - {0}" -f $_.Value) -ForegroundColor DarkGray }

    $gpoName = "SEC - Defender Hardening"
    if (-not (Confirm-Action ("Creer/MAJ la GPO '{0}' (Cloud+Reseau+SmartScreen, {1} regles ASR en mode {2}) et la lier sur {3} UO" -f $gpoName, $asrRules.Count, $modeLabel, $targetOUs.Count) -Strong)) { return }

    Invoke-Guarded -Description ("Creation/MAJ de la GPO {0}" -f $gpoName) -Action {
        $null = Get-OrCreateGpo -Name $gpoName
        $def = "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender"
        Set-GPRegistryValue -Name $gpoName -Key "$def\Spynet" -ValueName "SpynetReporting" -Type DWord -Value 2 | Out-Null
        Set-GPRegistryValue -Name $gpoName -Key "$def\Spynet" -ValueName "SubmitSamplesConsent" -Type DWord -Value 1 | Out-Null
        # Reseau : en mode Audit des regles ASR, la protection reseau est aussi en audit (2).
        $np = if ($asrValue -eq "2") { 2 } else { 1 }
        Set-GPRegistryValue -Name $gpoName -Key "$def\Windows Defender Exploit Guard\Network Protection" -ValueName "EnableNetworkProtection" -Type DWord -Value $np | Out-Null
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "EnableSmartScreen" -Type DWord -Value 1 | Out-Null
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "ShellSmartScreenLevel" -Type String -Value "Block" | Out-Null
        Set-GPRegistryValue -Name $gpoName -Key "$def\Windows Defender Exploit Guard\ASR" -ValueName "ExploitGuard_ASR_Rules" -Type DWord -Value 1 | Out-Null
        foreach ($rule in $asrRules.Keys) {
            Set-GPRegistryValue -Name $gpoName -Key "$def\Windows Defender Exploit Guard\ASR\Rules" -ValueName $rule -Type String -Value $asrValue | Out-Null
        }
        Add-GpoLinkSafe -Name $gpoName -Targets $targetOUs
    }
    Write-OutcomeLog ("GPO deployee en mode ASR '{0}'. Surveillez les evenements Defender 1121 (bloque) / 1122 (audit) avant de passer au mode superieur." -f $modeLabel)
}

function Invoke-Remediate13RestrictRdp {
    Write-Section "Restriction RDP (NLA + chiffrement + couche TLS) via GPO" Red
    Write-Info "Risque : casse les clients RDP tres anciens ne supportant pas la Network Level" `
               "Authentication (NLA) ou TLS - rare sur un parc a jour."

    if (-not (Test-GroupPolicyModule)) { return }
    $targetOUs = @(Select-OUsInteractive -Label "la GPO de restriction RDP" -Verb "CIBLER (lien de la GPO)")
    if ($targetOUs.Count -eq 0) { Write-Log "Aucune UO ciblee, action annulee." -Level WARN; return }

    $gpoName = "SEC - Restriction RDP (NLA)"
    if (-not (Confirm-Action ("Creer/MAJ la GPO '{0}' (NLA obligatoire, couche TLS, chiffrement eleve) et la lier sur {1} UO" -f $gpoName, $targetOUs.Count) -Strong)) { return }

    Invoke-Guarded -Description ("Creation/MAJ de la GPO {0}" -f $gpoName) -Action {
        $null = Get-OrCreateGpo -Name $gpoName
        $key = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        Set-GPRegistryValue -Name $gpoName -Key $key -ValueName "UserAuthentication" -Type DWord -Value 1 | Out-Null
        Set-GPRegistryValue -Name $gpoName -Key $key -ValueName "SecurityLayer" -Type DWord -Value 2 | Out-Null
        Set-GPRegistryValue -Name $gpoName -Key $key -ValueName "MinEncryptionLevel" -Type DWord -Value 3 | Out-Null
        Set-GPRegistryValue -Name $gpoName -Key $key -ValueName "fEncryptRPCTraffic" -Type DWord -Value 1 | Out-Null
        Add-GpoLinkSafe -Name $gpoName -Targets $targetOUs
    }
    Write-OutcomeLog "GPO liee. Le controle de QUI peut se connecter en RDP (droit 'Autoriser l'ouverture de session par les services Bureau a distance') reste a definir selon vos groupes d'administration." -Level WARN
}

function Invoke-Remediate13CleanupLocalAdmins {
    Write-Section "Retirer des comptes des administrateurs locaux sur une machine" Red
    Write-Info "Risque : retirer un compte qui a reellement besoin de ce privilege local cassera son usage" `
               "sur la machine concernee. Le compte Administrateur local integre (RID 500) n'est pas propose."

    $targets = @(Get-TargetComputers -Label "le nettoyage des administrateurs locaux")
    if ($targets.Count -eq 0) { return }
    $machine = @(Select-FromList -Items $targets -Prompt "Machine sur laquelle agir" -Single -Display { param($m) $m })
    if ($machine.Count -eq 0) { return }
    $machine = $machine[0]

    try {
        $members = @(Invoke-OnDC -ComputerName $machine -ScriptBlock $Script:GetLocalAdminsScriptBlock -ErrorAction Stop | Where-Object { -not ($_.SID -and $_.SID -match '-500$') })
    } catch {
        Write-Log ("Impossible de lire les administrateurs locaux de {0} : {1}" -f $machine, $_.Exception.Message) -Level ERROR
        return
    }
    if ($members.Count -eq 0) { Write-Log "Aucun membre retirable trouve." -Level OK; return }

    $toRemove = @(Select-FromList -Items $members -Prompt "Membres a retirer" -Display { param($m) "{0} ({1}, {2})" -f $m.Membre, $m.Type, $m.Source })
    if ($toRemove.Count -eq 0) { return }
    if (-not (Confirm-Action ("Retirer {0} compte(s) des administrateurs locaux de {1}" -f $toRemove.Count, $machine) -Strong)) { return }

    foreach ($t in $toRemove) {
        Invoke-Guarded -Description ("Retrait de {0} des administrateurs locaux de {1}" -f $t.Membre, $machine) -Action {
            Invoke-OnDC -ComputerName $machine -ScriptBlock {
                param($member, $sid)
                $id = if ($sid) { $sid } else { $member }
                Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member $id -ErrorAction Stop
            } -ArgumentList $t.Membre, $t.SID -ErrorAction Stop
        }
    }
}

function Set-PowerShellLoggingInGpo {
    param([Parameter(Mandatory)][string]$GpoName)
    $base = "HKLM\Software\Policies\Microsoft\Windows\PowerShell"
    Set-GPRegistryValue -Name $GpoName -Key "$base\ScriptBlockLogging" -ValueName "EnableScriptBlockLogging" -Type DWord -Value 1 | Out-Null
    Set-GPRegistryValue -Name $GpoName -Key "$base\ModuleLogging" -ValueName "EnableModuleLogging" -Type DWord -Value 1 | Out-Null
    # Sans liste de modules, la journalisation des modules n'enregistre RIEN : '*' = tous les modules.
    Set-GPRegistryValue -Name $GpoName -Key "$base\ModuleLogging\ModuleNames" -ValueName "*" -Type String -Value "*" | Out-Null
}

function Invoke-Remediate13EnablePowerShellLoggingExtended {
    Write-Section "Etendre la journalisation PowerShell aux postes/serveurs choisis" Cyan
    Write-Info "Complementaire a l'activation sur les DC (theme 15 > 3). Journalisation uniquement : peut" `
               "augmenter le volume du journal 'Microsoft-Windows-PowerShell/Operational' (evenement 4104)."

    if (-not (Test-GroupPolicyModule)) { return }
    $targetOUs = @(Select-OUsInteractive -Label "l'extension de la journalisation PowerShell" -Verb "CIBLER (lien de la GPO)")
    if ($targetOUs.Count -eq 0) { Write-Log "Aucune UO ciblee, action annulee." -Level WARN; return }

    $gpoName = "SEC - Audit PowerShell Logging"
    if (-not (Confirm-Action ("Lier la GPO '{0}' (creee/completee si besoin) sur {1} UO supplementaire(s)" -f $gpoName, $targetOUs.Count))) { return }

    Invoke-Guarded -Description ("Extension de la GPO {0}" -f $gpoName) -Action {
        $null = Get-OrCreateGpo -Name $gpoName
        Set-PowerShellLoggingInGpo -GpoName $gpoName
        Add-GpoLinkSafe -Name $gpoName -Targets $targetOUs
    }
}

function Invoke-Remediate13DisableWindowsScriptHost {
    Write-Section "Bloquer l'execution de scripts .vbs/.js (Windows Script Host)" Red
    Write-Info "Risque : casse les scripts de connexion/outils internes bases sur WSH (.vbs, .js, .wsf)." `
               "Verifiez l'absence de dependance (scripts de logon dans NETLOGON notamment) avant d'appliquer."

    if (-not (Test-GroupPolicyModule)) { return }
    $vbs = @()
    try { $vbs = @(Get-ChildItem -LiteralPath ("\\{0}\NETLOGON" -f (Get-CachedADDomain).DNSRoot) -Recurse -Include *.vbs, *.js, *.wsf -File -ErrorAction Stop) } catch { }
    if ($vbs.Count -gt 0) {
        Write-Log ("{0} script(s) WSH trouve(s) dans NETLOGON (ex : {1}) : ils cesseront de fonctionner sur les machines ciblees." -f $vbs.Count, $vbs[0].Name) -Level WARN
    }

    $targetOUs = @(Select-OUsInteractive -Label "le blocage Windows Script Host" -Verb "CIBLER (lien de la GPO)")
    if ($targetOUs.Count -eq 0) { Write-Log "Aucune UO ciblee, action annulee." -Level WARN; return }

    $gpoName = "SEC - Blocage Windows Script Host"
    if (-not (Confirm-Action ("Creer/MAJ la GPO '{0}' et la lier sur {1} UO" -f $gpoName, $targetOUs.Count) -Strong)) { return }

    Invoke-Guarded -Description ("Creation/MAJ de la GPO {0}" -f $gpoName) -Action {
        $null = Get-OrCreateGpo -Name $gpoName
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Microsoft\Windows Script Host\Settings" -ValueName "Enabled" -Type DWord -Value 0 | Out-Null
        Add-GpoLinkSafe -Name $gpoName -Targets $targetOUs
    }
}

function Invoke-Remediate13EnableFirewallBaseline {
    Write-Section "Activer le pare-feu Windows (3 profils) sur des postes/serveurs choisis" Red
    Write-Info "Risque : si des flux legitimes ne sont pas couverts par les regles predefinies actives" `
               "(ou vos regles personnalisees), ils seront bloques. Testez en UO pilote."

    if (-not (Test-GroupPolicyModule)) { return }
    $targetOUs = @(Select-OUsInteractive -Label "la GPO de pare-feu" -Verb "CIBLER (lien de la GPO)")
    if ($targetOUs.Count -eq 0) { Write-Log "Aucune UO ciblee, action annulee." -Level WARN; return }

    $gpoName = "SEC - Pare-feu Windows actif (Postes-Serveurs)"
    if (-not (Confirm-Action ("Creer/MAJ la GPO '{0}' et la lier sur {1} UO" -f $gpoName, $targetOUs.Count) -Strong)) { return }

    Invoke-Guarded -Description ("Creation/MAJ de la GPO {0}" -f $gpoName) -Action {
        $null = Get-OrCreateGpo -Name $gpoName
        Set-FirewallProfilesInGpo -GpoName $gpoName
        Add-GpoLinkSafe -Name $gpoName -Targets $targetOUs
    }
}

# ============================================================
#  THEME 12 - RESEAU ET ANTI-RELAY
# ============================================================

function Invoke-Audit14GlobalQueryBlockList {
    Write-Section "Audit de la Global Query Block List DNS (WPAD/ISATAP)" Magenta
    Write-Info "Le serveur DNS Windows bloque par defaut la resolution de 'wpad' et 'isatap'. Verifie que" `
               "ce blocage n'a pas ete retire par erreur, et qu'aucun enregistrement 'wpad' n'existe dans" `
               "les zones (un enregistrement wpad pointe tous les navigateurs vers un proxy)."

    $dcs = @(Get-ReachableDCs)
    if ($dcs.Count -eq 0) { return }
    $zone = (Get-CachedADDomain).DNSRoot
    foreach ($dc in $dcs) {
        try {
            $r = Invoke-OnDC -ComputerName $dc.HostName -ScriptBlock {
                param($z)
                $l = Get-DnsServerGlobalQueryBlockList -ErrorAction Stop
                $wpad = $null
                try { $wpad = @(Get-DnsServerResourceRecord -ZoneName $z -Name 'wpad' -ErrorAction Stop).Count } catch { $wpad = 0 }
                [PSCustomObject]@{ Enable = $l.Enable; List = @($l.List); WpadRecords = $wpad }
            } -ArgumentList $zone -ErrorAction Stop
            $hasWpad = $r.List -contains 'wpad'
            $hasIsatap = $r.List -contains 'isatap'
            $color = if ($r.Enable -and $hasWpad -and $hasIsatap -and -not $r.WpadRecords) { 'Green' } else { 'Yellow' }
            Write-Host ("  - {0} : activee={1}, wpad bloque={2}, isatap bloque={3}, enregistrement wpad dans {4}={5}" -f $dc.HostName, $r.Enable, $hasWpad, $hasIsatap, $zone, [bool]$r.WpadRecords) -ForegroundColor $color
        } catch {
            Write-Log ("Impossible de lire la Global Query Block List sur {0} (role DNS absent ?) : {1}" -f $dc.HostName, $_.Exception.Message) -Level WARN
        }
    }
}

function Invoke-Remediate14RestoreGlobalQueryBlockList {
    Write-Section "Retablir la Global Query Block List DNS (wpad/isatap)" Cyan
    Write-Info "Impact : restaure une protection par defaut de Windows (aucune incidence si WPAD/ISATAP" `
               "ne sont pas utilises intentionnellement, ce qui est la norme). Les autres noms deja" `
               "presents dans la liste sont conserves."

    $dcs = @(Get-ReachableDCs)
    if ($dcs.Count -eq 0) { return }
    if (-not (Confirm-Action "Retablir la Global Query Block List (wpad, isatap) activee sur tous les DC")) { return }

    foreach ($dc in $dcs) {
        Invoke-Guarded -Description ("Retablissement de la Global Query Block List sur {0}" -f $dc.HostName) -Action {
            Invoke-OnDC -ComputerName $dc.HostName -ScriptBlock {
                $current = @((Get-DnsServerGlobalQueryBlockList -ErrorAction Stop).List)
                $list = @($current + @('wpad', 'isatap') | Where-Object { $_ } | Sort-Object -Unique)
                Set-DnsServerGlobalQueryBlockList -List $list -Enable $true -ErrorAction Stop
            } -ErrorAction Stop
        }
    }
}

function Invoke-Remediate14DisableNetbiosOnComputers {
    Write-Section "Desactivation de NetBIOS sur TCP/IP sur des postes/serveurs choisis" Red
    Write-Info "Risque : casse la resolution de nom de secours NetBIOS/NBT-NS utilisee par certaines" `
               "applications/imprimantes anciennes quand le DNS echoue. Reglage par carte reseau :" `
               "une nouvelle carte (VPN, station d'accueil) reviendra au comportement par defaut."

    $targets = @(Get-TargetComputers -Label "la desactivation NetBIOS")
    if ($targets.Count -eq 0) { return }
    Write-Host ("Machines ciblees : {0}" -f ($targets -join ', ')) -ForegroundColor Yellow
    if (-not (Confirm-Action ("Desactiver NetBIOS sur TCP/IP sur {0} machine(s)" -f $targets.Count) -Strong)) { return }

    foreach ($name in $targets) {
        Invoke-Guarded -Description ("Desactivation NetBIOS sur {0}" -f $name) -Action {
            Invoke-OnDC -ComputerName $name -ScriptBlock {
                foreach ($nic in @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction Stop)) {
                    # 2 = desactiver NetBIOS sur TCP/IP pour cette interface.
                    $r = Invoke-CimMethod -InputObject $nic -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 } -ErrorAction Stop
                    if ($r.ReturnValue -notin 0, 1) { throw ("SetTcpipNetbios a echoue sur '{0}' (code {1})." -f $nic.Description, $r.ReturnValue) }
                }
            } -ErrorAction Stop
        }
    }
}

function Invoke-Remediate14RestrictRpc {
    Write-Section "Durcissement RPC (clients non authentifies, resolution du mappeur de points terminaux)" Red
    Write-Info "Risque : casse les applications RPC anciennes qui dependent de clients non authentifies." `
               "A appliquer aux SERVEURS MEMBRES / postes : ces deux parametres ne sont PAS recommandes" `
               "sur les controleurs de domaine (references CIS 'MS only')."

    if (-not (Test-GroupPolicyModule)) { return }
    $targetOUs = @(Select-OUsInteractive -Label "la GPO de durcissement RPC" -Verb "CIBLER (lien de la GPO)")
    if ($targetOUs.Count -eq 0) { Write-Log "Aucune UO ciblee, action annulee." -Level WARN; return }
    if (Test-TargetsIncludeDCs -Targets $targetOUs) {
        Write-Log "La selection inclut l'UO des DC ou la racine du domaine : deconseille pour ce parametre." -Level ERROR
        if (-not (Read-YesNo -Prompt "Continuer malgre tout ?")) { return }
    }

    $gpoName = "SEC - Durcissement RPC"
    if (-not (Confirm-Action ("Creer/MAJ la GPO '{0}' et la lier sur {1} UO" -f $gpoName, $targetOUs.Count) -Strong)) { return }

    Invoke-Guarded -Description ("Creation/MAJ de la GPO {0}" -f $gpoName) -Action {
        $null = Get-OrCreateGpo -Name $gpoName
        $key = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
        Set-GPRegistryValue -Name $gpoName -Key $key -ValueName "RestrictRemoteClients" -Type DWord -Value 1 | Out-Null
        Set-GPRegistryValue -Name $gpoName -Key $key -ValueName "EnableAuthEpResolution" -Type DWord -Value 1 | Out-Null
        Add-GpoLinkSafe -Name $gpoName -Targets $targetOUs
    }
}

function Invoke-Remediate14RestrictWinRm {
    Write-Section "Durcissement WinRM (authentification Basic desactivee, trafic chiffre obligatoire)" Red
    Write-Info "Risque : casse les scripts/outils tiers qui se connectent en WinRM avec l'authentification" `
               "Basic ou en trafic non chiffre (sans effet sur PowerShell Remoting Kerberos standard)."

    if (-not (Test-GroupPolicyModule)) { return }
    $targetOUs = @(Select-OUsInteractive -Label "la GPO de durcissement WinRM" -Verb "CIBLER (lien de la GPO)")
    if ($targetOUs.Count -eq 0) { Write-Log "Aucune UO ciblee, action annulee." -Level WARN; return }

    $gpoName = "SEC - Durcissement WinRM"
    if (-not (Confirm-Action ("Creer/MAJ la GPO '{0}' (Basic desactive, trafic chiffre obligatoire, client+serveur) et la lier sur {1} UO" -f $gpoName, $targetOUs.Count) -Strong)) { return }

    Invoke-Guarded -Description ("Creation/MAJ de la GPO {0}" -f $gpoName) -Action {
        $null = Get-OrCreateGpo -Name $gpoName
        foreach ($side in 'Service', 'Client') {
            $k = "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\$side"
            Set-GPRegistryValue -Name $gpoName -Key $k -ValueName "AllowBasic" -Type DWord -Value 0 | Out-Null
            Set-GPRegistryValue -Name $gpoName -Key $k -ValueName "AllowUnencryptedTraffic" -Type DWord -Value 0 | Out-Null
        }
        Add-GpoLinkSafe -Name $gpoName -Targets $targetOUs
    }
}

function Invoke-Remediate14RestrictSamEnumeration {
    Write-Section "Restreindre l'enumeration distante SAM/SAMR" Red
    Write-Info "Limite les appels SAMR distants (enumeration des comptes/groupes locaux) aux membres du" `
               "groupe Administrateurs locaux (valeur par defaut des OS recents, a imposer sur les plus" `
               "anciens). Risque : outils de supervision/inventaire utilisant un compte non-admin."

    if (-not (Test-GroupPolicyModule)) { return }
    $targetOUs = @(Select-OUsInteractive -Label "la restriction SAMR" -Verb "CIBLER (lien de la GPO)")
    if ($targetOUs.Count -eq 0) { Write-Log "Aucune UO ciblee, action annulee." -Level WARN; return }

    $gpoName = "SEC - Restriction enumeration SAMR"
    if (-not (Confirm-Action ("Creer/MAJ la GPO '{0}' (SAMR reserve aux administrateurs locaux) et la lier sur {1} UO" -f $gpoName, $targetOUs.Count) -Strong)) { return }

    Invoke-Guarded -Description ("Creation/MAJ de la GPO {0}" -f $gpoName) -Action {
        $null = Get-OrCreateGpo -Name $gpoName
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "RestrictRemoteSAM" -Type String -Value "O:BAG:BAD:(A;;RC;;;BA)" | Out-Null
        Add-GpoLinkSafe -Name $gpoName -Targets $targetOUs
    }
}

function Invoke-RiskyDisableLLMNR {
    Write-Section "Desactivation de LLMNR (et option mDNS) via GPO" Red
    Write-Info "LLMNR/mDNS sont des resolutions de nom de secours, interceptables sur le reseau local" `
               "(Responder) pour capturer des hachages NTLM. Risque : peripheriques/anciennes applications" `
               "qui en dependent quand le DNS echoue. Impact large : testez sur une UO pilote."

    if (-not (Test-GroupPolicyModule)) { return }
    $mdns = Read-YesNo -Prompt "Desactiver aussi mDNS (Windows 10 1809+ / 11 : meme risque que LLMNR) ?" -Default $true
    $gpoName = "SEC - Desactivation LLMNR"
    Write-Host "Liaison : choisissez des UO PILOTES (vide = GPO creee sans lien)." -ForegroundColor Yellow
    $targets = @(Select-OUsInteractive -Label "la desactivation LLMNR" -Verb "CIBLER (lien pilote)" -IncludeDomainRoot)
    if (-not (Confirm-Action ("Creer la GPO '{0}'{1}" -f $gpoName, $(if ($targets) { " et la lier sur $($targets.Count) cible(s)" } else { " (non liee)" })) -Strong)) { return }

    Invoke-Guarded -Description "Creation GPO LLMNR" -Action {
        $null = Get-OrCreateGpo -Name $gpoName
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" -ValueName "EnableMulticast" -Type DWord -Value 0 | Out-Null
        if ($mdns) { Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -ValueName "EnableMDNS" -Type DWord -Value 0 | Out-Null }
        if ($targets.Count -gt 0) { Add-GpoLinkSafe -Name $gpoName -Targets $targets }
    }
    if ($targets.Count -eq 0) { Write-OutcomeLog "GPO creee mais NON liee. Testez d'abord sur une UO pilote avant deploiement domaine entier." -Level WARN }
}

function Invoke-Audit14ExposedServices {
    Write-Section "Audit des ports/services exposes sur les DC" Magenta
    Write-Info "Liste les ports TCP en ECOUTE sur toutes les interfaces de chaque DC. Les ports attendus" `
               "d'un DC sont annotes ; les ports dynamiques RPC (49152-65535) sont regroupes. A examiner :" `
               "les ports 'NON STANDARD'."

    $known = @{
        53 = 'DNS'; 88 = 'Kerberos'; 135 = 'RPC mappeur'; 139 = 'NetBIOS session'; 389 = 'LDAP'; 445 = 'SMB'
        464 = 'Kerberos chgt mdp'; 593 = 'RPC sur HTTP'; 636 = 'LDAPS'; 3268 = 'Catalogue global'; 3269 = 'Catalogue global SSL'
        3389 = 'RDP'; 5985 = 'WinRM HTTP'; 5986 = 'WinRM HTTPS'; 9389 = 'AD Web Services'; 47001 = 'WinRM (local)'
    }
    $dcs = @(Get-ReachableDCs)
    if ($dcs.Count -eq 0) { return }

    $rows = @(foreach ($dc in $dcs) {
        try {
            Invoke-OnDC -ComputerName $dc.HostName -ScriptBlock {
                Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $_.LocalAddress -notin '127.0.0.1', '::1' } | ForEach-Object {
                    $procName = try { (Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName } catch { "?" }
                    [PSCustomObject]@{ DC = $env:COMPUTERNAME; Port = $_.LocalPort; Processus = $procName }
                }
            } -ErrorAction Stop
        } catch {
            Write-Log ("Impossible de lister les ports en ecoute sur {0} : {1}" -f $dc.HostName, $_.Exception.Message) -Level WARN
        }
    })
    $rows = @($rows | Sort-Object DC, Port -Unique | ForEach-Object {
        $svc = if ($known.ContainsKey([int]$_.Port)) { $known[[int]$_.Port] } elseif ($_.Port -ge 49152) { 'RPC dynamique' } else { 'NON STANDARD' }
        $_ | Add-Member -NotePropertyName Service -NotePropertyValue $svc -PassThru
    })
    $unusual = @($rows | Where-Object { $_.Service -eq 'NON STANDARD' })
    foreach ($u in $unusual) { Write-Host ("  - {0} : port {1} ({2})" -f $u.DC, $u.Port, $u.Processus) -ForegroundColor Yellow }
    if ($unusual.Count -eq 0) { Write-Log "Aucun port non standard en ecoute sur les DC." -Level OK }
    [void](Export-Report -Rows $rows -Name "Rapport_PortsExposes")
}

# ============================================================
#  THEME 13 - SAUVEGARDE ET RESILIENCE AD
# ============================================================

function Get-ADBackupStatus {
    <#
        Date de la derniere sauvegarde AD reconnue par l'annuaire, lue dans les metadonnees de
        replication de l'attribut dSASignature de chaque partition (methode de 'repadmin
        /showbackup' et de PingCastle) : independante de l'outil de sauvegarde (Windows Server
        Backup, Veeam...), de la langue de l'OS, et sans WinRM.
    #>
    $root = Get-ADRootDSE -ErrorAction Stop
    $server = (Get-CachedADDomain).PDCEmulator
    $rows = foreach ($nc in @($root.defaultNamingContext, $root.configurationNamingContext, $root.schemaNamingContext)) {
        $meta = $null
        try { $meta = Get-ADReplicationAttributeMetadata -Object $nc -Server $server -Properties dSASignature -ErrorAction Stop | Where-Object { $_.AttributeName -eq 'dSASignature' } } catch { }
        $last = if ($meta -and $meta.LastOriginatingChangeTime -gt [datetime]'1601-01-02') { $meta.LastOriginatingChangeTime } else { $null }
        [PSCustomObject]@{ Partition = $nc; DerniereSauvegarde = $last; AgeJours = if ($last) { [int]((Get-Date) - $last).TotalDays } else { $null } }
    }
    return @($rows)
}

function Get-TombstoneLifetime {
    try {
        $dn = "CN=Directory Service,CN=Windows NT,CN=Services,{0}" -f (Get-ADRootDSE).configurationNamingContext
        $v = (Get-ADObject -Identity $dn -Properties tombstoneLifetime -ErrorAction Stop).tombstoneLifetime
        if ($v) { return [int]$v } else { return 60 }   # attribut absent : 60 jours (forets anciennes)
    } catch { return $null }
}

function Invoke-Audit17SystemStateBackupStatus {
    Write-Section "Etat des sauvegardes Active Directory" Magenta
    Write-Info "Source 1 (fiable, sans WinRM) : date de derniere sauvegarde enregistree par l'annuaire pour" `
               "chaque partition (tout outil de sauvegarde 'AD-aware'). Source 2 : journal" `
               "Microsoft-Windows-Backup de chaque DC (Windows Server Backup uniquement)."

    $tsl = Get-TombstoneLifetime
    if ($tsl) { Write-Host ("Duree de vie des objets supprimes (tombstone) : {0} jours - une sauvegarde plus ancienne est INUTILISABLE pour restaurer un DC." -f $tsl) -ForegroundColor Cyan }

    try {
        $rows = @(Get-ADBackupStatus)
        foreach ($r in $rows) {
            $color = if (-not $r.DerniereSauvegarde -or $r.AgeJours -gt 7) { 'Red' } elseif ($r.AgeJours -gt 1) { 'Yellow' } else { 'Green' }
            Write-Host ("  - {0} : {1}" -f $r.Partition, $(if ($r.DerniereSauvegarde) { "derniere sauvegarde le {0} ({1} j)" -f $r.DerniereSauvegarde, $r.AgeJours } else { 'JAMAIS sauvegardee' })) -ForegroundColor $color
        }
        $domainRow = $rows | Select-Object -First 1
        if (-not $domainRow.DerniereSauvegarde) { Write-Log "Aucune sauvegarde AD n'a jamais ete enregistree pour la partition du domaine." -Level ERROR }
        elseif ($tsl -and $domainRow.AgeJours -ge $tsl) { Write-Log "La derniere sauvegarde depasse la duree de vie des tombstones : elle n'est plus restaurable." -Level ERROR }
        elseif ($domainRow.AgeJours -gt 7) { Write-Log ("Derniere sauvegarde AD il y a {0} jours : frequence recommandee quotidienne." -f $domainRow.AgeJours) -Level WARN }
        else { Write-Log "Sauvegarde AD recente enregistree par l'annuaire." -Level OK }
        [void](Export-Report -Rows $rows -Name "Rapport_SauvegardeAD")
    } catch {
        Write-Log ("Lecture des metadonnees de sauvegarde impossible : {0}" -f $_.Exception.Message) -Level WARN
    }

    $dcs = @(Get-ReachableDCs)
    foreach ($dc in $dcs) {
        try {
            $last = Invoke-OnDC -ComputerName $dc.HostName -ScriptBlock {
                try { (Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Backup'; Id = 4 } -MaxEvents 1 -ErrorAction Stop).TimeCreated } catch { $null }
            } -ErrorAction Stop
            Write-Host ("  {0} : derniere sauvegarde Windows Server Backup reussie : {1}" -f $dc.HostName, $(if ($last) { $last } else { 'aucune (ou autre outil de sauvegarde)' })) -ForegroundColor DarkGray
        } catch { }
    }
}

function Invoke-SafeEnableRecycleBin {
    Write-Section "Activation de la Corbeille Active Directory (AD Recycle Bin)" Cyan
    Write-Info "Impact : AUCUN sur l'existant. Permet de restaurer un objet supprime par erreur avec tous" `
               "ses attributs (appartenances aux groupes incluses). IRREVERSIBLE (ne peut etre desactivee)." `
               "Necessite le niveau fonctionnel de foret Windows Server 2008 R2."
    try {
        $forest = (Get-CachedADForest).Name
        $feature = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" -ErrorAction Stop
        if (@($feature.EnabledScopes).Count -gt 0) { Write-Log "La Corbeille AD est deja activee." -Level OK; return }
    } catch {
        Write-Log "Impossible de verifier l'etat de la Corbeille AD : $($_.Exception.Message)" -Level ERROR
        return
    }

    if (Confirm-Action "Activer la Corbeille Active Directory (irreversible)") {
        Invoke-Guarded -Description "Enable-ADOptionalFeature 'Recycle Bin Feature'" -Action {
            Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target $forest -Confirm:$false
        }
    }
}

function Invoke-Remediate17ScheduleSystemStateBackup {
    Write-Section "Planifier une sauvegarde System State quotidienne sur un DC" Red
    Write-Info "Une sauvegarde non testee ne constitue pas une garantie de reprise : testez la restauration" `
               "periodiquement (item 4). Cible de sauvegarde INDEPENDANTE du domaine si possible (partage" `
               "avec compte dedie, ou disque non joint) pour resister a un ransomware."

    $dcs = @(Get-DomainControllersList)
    if ($dcs.Count -eq 0) { return }
    Write-Host "Controleurs de domaine disponibles :"
    for ($i = 0; $i -lt $dcs.Count; $i++) { Write-Host ("  [{0}] {1}" -f $i, $dcs[$i].HostName) }
    $targetDC = $dcs[(Read-IntValue -Prompt "DC sur lequel planifier la sauvegarde" -Default 0 -Min 0 -Max ($dcs.Count - 1))].HostName

    $target = Read-Host "Cible de sauvegarde (ex : \\NAS\Backups\DC01 ou E: - lecteur/partage DEDIE, jamais le disque systeme)"
    if ([string]::IsNullOrWhiteSpace($target)) { Write-Log "Cible de sauvegarde vide, action annulee." -Level WARN; return }
    if ($target -match '^[cC]:') { Write-Log "La cible ne peut pas etre le volume systeme (C:)." -Level ERROR; return }

    $timeInput = Read-Host "Heure quotidienne de la sauvegarde (format HH:mm) [defaut 01:00]"
    if ($timeInput -notmatch '^([01]\d|2[0-3]):[0-5]\d$') { $timeInput = "01:00" }

    if (-not (Confirm-Action ("Planifier une sauvegarde System State quotidienne a {0} sur {1}, cible {2}" -f $timeInput, $targetDC, $target) -Strong)) { return }

    Invoke-Guarded -Description ("Installation de Windows Server Backup sur {0} (si absente)" -f $targetDC) -Action {
        Invoke-OnDC -ComputerName $targetDC -ScriptBlock {
            if (-not (Get-WindowsFeature -Name Windows-Server-Backup -ErrorAction SilentlyContinue).Installed) {
                Install-WindowsFeature -Name Windows-Server-Backup -ErrorAction Stop | Out-Null
            }
        } -ErrorAction Stop
    }

    Invoke-Guarded -Description ("Creation de la tache planifiee de sauvegarde System State sur {0}" -f $targetDC) -Action {
        Invoke-OnDC -ComputerName $targetDC -ScriptBlock {
            param($backupTarget, $time)
            $taskName = "SEC - Sauvegarde System State"
            $act = New-ScheduledTaskAction -Execute "wbadmin.exe" -Argument ("start systemstatebackup -backupTarget:`"{0}`" -quiet" -f $backupTarget)
            $trg = New-ScheduledTaskTrigger -Daily -At $time
            $prn = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            $set = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            Register-ScheduledTask -TaskName $taskName -Action $act -Trigger $trg -Principal $prn -Settings $set -Description "Sauvegarde System State quotidienne - deployee par le script de remediation AD" -ErrorAction Stop | Out-Null
        } -ArgumentList $target, $timeInput -ErrorAction Stop
    }
    Write-OutcomeLog ("Tache planifiee creee sur {0}. Verifiez que le compte ordinateur {0}`$ a acces en ecriture a '{1}' (partage reseau), puis controlez le resultat demain (item 1)." -f $targetDC, $target) -Level WARN
}

function Invoke-Remediate17GenerateRecoveryProcedures {
    Write-Section "Generer les procedures de recuperation AD (objet / DC / foret)" Cyan
    Write-Info "Impact : AUCUN. Ecrit uniquement des fichiers texte de procedure dans Logs\Procedures." `
               "Ces procedures sont a tester en conditions reelles au moins une fois (labo)."

    if (-not (Confirm-Action "Generer/mettre a jour les fichiers de procedure de recuperation")) { return }

    $tsl = Get-TombstoneLifetime
    $tslText = if ($tsl) { "$tsl jours dans CETTE foret" } else { "180 jours pour une foret creee depuis Windows Server 2003 SP1, 60 jours sinon" }
    $dir = Join-Path $Script:LogDir "Procedures"

    $objectRecovery = @'
PROCEDURE - RECUPERATION D'UN OBJET AD SUPPRIME PAR ERREUR
============================================================
Prerequis : Corbeille Active Directory activee (theme 13 > 2) AVANT la suppression.

1. Identifier l'objet supprime :
   Get-ADObject -Filter 'isDeleted -eq $true -and Name -like "*<nom recherche>*"' -IncludeDeletedObjects -Properties lastKnownParent

2. Restaurer l'objet (et ses attributs, appartenances aux groupes incluses) :
   Get-ADObject -Filter 'isDeleted -eq $true -and Name -like "*<nom recherche>*"' -IncludeDeletedObjects | Restore-ADObject
   (Pour une UO et son contenu : restaurer d'abord l'UO, puis les objets enfants.)

3. Verifier l'objet restaure (appartenances de groupe, attributs) et corriger si necessaire.

Si la Corbeille AD n'etait PAS activee au moment de la suppression : restauration
authoritative necessaire depuis une sauvegarde System State (voir procedure DC,
avec ntdsutil "authoritative restore" cible sur le sous-arbre concerne uniquement).
'@

    $dcRecovery = @"
PROCEDURE - RECUPERATION D'UN CONTROLEUR DE DOMAINE
============================================================
Cas 1 : le DC est reparable (materiel/OS intact, base AD corrompue)
  1. Demarrer en mode DSRM : bcdedit /set safeboot dsrepair, puis redemarrer
     (le mot de passe DSRM doit etre connu et teste - ntdsutil "set dsrm password").
  2. Restaurer le System State depuis la derniere sauvegarde saine :
     wbadmin get versions -backupTarget:<cible>
     wbadmin start systemstaterecovery -version:<identifiant version> -backupTarget:<cible>
  3. Si restauration AUTHORITATIVE necessaire (objets a re-propager comme faisant foi) :
     ntdsutil
       activate instance ntds
       authoritative restore
         restore subtree "<DN de l'objet ou sous-arbre>"
  4. Redemarrer normalement (bcdedit /deletevalue safeboot), verifier la replication
     (repadmin /replsummary, repadmin /showrepl) et SYSVOL (dfsrdiag / evenements DFSR).

Cas 2 : le DC est irrecuperable (materiel detruit, corruption totale)
  1. Nettoyer les metadonnees AD du DC mort : suppression du compte ordinateur du DC dans
     'Utilisateurs et ordinateurs AD' (nettoyage automatique depuis 2008) ou
     ntdsutil -> metadata cleanup.
  2. Transferer/saisir les roles FSMO qu'il detenait (Move-ADDirectoryServerOperationMasterRole -Force).
  3. Retirer les enregistrements DNS obsoletes du DC.
  4. Promouvoir un nouveau DC pour retablir le nombre de DC prevu.

IMPORTANT : ne jamais restaurer un DC a partir d'une sauvegarde plus ancienne que la duree
de vie des objets supprimes (tombstone lifetime : $tslText) : risque
d'objets persistants et de "USN rollback". Ne jamais restaurer un DC par instantane de VM
non supporte (hors VM-GenerationID).
"@

    $forestRecovery = @'
PROCEDURE (RESUME) - RECONSTRUCTION D'UNE FORET ACTIVE DIRECTORY
============================================================
A utiliser en dernier recours (compromission generalisee, perte de tous les DC d'un domaine).
Suivre le "Active Directory Forest Recovery Guide" de Microsoft pour le detail ; grandes etapes :

1. Isoler completement l'environnement compromis (reseau deconnecte) avant toute action.
2. Pour CHAQUE domaine, choisir un DC inscriptible sauvegarde AVANT la compromission (idealement
   le PDC Emulator ; dans le domaine racine, celui qui porte les roles de foret).
3. Restaurer ce DC en premier, hors reseau de production, par restauration System State
   NON authoritative, puis marquer SYSVOL comme faisant autorite (DFSR : msDFSR-Options=1).
4. Sur ce DC : nettoyer les metadonnees des autres DC, saisir les roles FSMO, augmenter le pool
   RID (+100 000), invalider le pool RID courant, et reinitialiser DEUX FOIS le mot de passe
   krbtgt (theme 4) ainsi que le mot de passe du compte ordinateur du DC et des approbations.
5. Reinitialiser les mots de passe de TOUS les comptes a privileges (et idealement de tous les
   comptes, l'attaquant ayant pu extraire la base NTDS).
6. Reconstruire les autres DC par nouvelle promotion (pas par restauration), en verifiant la
   replication a chaque etape.
7. Ne reconnecter le reseau de production qu'apres validation complete (replication saine,
   SYSVOL/NETLOGON coherents, krbtgt renouvele, comptes a privileges revus, cause racine
   eliminee), puis effectuer un nouvel audit PingCastle complet.
'@

    Invoke-Guarded -Description "Generation des procedures de recuperation" -Action {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $dir "Recuperation_Objet.txt") -Value $objectRecovery -Encoding UTF8
        Set-Content -LiteralPath (Join-Path $dir "Recuperation_DC.txt") -Value $dcRecovery -Encoding UTF8
        Set-Content -LiteralPath (Join-Path $dir "Reconstruction_Foret.txt") -Value $forestRecovery -Encoding UTF8
    }
    Write-OutcomeLog ("Procedures generees dans {0}." -f $dir)
}

# ============================================================
#  THEME 14 - OBSOLESCENCE
# ============================================================

# Table de cycle de vie Microsoft (dates de FIN de support, a confirmer sur
# https://learn.microsoft.com/lifecycle). Le statut est CALCULE par rapport a la date du jour :
# il ne se perime plus avec le temps comme une liste de libelles figes.
#   Os      : regex sur l'attribut operatingSystem
#   Build   : numero de build exact (0 = toute build)
#   Ent     : date de fin pour les editions Entreprise/Education (Windows 11) ; Fin sinon
$Script:OsLifecycle = @(
    @{ Os = 'Windows (NT|2000|XP|Vista)|Windows 7|Windows 8'; Build = 0; Fin = '2023-01-10'; Label = 'Windows client ancien' }
    @{ Os = 'Server 2003';                 Build = 0;     Fin = '2015-07-14'; Label = 'Windows Server 2003' }
    @{ Os = 'Server 2008';                 Build = 0;     Fin = '2020-01-14'; Label = 'Windows Server 2008 / 2008 R2' }
    @{ Os = 'Server 2012';                 Build = 0;     Fin = '2023-10-10'; Label = 'Windows Server 2012 / 2012 R2 (ESU payantes jusqu''au 13/10/2026)' }
    @{ Os = 'Server 2016';                 Build = 0;     Fin = '2027-01-12'; Label = 'Windows Server 2016' }
    @{ Os = 'Server 2019';                 Build = 0;     Fin = '2029-01-09'; Label = 'Windows Server 2019' }
    @{ Os = 'Server 2022';                 Build = 0;     Fin = '2031-10-14'; Label = 'Windows Server 2022' }
    @{ Os = 'Server 2025';                 Build = 0;     Fin = '2034-11-14'; Label = 'Windows Server 2025' }
    @{ Os = 'Windows 10.*LTS[BC]';         Build = 10240; Fin = '2025-10-14'; Label = 'Windows 10 LTSB 2015' }
    @{ Os = 'Windows 10.*LTS[BC]';         Build = 14393; Fin = '2026-10-13'; Label = 'Windows 10 LTSB 2016' }
    @{ Os = 'Windows 10.*LTS[BC]';         Build = 17763; Fin = '2029-01-09'; Label = 'Windows 10 LTSC 2019' }
    @{ Os = 'Windows 10.*IoT.*LTSC';       Build = 19044; Fin = '2032-01-13'; Label = 'Windows 10 IoT LTSC 2021' }
    @{ Os = 'Windows 10.*LTSC';            Build = 19044; Fin = '2027-01-12'; Label = 'Windows 10 LTSC 2021' }
    @{ Os = 'Windows 10';                  Build = 0;     Fin = '2025-10-14'; Label = 'Windows 10 (ESU payantes possibles)' }
    @{ Os = 'Windows 11.*IoT.*LTSC';       Build = 26100; Fin = '2034-10-10'; Label = 'Windows 11 IoT LTSC 2024' }
    @{ Os = 'Windows 11.*LTSC';            Build = 26100; Fin = '2029-10-09'; Label = 'Windows 11 LTSC 2024' }
    @{ Os = 'Windows 11';                  Build = 22000; Fin = '2023-10-10'; Ent = '2024-10-08'; Label = 'Windows 11 21H2' }
    @{ Os = 'Windows 11';                  Build = 22621; Fin = '2024-10-08'; Ent = '2025-10-14'; Label = 'Windows 11 22H2' }
    @{ Os = 'Windows 11';                  Build = 22631; Fin = '2025-11-11'; Ent = '2026-11-10'; Label = 'Windows 11 23H2' }
    @{ Os = 'Windows 11';                  Build = 26100; Fin = '2026-10-13'; Ent = '2027-10-12'; Label = 'Windows 11 24H2' }
    @{ Os = 'Windows 11';                  Build = 26200; Fin = '2027-10-12'; Ent = '2028-10-10'; Label = 'Windows 11 25H2' }
)

function Get-OsSupportStatus {
    <#
        Statut de support d'un OS d'apres son libelle et son numero de build (attributs AD
        operatingSystem / operatingSystemVersion), CALCULE a la date du jour (-Today pour les
        tests) : EOL (fin depassee), BIENTOT (fin dans moins d'un an), SUPPORTE ou INCONNU.
        Editions Entreprise/Education de Windows 11 : calendrier etendu pris en compte.
    #>
    param([string]$OS, [string]$Version, [datetime]$Today = (Get-Date))
    if ([string]::IsNullOrWhiteSpace($OS)) { return [PSCustomObject]@{ Statut = 'INCONNU'; Detail = 'Attribut operatingSystem vide'; FinSupport = $null } }
    $build = 0
    if ($Version -match '\((\d+)\)') { $build = [int]$Matches[1] }
    $isEnt = $OS -match 'Enterprise|Entreprise|Education|Éducation'

    $entry = $Script:OsLifecycle | Where-Object { $OS -match $_.Os -and ($_.Build -eq 0 -or $_.Build -eq $build) } | Select-Object -First 1
    if (-not $entry) {
        if ($OS -match 'Windows 11' -and $build -gt 26200) { return [PSCustomObject]@{ Statut = 'SUPPORTE'; Detail = ("Windows 11 build {0} (version recente, non referencee)" -f $build); FinSupport = $null } }
        if ($OS -match 'Windows 11' -and $build -gt 0) { return [PSCustomObject]@{ Statut = 'EOL'; Detail = ("Windows 11 build {0} (pre-version ou version ancienne)" -f $build); FinSupport = $null } }
        return [PSCustomObject]@{ Statut = 'INCONNU'; Detail = 'OS non reference (non-Windows, build absente ou libelle inattendu)'; FinSupport = $null }
    }
    $endText = if ($isEnt -and $entry.Ent) { $entry.Ent } else { $entry.Fin }
    $end = [datetime]::ParseExact($endText, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
    $edition = if ($entry.Ent) { if ($isEnt) { ' (Entreprise/Education)' } else { ' (Famille/Pro)' } } else { '' }
    $statut = if ($end -lt $Today.Date) { 'EOL' } elseif ($end -lt $Today.Date.AddDays(365)) { 'BIENTOT' } else { 'SUPPORTE' }
    $verb = if ($statut -eq 'EOL') { 'fin de support depassee depuis le' } else { 'fin de support le' }
    return [PSCustomObject]@{ Statut = $statut; Detail = ("{0}{1} : {2} {3:dd/MM/yyyy}" -f $entry.Label, $edition, $verb, $end); FinSupport = $end }
}

function Invoke-Audit18UnsupportedOS {
    Write-Section "Inventaire des systemes d'exploitation non/bientot non supportes" Magenta
    Write-Info "Statut calcule a la date du jour d'apres le libelle, le numero de build (LTSC, versions" `
               "Windows 11) et l'edition. BIENTOT = fin de support dans moins d'un an. Dates de reference" `
               "integrees au script (table `$Script:OsLifecycle) : a confirmer sur le site Lifecycle Microsoft."

    # Les comptes de service geres (gMSA...) sont renvoyes par Get-ADComputer mais n'ont pas d'OS.
    $computers = @(Get-ADComputer -Filter 'Enabled -eq $true' -Properties OperatingSystem, OperatingSystemVersion, DNSHostName, LastLogonDate | Where-Object { (Get-ComputerAccountKind -Computer $_) -ne 'MSA' })
    $rows = @($computers | ForEach-Object {
        $st = Get-OsSupportStatus -OS $_.OperatingSystem -Version $_.OperatingSystemVersion
        [PSCustomObject]@{ Name = $_.Name; DNSHostName = $_.DNSHostName; OperatingSystem = $_.OperatingSystem; Version = $_.OperatingSystemVersion; DerniereConnexion = $_.LastLogonDate; Statut = $st.Statut; FinSupport = $st.FinSupport; Detail = $st.Detail }
    })
    foreach ($s in 'EOL', 'BIENTOT', 'INCONNU', 'SUPPORTE') {
        $sub = @($rows | Where-Object Statut -eq $s)
        if ($sub.Count -eq 0) { continue }
        Write-Host ("{0,-9} : {1} ordinateur(s) actif(s)" -f $s, $sub.Count) -ForegroundColor $(switch ($s) { 'EOL' { 'Red' } 'BIENTOT' { 'Yellow' } 'INCONNU' { 'Gray' } default { 'Green' } })
        if ($s -in 'EOL', 'BIENTOT') {
            $sub | Group-Object OperatingSystem | Sort-Object Count -Descending | ForEach-Object { Write-Host ("    - {0} : {1}" -f $_.Name, $_.Count) }
        }
    }
    [void](Export-Report -Rows ($rows | Where-Object { $_.Statut -ne 'SUPPORTE' }) -Name "Rapport_OS_Obsoletes")
}

function Invoke-Audit18LegacyProtocolsOnComputers {
    Write-Section "Protocoles obsoletes actifs sur des postes/serveurs choisis (SMBv1, TLS 1.0/1.1)" Magenta
    Write-Info "TLS 1.0/1.1 : la cle SCHANNEL absente signifie le comportement par DEFAUT de l'OS, qui" `
               "depend de sa version (desactives par defaut depuis Windows 11 23H2+ / Server 2025)."

    $targets = @(Get-TargetComputers -Label "l'audit des protocoles obsoletes" -IncludeDCs)
    if ($targets.Count -eq 0) { return }

    $rows = @(foreach ($name in $targets) {
        try {
            Invoke-OnDC -ComputerName $name -ScriptBlock {
                $smb1 = $null
                try { $smb1 = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch { }
                $build = [int](Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue).CurrentBuildNumber
                $states = @()
                foreach ($proto in @('TLS 1.0', 'TLS 1.1')) {
                    $p = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\Server"
                    $state = if (Test-Path $p) {
                        $e = (Get-ItemProperty -Path $p -ErrorAction SilentlyContinue).Enabled
                        if ($e -eq 0) { 'desactive' } else { 'ACTIVE (explicite)' }
                    } elseif ($build -ge 26100) { 'desactive (defaut OS)' } else { 'ACTIVE (defaut OS)' }
                    $states += "${proto}: $state"
                }
                [PSCustomObject]@{ Machine = $env:COMPUTERNAME; Build = $build; SMB1Serveur = $smb1; TLS = $states -join ' | ' }
            } -ErrorAction Stop
        } catch {
            Write-Log ("Impossible d'interroger {0} : {1}" -f $name, $_.Exception.Message) -Level WARN
        }
    })
    foreach ($r in $rows) {
        $bad = $r.SMB1Serveur -or $r.TLS -match 'ACTIVE'
        Write-Host ("  - {0} : SMBv1={1}, {2}" -f $r.Machine, $r.SMB1Serveur, $r.TLS) -ForegroundColor $(if ($bad) { 'Yellow' } else { 'Green' })
    }
    [void](Export-Report -Rows $rows -Name "Rapport_ProtocolesObsoletes")
}

function Invoke-Remediate18GenerateTreatmentPlan {
    Write-Section "Generer le plan de traitement de l'obsolescence (consolide)" Cyan
    Write-Info "Impact : AUCUN. Consolide en un seul CSV categorise : OS hors support / bientot hors support," `
               "comptes avec SPN sans AES, comptes 'DES uniquement', niveau fonctionnel du domaine." `
               "(Les audits SMBv1/TLS/NTLMv1 necessitent un ciblage ou un delai d'observation : a lancer a part.)"

    if (-not (Confirm-Action "Lancer la consolidation du plan de traitement de l'obsolescence")) { return }
    $rows = [System.Collections.Generic.List[object]]::new()

    foreach ($c in @(Get-ADComputer -Filter 'Enabled -eq $true' -Properties OperatingSystem, OperatingSystemVersion | Where-Object { (Get-ComputerAccountKind -Computer $_) -ne 'MSA' })) {
        $st = Get-OsSupportStatus -OS $c.OperatingSystem -Version $c.OperatingSystemVersion
        if ($st.Statut -in 'EOL', 'BIENTOT') {
            $rows.Add([PSCustomObject]@{ Priorite = $(if ($st.Statut -eq 'EOL') { 1 } else { 2 }); Categorie = "OS $($st.Statut)"; Element = $c.Name; Detail = "$($c.OperatingSystem) - $($st.Detail)" })
        }
    }
    foreach ($a in @(Get-ADUser -LDAPFilter "(&(servicePrincipalName=*)(!(sAMAccountName=krbtgt*))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" -Properties 'msDS-SupportedEncryptionTypes' | Where-Object { -not (Test-HasAesEncryptionType $_.'msDS-SupportedEncryptionTypes') })) {
        $rows.Add([PSCustomObject]@{ Priorite = 2; Categorie = 'Compte de service (SPN) sans AES'; Element = $a.SamAccountName; Detail = (Get-SupportedEncryptionTypesLabel -Value $a.'msDS-SupportedEncryptionTypes') })
    }
    foreach ($a in @(Get-ADUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=2097152)")) {
        $rows.Add([PSCustomObject]@{ Priorite = 1; Categorie = 'Compte DES uniquement'; Element = $a.SamAccountName; Detail = 'USE_DES_KEY_ONLY' })
    }
    $mode = [string](Get-CachedADDomain).DomainMode
    if ($mode -match '2003|2008|2012Domain$') {
        $rows.Add([PSCustomObject]@{ Priorite = 2; Categorie = 'Niveau fonctionnel'; Element = (Get-CachedADDomain).DNSRoot; Detail = "$mode : viser Windows2016Domain" })
    }

    [void](Export-Report -Rows ($rows | Sort-Object Priorite, Categorie, Element) -Name "Plan_Traitement_Obsolescence")
}

# ============================================================
#  THEME 15 - JOURNALISATION ET DETECTION
# ============================================================

# Sous-categories ciblees par GUID (identifiant stable, independant de la langue de l'OS).
$Script:AuditSubcategories = @(
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
    [PSCustomObject]@{ Name = "Sensitive Privilege Use";            Guid = "{0CCE9228-69AE-11D9-BED3-505054503030}" }
    [PSCustomObject]@{ Name = "Other Account Logon Events";         Guid = "{0CCE9241-69AE-11D9-BED3-505054503030}" }
    [PSCustomObject]@{ Name = "Special Logon";                      Guid = "{0CCE921B-69AE-11D9-BED3-505054503030}" }
    [PSCustomObject]@{ Name = "Logon";                              Guid = "{0CCE9215-69AE-11D9-BED3-505054503030}" }
    [PSCustomObject]@{ Name = "Logoff";                             Guid = "{0CCE9216-69AE-11D9-BED3-505054503030}" }
    [PSCustomObject]@{ Name = "Account Lockout";                    Guid = "{0CCE9217-69AE-11D9-BED3-505054503030}" }
    [PSCustomObject]@{ Name = "Audit Policy Change";                Guid = "{0CCE922F-69AE-11D9-BED3-505054503030}" }
    [PSCustomObject]@{ Name = "Process Creation";                   Guid = "{0CCE922B-69AE-11D9-BED3-505054503030}" }
)

function Invoke-SafeEnableDCAuditPolicy {
    Write-Section "Activation de la politique d'audit avancee sur les controleurs de domaine" Cyan
    Write-Info "Impact : AUCUN sur le fonctionnement (journalisation uniquement). Augmente le volume du" `
               "journal Securite : la taille du journal est portee a 1 Go minimum si elle est inferieure." `
               "Attention : si une GPO definit une strategie d'audit AVANCEE pour les DC, elle ecrasera" `
               "ces reglages locaux au prochain rafraichissement (verifiez avec l'item 6)."

    $dcs = @(Get-ReachableDCs)
    if ($dcs.Count -eq 0) { return }
    $subcategories = $Script:AuditSubcategories

    Write-Host ("Activation Succes+Echec sur {0} sous-categories d'audit, sur {1} DC :" -f $subcategories.Count, $dcs.Count) -ForegroundColor Yellow
    Write-ListPreview -Items $dcs -Format { param($d) $d.HostName }
    if (-not (Confirm-Action "Activer l'audit avance (auditpol) sur tous les DC")) { return }

    foreach ($dc in $dcs) {
        Invoke-Guarded -Description ("auditpol /set + taille du journal Securite sur {0}" -f $dc.HostName) -Action {
            $results = Invoke-OnDC -ComputerName $dc.HostName -ScriptBlock {
                param($cats)
                # Force la prise en compte des sous-categories (sinon une strategie d'audit 'classique'
                # par categorie, definie par GPO, peut les ignorer).
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -Type DWord
                foreach ($c in $cats) {
                    $null = & auditpol.exe /set /subcategory:"$($c.Guid)" /success:enable /failure:enable 2>&1
                    [PSCustomObject]@{ Name = $c.Name; Success = ($LASTEXITCODE -eq 0) }
                }
                $log = Get-WinEvent -ListLog Security
                if ($log.MaximumSizeInBytes -lt 1GB) { & wevtutil.exe sl Security /ms:1073741824 | Out-Null }
            } -ArgumentList (, $subcategories) -ErrorAction Stop

            $failed = @($results | Where-Object { -not $_.Success })
            if ($failed.Count -gt 0) {
                foreach ($f in $failed) { Write-Log ("Echec auditpol pour la sous-categorie '{0}' sur {1}." -f $f.Name, $dc.HostName) -Level ERROR }
                throw ("{0}/{1} sous-categorie(s) non appliquee(s) sur {2}." -f $failed.Count, @($results).Count, $dc.HostName)
            }
        }
    }
}

function Invoke-Audit19EffectiveAuditPolicy {
    Write-Section "Politique d'audit EFFECTIVE sur les DC (auditpol /backup, independant de la langue)" Magenta
    $dcs = @(Get-ReachableDCs)
    if ($dcs.Count -eq 0) { return }
    $wanted = $Script:AuditSubcategories

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($dc in $dcs) {
        try {
            $csv = Invoke-OnDC -ComputerName $dc.HostName -ScriptBlock {
                $tmp = Join-Path $env:TEMP ("auditpol_{0}.csv" -f [guid]::NewGuid())
                & auditpol.exe /backup /file:$tmp | Out-Null
                $data = Import-Csv -Path $tmp
                Remove-Item $tmp -Force -ErrorAction SilentlyContinue
                $log = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
                [PSCustomObject]@{ Rows = @($data | Where-Object { $_.'Subcategory GUID' } | Select-Object 'Subcategory GUID', 'Setting Value'); MaxMo = if ($log) { [int]($log.MaximumSizeInBytes / 1MB) } else { $null } }
            } -ErrorAction Stop
            $missing = @()
            foreach ($w in $wanted) {
                $line = $csv.Rows | Where-Object { $_.'Subcategory GUID' -eq $w.Guid } | Select-Object -First 1
                $val = if ($line) { [int]$line.'Setting Value' } else { 0 }
                $label = switch ($val) { 0 { 'Aucun' } 1 { 'Succes' } 2 { 'Echec' } 3 { 'Succes+Echec' } default { $val } }
                $rows.Add([PSCustomObject]@{ DC = $dc.HostName; SousCategorie = $w.Name; Reglage = $label })
                if ($val -ne 3) { $missing += "$($w.Name)=$label" }
            }
            Write-Host ("  - {0} : {1}/{2} sous-categories en Succes+Echec, journal Securite {3} Mo" -f $dc.HostName, ($wanted.Count - $missing.Count), $wanted.Count, $csv.MaxMo) -ForegroundColor $(if ($missing.Count -eq 0) { 'Green' } else { 'Yellow' })
            if ($missing.Count -gt 0) { Write-Host ("      Incomplet : {0}" -f ($missing -join ', ')) -ForegroundColor DarkYellow }
        } catch { Write-Log ("Lecture de la politique d'audit impossible sur {0} : {1}" -f $dc.HostName, $_.Exception.Message) -Level WARN }
    }
    [void](Export-Report -Rows $rows -Name "Rapport_PolitiqueAudit_DC")
}

function Invoke-SafeEnablePowerShellLogging {
    Write-Section "Activation de la journalisation PowerShell (Script Block + modules) via GPO" Cyan
    Write-Info "Impact : AUCUN fonctionnel. Journalisation uniquement (evenements 4103/4104)."

    if (-not (Test-GroupPolicyModule)) { return }
    $gpoName = "SEC - Audit PowerShell Logging"
    $ouDCs = Get-DomainControllersOU

    Write-Host ("GPO cible : '{0}', lien prevu sur : {1}" -f $gpoName, $ouDCs) -ForegroundColor Yellow
    if (-not (Confirm-Action "Creer/mettre a jour cette GPO et l'activer sur l'OU Domain Controllers")) { return }

    Invoke-Guarded -Description "Creation/MAJ GPO PowerShell Logging" -Action {
        $null = Get-OrCreateGpo -Name $gpoName
        Set-PowerShellLoggingInGpo -GpoName $gpoName
        Add-GpoLinkSafe -Name $gpoName -Targets $ouDCs
    }
}

function Invoke-Audit19ObjectAuditingStatus {
    Write-Section "Audit du SACL (auditing) sur les objets AD sensibles" Magenta
    Write-Info "Verifie si un audit 'Ecriture' (Succes) existe sur la racine du domaine, AdminSDHolder et" `
               "le conteneur des GPO - necessaire, en plus de la sous-categorie 'Modifications du service" `
               "d'annuaire', pour generer les evenements 5136."

    try {
        $domainDN = (Get-CachedADDomain).DistinguishedName
    } catch {
        Write-Log ("Impossible de lire le domaine : {0}" -f $_.Exception.Message) -Level ERROR
        return
    }
    foreach ($dn in @($domainDN, "CN=AdminSDHolder,CN=System,$domainDN", "CN=Policies,CN=System,$domainDN")) {
        try {
            $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dn")
            $entry.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Sacl
            $hasAudit = @($entry.ObjectSecurity.GetAuditRules($true, $true, [System.Security.Principal.SecurityIdentifier]) |
                Where-Object { ($_.AuditFlags -band [System.Security.AccessControl.AuditFlags]::Success) -and ($_.ActiveDirectoryRights -band ([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor [System.DirectoryServices.ActiveDirectoryRights]::GenericAll)) }).Count -gt 0
            Write-Host ("  - {0} : audit ecriture present = {1}" -f $dn, $hasAudit) -ForegroundColor $(if ($hasAudit) { 'Green' } else { 'Yellow' })
        } catch {
            Write-Log ("Impossible de lire le SACL de {0} (privilege 'Gerer l'audit et le journal de securite' requis) : {1}" -f $dn, $_.Exception.Message) -Level WARN
        }
    }
}

function Invoke-Remediate19ConfigureObjectAuditing {
    Write-Section "Configurer l'audit SACL sur les objets AD sensibles" Red
    Write-Info "Ajoute une regle d'audit 'Ecrire les proprietes' (Succes, objet + descendants) pour 'Tout le" `
               "monde' (SID S-1-1-0, independant de la langue) sur la racine du domaine, AdminSDHolder et" `
               "le conteneur des GPO. Additif uniquement. Risque : volume accru du journal Securite."

    try { $domainDN = (Get-CachedADDomain).DistinguishedName } catch { Write-Log $_.Exception.Message -Level ERROR; return }
    $targets = @($domainDN, "CN=AdminSDHolder,CN=System,$domainDN", "CN=Policies,CN=System,$domainDN")
    if (-not (Confirm-Action ("Ajouter l'audit d'ecriture (Succes) sur {0} objets sensibles" -f $targets.Count) -Strong)) { return }

    foreach ($dn in $targets) {
        Invoke-Guarded -Description ("Ajout de la regle d'audit sur {0}" -f $dn) -Action {
            $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dn")
            $entry.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Sacl
            $everyone = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
            $auditRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
                $everyone,
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
    Write-Section "Configurer la redirection des journaux vers un collecteur (SIEM / WEF)" Red
    Write-Info "Pousse 'Configurer le gestionnaire d'abonnements cible' (Windows Event Forwarding) vers" `
               "les DC. Prerequis : collecteur WEF existant (abonnement, certificats si HTTPS). Le service" `
               "'Service reseau' doit aussi pouvoir lire le journal Securite (ajout automatique de son SID" `
               "a la permission de lecture du journal via la GPO)."

    if (-not (Test-GroupPolicyModule)) { return }
    $collector = Read-Host "URL du collecteur WEF (ex : https://wec.domaine.local:5986/wsman/SubscriptionManager/WEC)"
    if ([string]::IsNullOrWhiteSpace($collector)) { Write-Log "URL vide, action annulee." -Level WARN; return }
    if ($collector -notmatch '^https?://[^/]+') { Write-Log "URL invalide (http(s)://serveur:port/...)." -Level ERROR; return }

    $ouDCs = Get-DomainControllersOU
    $gpoName = "SEC - Redirection journaux (WEF)"
    if (-not (Confirm-Action ("Creer/lier la GPO '{0}' sur l'OU Domain Controllers (collecteur : {1})" -f $gpoName, $collector) -Strong)) { return }

    Invoke-Guarded -Description ("Creation/MAJ de la GPO {0}" -f $gpoName) -Action {
        $null = Get-OrCreateGpo -Name $gpoName
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager" -ValueName "1" -Type String -Value ("Server={0},Refresh=60" -f $collector) | Out-Null
        # Lecture du journal Securite par NETWORK SERVICE (S-1-5-20), requise par le client WEF.
        Set-GPRegistryValue -Name $gpoName -Key "HKLM\Software\Policies\Microsoft\Windows\EventLog\Security" -ValueName "ChannelAccess" -Type String -Value "O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;S-1-5-20)" | Out-Null
        Add-GpoLinkSafe -Name $gpoName -Targets $ouDCs
    }
    Write-OutcomeLog "GPO liee sur l'OU Domain Controllers. Le service WinRM doit etre actif sur les DC (theme 8 > 4)."
}

# ============================================================
#  THEME 18 - HYGIENE DES COMPTES INACTIFS (logique commune)
# ============================================================

function Read-InactivityThresholds {
    <#
        Seuils d'inactivite laisses a l'appreciation du technicien (conges longue duree,
        comptes de service peu sollicites, saisonnalite...). lastLogonTimestamp n'etant
        replique qu'avec un retard pouvant atteindre 14 jours, un seuil < 30 jours n'est
        pas fiable et est refuse.
    #>
    param([int]$DefaultUserDays = 180, [int]$DefaultComputerDays = 90)
    Write-Host ""
    Write-Info "Seuils d'inactivite : a ajuster au contexte (un compte 'inactif' peut etre un salarie en" `
               "conge, un compte de service saisonnier...). Minimum 30 jours (precision de lastLogonTimestamp)."
    return [PSCustomObject]@{
        UserDays     = Read-IntValue -Prompt "Seuil d'inactivite UTILISATEURS en jours" -Default $DefaultUserDays -Min 30 -Max 3650
        ComputerDays = Read-IntValue -Prompt "Seuil d'inactivite ORDINATEURS en jours" -Default $DefaultComputerDays -Min 30 -Max 3650
    }
}

function Read-DisableCutoffDate {
    param([Parameter(Mandatory)][string]$Label)
    $dateInput = Read-Host ("Desactiver {0} dont la derniere activite est ANTERIEURE au (jj/mm/aaaa)" -f $Label)
    $parsed = [datetime]::MinValue
    $ok = $false
    foreach ($fmt in @("dd/MM/yyyy", "d/M/yyyy", "yyyy-MM-dd")) {
        if ([datetime]::TryParseExact($dateInput, $fmt, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$parsed)) { $ok = $true; break }
    }
    if (-not $ok) { Write-Log ("Date invalide : '{0}'. Format attendu jj/mm/aaaa." -f $dateInput) -Level ERROR; return $null }
    if ($parsed -gt (Get-Date).AddDays(-30)) {
        Write-Host "Date a moins de 30 jours (ou future) : lastLogonTimestamp n'est pas assez precis (retard de replication jusqu'a 14 j) et des comptes ACTIFS seraient concernes." -ForegroundColor Yellow
        if (-not (Read-YesNo -Prompt "Continuer avec cette date ?")) { return $null }
    }
    return $parsed
}

function Read-ExtraExclusionGroups {
    <#
        Garde-fou : membres de ces groupes jamais desactives/deplaces. Une liste de groupes a
        privileges est exclue par defaut ; des groupes supplementaires peuvent etre ajoutes.
    #>
    Write-Host ""
    Write-Host "Groupes EXCLUS par defaut (jamais desactives/deplaces) :" -ForegroundColor DarkGray
    Write-Host ("  {0}" -f ($Script:DefaultExcludedGroups -join ', ')) -ForegroundColor DarkGray

    $extraInput = Read-Host "Groupes SUPPLEMENTAIRES a exclure (comptes de service, VIP...), separes par une virgule (vide = aucun)"
    $extra = @()
    if (-not [string]::IsNullOrWhiteSpace($extraInput)) {
        foreach ($g in @($extraInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
            if (Get-ADGroup -Filter "Name -eq '$($g -replace "'", "''")'" -ErrorAction SilentlyContinue) { $extra += $g }
            else { Write-Log ("Groupe '{0}' introuvable dans l'annuaire - ignore." -f $g) -Level WARN }
        }
    }
    return @($Script:DefaultExcludedGroups + $extra | Select-Object -Unique)
}

function Get-InactiveAccountCandidates {
    <#
        Comptes ACTIVES consideres inactifs depuis $Cutoff, avec garde-fous anti-faux positifs :
          - inclut les comptes JAMAIS connectes (lastLogonTimestamp vide), sauf s'ils ont ete
            crees apres la date seuil ;
          - exclut un compte dont le mot de passe a change apres la date seuil (pour un
            ordinateur, le mot de passe machine est renouvele tous les 30 j tant qu'il vit) ;
          - exclut comptes d'approbation (trusts), DC/RODC, objets de cluster (CNO/VCO),
            comptes de service geres (gMSA/MSA/dMSA : renvoyes par Get-ADComputer), compte
            Entra Seamless SSO (AZUREADSSOACC$, jamais "connecte" mais indispensable), comptes
            krbtgt*, comptes systeme et membres des groupes exclus, UO exclues, quarantaine.
        Chaque objet porte la raison d'exclusion eventuelle (colonne Exclusion) pour l'audit.
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('User', 'Computer')][string]$Type,
        [Parameter(Mandatory)][datetime]$Cutoff,
        [string[]]$ExcludedOUs = @(),
        [string[]]$QuarantineOUs = @(),
        $ProtectedSids,
        $ProtectedComputerDNs
    )
    $ft = $Cutoff.ToFileTimeUtc()
    $filter = "(&(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(userAccountControl:1.2.840.113556.1.4.803:=2048))(|(!(lastLogonTimestamp=*))(lastLogonTimestamp<=$ft)))"
    $props = @('lastLogonTimestamp', 'pwdLastSet', 'whenCreated', 'servicePrincipalName', 'primaryGroupID', 'Description')
    $objs = if ($Type -eq 'User') { @(Get-ADUser -LDAPFilter $filter -Properties $props) }
            else { @(Get-ADComputer -LDAPFilter $filter -Properties ($props + 'OperatingSystem')) }

    foreach ($o in $objs) {
        $llt = ConvertFrom-FileTimeSafe $o.lastLogonTimestamp
        $pls = ConvertFrom-FileTimeSafe $o.pwdLastSet
        $reason = $null
        $kind = if ($Type -eq 'Computer') { Get-ComputerAccountKind -Computer $o } else { 'User' }
        if ($ProtectedSids -and $ProtectedSids.Contains($o.SID.Value)) { $reason = 'compte protege (systeme / groupe exclu)' }
        elseif ($kind -eq 'DC' -or ($ProtectedComputerDNs -and $ProtectedComputerDNs.Contains($o.DistinguishedName))) { $reason = 'controleur de domaine' }
        elseif ($kind -eq 'MSA') { $reason = 'compte de service gere (gMSA/MSA/dMSA)' }
        elseif ($kind -eq 'EntraSSO') { $reason = 'compte Entra Seamless SSO (AZUREADSSOACC)' }
        elseif ($o.SamAccountName -like 'krbtgt*') { $reason = 'compte krbtgt' }
        elseif (Test-DNUnderAny -DN $o.DistinguishedName -Containers $QuarantineOUs) { $reason = 'deja en quarantaine' }
        elseif (Test-DNUnderAny -DN $o.DistinguishedName -Containers $ExcludedOUs) { $reason = 'UO exclue' }
        elseif ($o.whenCreated -gt $Cutoff) { $reason = 'cree apres la date seuil' }
        elseif ($pls -and $pls -gt $Cutoff) { $reason = 'mot de passe change apres la date seuil (activite recente)' }
        elseif ($kind -eq 'Cluster') { $reason = 'objet de cluster (CNO/VCO)' }

        [PSCustomObject]@{
            SamAccountName    = $o.SamAccountName
            Type              = $Type
            DerniereConnexion = $llt
            JamaisConnecte    = (-not $llt)
            MdpChange         = $pls
            Cree              = $o.whenCreated
            OS                = if ($Type -eq 'Computer') { $o.OperatingSystem } else { $null }
            Exclusion         = $reason
            DistinguishedName = $o.DistinguishedName
        }
    }
}

function Add-DisabledMarkerToDescription {
    # Ajoute (sans ecraser la description existante) "Desactive le : <date>" pour tracer
    # directement dans l'annuaire QUAND l'objet a ete desactive par le script.
    param([Parameter(Mandatory)][string]$Identity)
    $marker = "Desactive le : {0} (SEC)" -f (Get-Date -Format "dd/MM/yyyy")
    $obj = Get-ADObject -Identity $Identity -Properties Description
    $newDescription = if ([string]::IsNullOrWhiteSpace($obj.Description)) { $marker } else { "$($obj.Description) | $marker" }
    if ($newDescription.Length -gt 1024) { $newDescription = $newDescription.Substring($newDescription.Length - 1024) }
    Set-ADObject -Identity $Identity -Replace @{ Description = $newDescription }
}

function Confirm-OrCreateOU {
    param([Parameter(Mandatory)][string]$Name)
    $domainDN = (Get-CachedADDomain).DistinguishedName
    $dn = "OU=$Name,$domainDN"
    Invoke-Guarded -Description ("Creation de l'UO '{0}' (si absente, protegee contre la suppression)" -f $Name) -Action {
        if (-not (Get-ADOrganizationalUnit -LDAPFilter "(ou=$Name)" -SearchBase $domainDN -SearchScope OneLevel -ErrorAction SilentlyContinue)) {
            New-ADOrganizationalUnit -Name $Name -Path $domainDN -ProtectedFromAccidentalDeletion $true
        }
    }
    return $dn
}

function Invoke-InactiveAccountsWorkflow {
    <#
        Workflow commun aux desactivations "par anciennete" et "par date" :
        perimetre -> seuils -> exclusions -> candidats (avec garde-fous) -> export CSV (y compris
        les exclusions, pour audit) -> selection eventuelle -> confirmation -> desactivation,
        marquage de la description, deplacement en UO de quarantaine (jamais de suppression).
    #>
    param([Parameter(Mandatory)][ValidateSet('Anciennete', 'Date')][string]$Mode)

    $applyUsers = Read-YesNo -Prompt "Traiter les UTILISATEURS inactifs ?" -Default $true
    $applyComputers = Read-YesNo -Prompt "Traiter les POSTES/SERVEURS inactifs ?" -Default $true
    if (-not $applyUsers -and -not $applyComputers) { Write-Log "Aucun perimetre selectionne, action annulee." -Level WARN; return }

    $cutUsers = $null; $cutComputers = $null
    if ($Mode -eq 'Anciennete') {
        $t = Read-InactivityThresholds
        $cutUsers = (Get-Date).AddDays(-$t.UserDays)
        $cutComputers = (Get-Date).AddDays(-$t.ComputerDays)
        $userOU = $Script:QuarantineOUName; $computerOU = $Script:QuarantineOUName
    } else {
        if ($applyUsers) { $cutUsers = Read-DisableCutoffDate -Label "les UTILISATEURS"; if (-not $cutUsers) { return } }
        if ($applyComputers) { $cutComputers = Read-DisableCutoffDate -Label "les POSTES/SERVEURS"; if (-not $cutComputers) { return } }
        $userOU = $Script:DisableUserOUName; $computerOU = $Script:DisableComputerOUName
    }

    $exclUsers = @(); $exclComputers = @()
    if ($applyUsers) { $exclUsers = @(Select-ExclusionOUs -Label "les UTILISATEURS") }
    if ($applyComputers) { $exclComputers = @(Select-ExclusionOUs -Label "les POSTES/SERVEURS") }
    $excludedGroups = @(Read-ExtraExclusionGroups)

    Write-Host "Calcul des candidats et application des garde-fous..." -ForegroundColor DarkGray
    $protectedSids = Get-AlwaysProtectedPrincipalSids
    $protectedSids.UnionWith((Get-ExpandedGroupMemberSids -GroupNames $excludedGroups))
    $protectedDCs = Get-ProtectedDCComputerDNs
    $domainDN = (Get-CachedADDomain).DistinguishedName
    $quarantine = @("OU=$Script:QuarantineOUName,$domainDN", "OU=$Script:DisableUserOUName,$domainDN", "OU=$Script:DisableComputerOUName,$domainDN")

    $all = @()
    if ($applyUsers) { $all += @(Get-InactiveAccountCandidates -Type User -Cutoff $cutUsers -ExcludedOUs $exclUsers -QuarantineOUs $quarantine -ProtectedSids $protectedSids) }
    if ($applyComputers) { $all += @(Get-InactiveAccountCandidates -Type Computer -Cutoff $cutComputers -ExcludedOUs $exclComputers -QuarantineOUs $quarantine -ProtectedSids $protectedSids -ProtectedComputerDNs $protectedDCs) }

    $selected = @($all | Where-Object { -not $_.Exclusion })
    $skipped = @($all | Where-Object { $_.Exclusion })
    Write-Host ""
    foreach ($ty in 'User', 'Computer') {
        $s = @($selected | Where-Object Type -eq $ty); $k = @($skipped | Where-Object Type -eq $ty)
        if ($s.Count -or $k.Count) {
            Write-Host ("{0} a desactiver : {1} (dont {2} jamais connecte(s)) ; {3} ecarte(s) par garde-fou" -f $(if ($ty -eq 'User') { 'Utilisateurs' } else { 'Postes/serveurs' }), $s.Count, @($s | Where-Object JamaisConnecte).Count, $k.Count) -ForegroundColor Yellow
        }
    }
    $skipped | Group-Object Exclusion | ForEach-Object { Write-Host ("    ecartes - {0} : {1}" -f $_.Name, $_.Count) -ForegroundColor DarkGray }

    [void](Export-Report -Name ("Desactivation_{0}_Revue" -f $Mode) -Rows ($all | Select-Object SamAccountName, Type, DerniereConnexion, JamaisConnecte, MdpChange, Cree, OS, @{N='Action';E={ if ($_.Exclusion) { "Exclu : $($_.Exclusion)" } else { 'Desactive + deplace' } }}, DistinguishedName))

    if ($selected.Count -eq 0) { Write-Log "Aucun compte a traiter apres application des garde-fous." -Level OK; return }

    if (Read-YesNo -Prompt "Afficher la liste et ne selectionner qu'une partie des comptes ?") {
        $selected = @(Select-FromList -Items $selected -Prompt "Comptes a traiter" -Display { param($c) "{0} [{1}] derniere connexion : {2}" -f $c.SamAccountName, $c.Type, $(if ($c.DerniereConnexion) { $c.DerniereConnexion.ToString('dd/MM/yyyy') } else { 'jamais' }) })
        if ($selected.Count -eq 0) { return }
    }

    if (-not (Confirm-Action ("Desactiver et deplacer en quarantaine {0} compte(s) (jamais supprimes, reversible)" -f $selected.Count) -Strong)) { return }

    $targets = @{}
    if (@($selected | Where-Object Type -eq 'User').Count) { $targets['User'] = Confirm-OrCreateOU -Name $userOU }
    if (@($selected | Where-Object Type -eq 'Computer').Count) { $targets['Computer'] = Confirm-OrCreateOU -Name $computerOU }

    foreach ($c in $selected) {
        Invoke-Guarded -Description ("Desactivation + quarantaine {0} {1}" -f $c.Type, $c.SamAccountName) -Action {
            Disable-ADAccount -Identity $c.DistinguishedName
            Add-DisabledMarkerToDescription -Identity $c.DistinguishedName
            Move-ADObject -Identity $c.DistinguishedName -TargetPath $targets[$c.Type]
        }
    }
    Write-OutcomeLog "Comptes desactives et deplaces. Retour arriere : Enable-ADAccount + deplacement vers l'UO d'origine (colonne DistinguishedName du CSV de revue)."

    if ($Mode -eq 'Date' -and (Read-YesNo -Prompt "Automatiser cette desactivation via une tache planifiee recurrente ?")) {
        Invoke-AutomationSetupScheduledTask
    }
}

function Invoke-RiskyDisableInactiveAccounts {
    Write-Section "Desactivation des comptes inactifs par ANCIENNETE (quarantaine)" Red
    Write-Info "Risque : un compte 'inactif' peut etre un salarie en conge longue duree, un compte de" `
               "service peu utilise, un poste eteint. Les comptes sont DESACTIVES et DEPLACES vers" `
               ("'{0}' (jamais supprimes). Garde-fous : DC, comptes systeme, groupes a privileges," -f $Script:QuarantineOUName) `
               "comptes d'approbation, objets de cluster, comptes recents ou au mot de passe recemment change."
    Invoke-InactiveAccountsWorkflow -Mode Anciennete
}

function Invoke-RiskyDisableByDate {
    Write-Section "Desactivation des postes/serveurs et/ou utilisateurs a partir d'une DATE choisie" Red
    Write-Info ("Les comptes sont DESACTIVES et DEPLACES vers '{0}' (utilisateurs) / '{1}' (ordinateurs)," -f $Script:DisableUserOUName, $Script:DisableComputerOUName) `
               "jamais supprimes. Memes garde-fous que la desactivation par anciennete."
    Invoke-InactiveAccountsWorkflow -Mode Date
}

function Invoke-ReportInactiveAccounts {
    Write-Section "Rapport : comptes inactifs (actifs dans l'annuaire mais sans activite)" Magenta
    Write-Info "Inclut les comptes jamais connectes ; colonne 'Exclusion' = motif pour lequel une" `
               "desactivation automatique NE les traiterait PAS (DC, cluster, compte recent...)."
    $t = Read-InactivityThresholds
    $protected = Get-AlwaysProtectedPrincipalSids
    $rows = @(Get-InactiveAccountCandidates -Type User -Cutoff (Get-Date).AddDays(-$t.UserDays) -ProtectedSids $protected) +
            @(Get-InactiveAccountCandidates -Type Computer -Cutoff (Get-Date).AddDays(-$t.ComputerDays) -ProtectedSids $protected -ProtectedComputerDNs (Get-ProtectedDCComputerDNs))
    $real = @($rows | Where-Object { -not $_.Exclusion })
    Write-Host ("{0} utilisateur(s) inactif(s) > {1} j, {2} ordinateur(s) inactif(s) > {3} j (hors exclusions)." -f @($real | Where-Object Type -eq 'User').Count, $t.UserDays, @($real | Where-Object Type -eq 'Computer').Count, $t.ComputerDays) -ForegroundColor Yellow
    [void](Export-Report -Rows $rows -Name ("Rapport_ComptesInactifs_U{0}j_C{1}j" -f $t.UserDays, $t.ComputerDays))
}

# ============================================================
#  AUTOMATISATION (tache planifiee de desactivation)
# ============================================================

function Get-DisableByDateScheduledScriptContent {
    <#
        Script autonome deploye sur le DC cible et execute par la tache planifiee. Parametres
        figes a la configuration (pour les changer : relancer la configuration). Reprend les
        MEMES garde-fous que l'action manuelle (cf. Get-InactiveAccountCandidates).
    #>
    param(
        [int]$DaysUsers, [int]$DaysComputers, [bool]$ApplyUsers, [bool]$ApplyComputers,
        [string[]]$ExcludedOUsUsers, [string[]]$ExcludedOUsComputers, [string[]]$ExcludedGroupSids,
        [string]$DisableUserOUName, [string]$DisableComputerOUName, [bool]$ReportOnly
    )
    $lit = { param($arr) (@($arr) | Where-Object { $_ } | ForEach-Object { "'{0}'" -f ($_ -replace "'", "''") }) -join ', ' }

    $header = @"
# Parametres generes par le menu Automatisation le $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
`$DaysUsers = $DaysUsers
`$DaysComputers = $DaysComputers
`$ApplyUsers = `$$ApplyUsers
`$ApplyComputers = `$$ApplyComputers
`$ReportOnly = `$$ReportOnly
`$ExcludedOUsUsers = @($(& $lit $ExcludedOUsUsers))
`$ExcludedOUsComputers = @($(& $lit $ExcludedOUsComputers))
`$ExcludedGroupSids = @($(& $lit $ExcludedGroupSids))
`$DisableUserOUName = '$($DisableUserOUName -replace "'", "''")'
`$DisableComputerOUName = '$($DisableComputerOUName -replace "'", "''")'
"@

    $body = @'
# Disable-ByDate.ps1
# Deploye et execute automatiquement par la tache planifiee "SEC - Desactivation Auto (date/anciennete)".
# Ne PAS executer manuellement sans avoir revu les parametres et exclusions ci-dessus.

$logDir = "C:\SEC-Scripts"
$logFile = Join-Path $logDir "Disable-ByDate.log"

function Write-DisLog {
    param([string]$Message, [string]$Type = "Information")
    $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Add-Content -Path $logFile -Value $line -Encoding UTF8
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("SEC-AutoDisable")) {
            New-EventLog -LogName Application -Source "SEC-AutoDisable" -ErrorAction SilentlyContinue
        }
        $id = if ($Type -eq "Error") { 2001 } else { 2000 }
        Write-EventLog -LogName Application -Source "SEC-AutoDisable" -EventId $id -EntryType $Type -Message $Message -ErrorAction SilentlyContinue
    } catch { }
}

function ConvertFrom-FT { param($v) if ($null -eq $v -or [int64]$v -le 0 -or [int64]$v -eq [int64]::MaxValue) { $null } else { [DateTime]::FromFileTime([int64]$v) } }
function Test-Under { param([string]$DN, [string[]]$List) foreach ($c in $List) { if ($c -and $DN.EndsWith(",$c", [StringComparison]::OrdinalIgnoreCase)) { return $true } } return $false }

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $domain = Get-ADDomain -ErrorAction Stop
} catch {
    Write-DisLog ("Impossible de contacter le domaine : {0}. Execution annulee." -f $_.Exception.Message) "Error"
    exit 1
}
$domainDN = $domain.DistinguishedName
$sid = $domain.DomainSID.Value
$mode = if ($ReportOnly) { "RAPPORT SEUL (aucune modification)" } else { "DESACTIVATION" }
Write-DisLog "Debut de l'execution planifiee - mode $mode (utilisateurs > $DaysUsers j / postes > $DaysComputers j)."

# --- Garde-fous non desactivables ---
$protected = [System.Collections.Generic.HashSet[string]]::new()
foreach ($rid in 500, 501, 502) { [void]$protected.Add("$sid-$rid") }
try { [void]$protected.Add(([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value) } catch { }
foreach ($g in $ExcludedGroupSids) {
    try {
        # Groupes de foret (Enterprise/Schema Admins...) : interroges sur le domaine racine.
        $p = @{ Identity = $g; Recursive = $true; ErrorAction = 'Stop' }
        if ($g -notlike "$sid-*" -and $g -notlike 'S-1-5-32-*') { $p['Server'] = (Get-ADForest).RootDomain }
        Get-ADGroupMember @p | ForEach-Object { [void]$protected.Add($_.SID.Value) }
    } catch {
        Write-DisLog "Groupe d'exclusion '$g' illisible : execution ANNULEE par securite (une exclusion non appliquee pourrait desactiver un compte protege)." "Error"
        exit 1
    }
}
$quarantine = @("OU=$DisableUserOUName,$domainDN", "OU=$DisableComputerOUName,$domainDN", "OU=SEC-OU_QUARANTAINE_COMPTES_INACTIFS,$domainDN")
$report = [System.Collections.Generic.List[object]]::new()

function Invoke-Pass {
    param([string]$Type, [int]$Days, [string[]]$ExcludedOUs, [string]$TargetOU)
    $cutoff = (Get-Date).AddDays(-$Days)
    $ft = $cutoff.ToFileTimeUtc()
    $filter = "(&(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(userAccountControl:1.2.840.113556.1.4.803:=2048))(|(!(lastLogonTimestamp=*))(lastLogonTimestamp<=$ft)))"
    $props = @('lastLogonTimestamp', 'pwdLastSet', 'whenCreated', 'servicePrincipalName', 'primaryGroupID', 'Description')
    $objs = if ($Type -eq 'User') { @(Get-ADUser -LDAPFilter $filter -Properties $props) } else { @(Get-ADComputer -LDAPFilter $filter -Properties $props) }
    $done = 0; $failed = 0
    foreach ($o in $objs) {
        $pls = ConvertFrom-FT $o.pwdLastSet
        if ($protected.Contains($o.SID.Value)) { continue }
        if ($o.primaryGroupID -in 516, 521) { continue }
        # Comptes de service geres (derivent de 'computer'), Seamless SSO, krbtgt* : jamais traites.
        if ([string]$o.ObjectClass -in 'msDS-GroupManagedServiceAccount', 'msDS-ManagedServiceAccount', 'msDS-DelegatedManagedServiceAccount') { continue }
        if ($o.SamAccountName -ieq 'AZUREADSSOACC$' -or $o.SamAccountName -like 'krbtgt*') { continue }
        if (Test-Under $o.DistinguishedName $quarantine) { continue }
        if (Test-Under $o.DistinguishedName $ExcludedOUs) { continue }
        if ($o.whenCreated -gt $cutoff) { continue }
        if ($pls -and $pls -gt $cutoff) { continue }
        if ($Type -eq 'Computer' -and (@($o.servicePrincipalName) -match '^MSClusterVirtualServer/').Count -gt 0) { continue }
        $report.Add([PSCustomObject]@{ Date = Get-Date; Type = $Type; Compte = $o.SamAccountName; DerniereConnexion = ConvertFrom-FT $o.lastLogonTimestamp; DN = $o.DistinguishedName; Mode = $mode })
        if ($ReportOnly) { continue }
        try {
            Disable-ADAccount -Identity $o.DistinguishedName -ErrorAction Stop
            $marker = "Desactive le : {0} (SEC auto)" -f (Get-Date -Format "dd/MM/yyyy")
            $desc = if ([string]::IsNullOrWhiteSpace($o.Description)) { $marker } else { "$($o.Description) | $marker" }
            if ($desc.Length -gt 1024) { $desc = $desc.Substring($desc.Length - 1024) }
            Set-ADObject -Identity $o.DistinguishedName -Replace @{ Description = $desc } -ErrorAction Stop
            Move-ADObject -Identity $o.DistinguishedName -TargetPath $TargetOU -ErrorAction Stop
            $done++
        } catch {
            $failed++
            Write-DisLog ("Echec sur {0} : {1}" -f $o.SamAccountName, $_.Exception.Message) "Error"
        }
    }
    Write-DisLog ("{0} : {1} candidat(s) apres garde-fous, {2} traite(s), {3} echec(s) ({4} objet(s) examines)." -f $Type, @($report | Where-Object Type -eq $Type).Count, $done, $failed, $objs.Count)
}

foreach ($ou in @($DisableUserOUName, $DisableComputerOUName)) {
    if (-not $ReportOnly -and -not (Get-ADOrganizationalUnit -LDAPFilter "(ou=$ou)" -SearchBase $domainDN -SearchScope OneLevel -ErrorAction SilentlyContinue)) {
        Write-DisLog "UO de quarantaine '$ou' absente : relancez la configuration depuis le menu (elle la cree). Execution annulee." "Error"
        exit 1
    }
}
try {
    if ($ApplyUsers) { Invoke-Pass -Type User -Days $DaysUsers -ExcludedOUs $ExcludedOUsUsers -TargetOU "OU=$DisableUserOUName,$domainDN" }
    if ($ApplyComputers) { Invoke-Pass -Type Computer -Days $DaysComputers -ExcludedOUs $ExcludedOUsComputers -TargetOU "OU=$DisableComputerOUName,$domainDN" }
} catch {
    Write-DisLog ("ECHEC de l'execution : {0}" -f $_.Exception.Message) "Error"
}
if ($report.Count -gt 0) {
    $csv = Join-Path $logDir ("Disable-ByDate_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    $report | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8 -Delimiter ';'
    Write-DisLog "Detail : $csv"
}
Write-DisLog "Fin de l'execution planifiee."
'@
    return $header + "`r`n" + $body
}

function Grant-DisableAutomationPermissions {
    <#
        Delegue a un gMSA UNIQUEMENT les droits necessaires pour desactiver, annoter et deplacer
        des comptes utilisateur/ordinateur (ecriture de userAccountControl et description,
        creation/suppression d'objets User/Computer pour Move-ADObject). Jamais de droit Domain
        Admin. Note : les objets proteges par AdminSDHolder (adminCount=1) restent hors de portee.
    #>
    param(
        [Parameter(Mandatory)][string]$PrincipalSam,
        [Parameter(Mandatory)][string]$TargetDC,
        [Parameter(Mandatory)][string]$DelegationRootDN
    )
    $domainNetbios = (Get-CachedADDomain).NetBIOSName
    Invoke-Guarded -Description ("Delegation (userAccountControl, description, creation/suppression User/Computer) sur {0} a {1}" -f $DelegationRootDN, $PrincipalSam) -Action {
        Invoke-OnDC -ComputerName $TargetDC -ScriptBlock {
            param($rootDN, $account)
            foreach ($g in @(
                "${account}:WP;userAccountControl;user", "${account}:WP;userAccountControl;computer",
                "${account}:WP;description;user", "${account}:WP;description;computer",
                "${account}:CCDC;user", "${account}:CCDC;computer"
            )) {
                & dsacls.exe "$rootDN" /I:S /G $g | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "dsacls a echoue pour '$g' (code $LASTEXITCODE)." }
            }
            # Les ACE "Creer/Supprimer" doivent aussi s'appliquer a la racine elle-meme.
            & dsacls.exe "$rootDN" /G "${account}:CCDC;user" "${account}:CCDC;computer" | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "dsacls a echoue sur la racine (code $LASTEXITCODE)." }
        } -ArgumentList $DelegationRootDN, "$domainNetbios\$PrincipalSam" -ErrorAction Stop
    }
}

function Invoke-AutomationSetupScheduledTask {
    Write-Section "Configuration de la tache planifiee de desactivation automatique" Red
    Write-Info "Execute PERIODIQUEMENT la desactivation des comptes inactifs, avec les memes garde-fous que" `
               "l'action manuelle. Le seuil est une ANCIENNETE glissante (X jours sans activite) recalculee" `
               "a chaque execution. Le mode 'rapport seul' permet de valider le resultat avant d'activer" `
               "la desactivation reelle (recommande pour les premieres semaines)."

    $applyUsers = Read-YesNo -Prompt "Desactiver automatiquement les UTILISATEURS inactifs ?" -Default $true
    $applyComputers = Read-YesNo -Prompt "Desactiver automatiquement les POSTES/SERVEURS inactifs ?" -Default $true
    if (-not $applyUsers -and -not $applyComputers) { Write-Log "Aucun perimetre selectionne, configuration annulee." -Level WARN; return }

    $thresholds = Read-InactivityThresholds
    $excludedOUsUsers = @(); $excludedOUsComputers = @()
    if ($applyUsers) { $excludedOUsUsers = @(Select-ExclusionOUs -Label "les UTILISATEURS") }
    if ($applyComputers) { $excludedOUsComputers = @(Select-ExclusionOUs -Label "les POSTES/SERVEURS") }
    $excludedGroups = @(Read-ExtraExclusionGroups)
    # Les groupes sont figes par SID dans le script deploye (robuste aux renommages et a la langue).
    $excludedGroupSids = @(foreach ($g in $excludedGroups) {
        try {
            $ref = Resolve-ADGroupRef -Name $g
            $p = @{ Identity = $ref.Identity; ErrorAction = 'Stop' }
            if ($ref.Server) { $p['Server'] = $ref.Server }
            (Get-ADGroup @p).SID.Value
        } catch { Write-Log ("Groupe '{0}' introuvable : non inclus dans les exclusions." -f $g) -Level WARN }
    })

    $daysInterval = Read-IntValue -Prompt "Intervalle entre chaque execution, en jours" -Default 7 -Min 1 -Max 365
    $reportOnly = Read-YesNo -Prompt "Mode RAPPORT SEUL (aucune desactivation, CSV uniquement) ?" -Default $true

    $dcs = @(Get-DomainControllersList | Where-Object { -not $_.IsReadOnly })
    if ($dcs.Count -eq 0) { return }
    $pdc = (Get-CachedADDomain).PDCEmulator
    Write-Host "Controleurs de domaine inscriptibles :"
    for ($i = 0; $i -lt $dcs.Count; $i++) { Write-Host ("  [{0}] {1}{2}" -f $i, $dcs[$i].HostName, $(if ($dcs[$i].HostName -eq $pdc) { ' (PDC)' } else { '' })) }
    $defaultIdx = [Math]::Max(0, [array]::IndexOf(@($dcs | ForEach-Object { $_.HostName }), $pdc))
    $targetDC = $dcs[(Read-IntValue -Prompt "DC qui hebergera la tache planifiee" -Default $defaultIdx -Min 0 -Max ($dcs.Count - 1))].HostName

    Write-Host ""
    Write-Host "Compte d'execution de la tache :" -ForegroundColor Cyan
    Write-Info "  [1] SYSTEM du DC (defaut) : aucun droit a deleguer ; le script est stocke dans un dossier" `
               "      restreint a SYSTEM/Administrateurs." `
               "  [2] gMSA dedie (moindre privilege) : droits delegues sur une racine choisie, MAIS le gMSA" `
               "      doit recevoir le droit 'Ouvrir une session en tant que tache' sur le DC (a ajouter" `
               "      MANUELLEMENT dans 'Default Domain Controllers Policy'), sinon la tache echoue."
    $useGmsa = (Read-Host "Choix [1/2] (defaut 1)") -eq '2'
    $gmsaName = $null; $delegationRoot = $null
    $domain = Get-CachedADDomain
    if ($useGmsa) {
        $gmsaName = Read-Host "Nom du gMSA dedie a creer/reutiliser [defaut svc-ADAutoDisable]"
        if ([string]::IsNullOrWhiteSpace($gmsaName)) { $gmsaName = "svc-ADAutoDisable" }
        if ($gmsaName.Length -gt 15) { Write-Log "Nom de gMSA trop long (15 caracteres max)." -Level ERROR; return }
        $delegationRoot = Read-Host ("Racine de delegation (DN complet, vide = racine du domaine {0})" -f $domain.DistinguishedName)
        if ([string]::IsNullOrWhiteSpace($delegationRoot)) { $delegationRoot = $domain.DistinguishedName }
    }

    Write-Host ""
    Write-Host "Resume :" -ForegroundColor Yellow
    Write-Host ("  Utilisateurs      : {0}" -f $(if ($applyUsers) { "OUI, > $($thresholds.UserDays) j ($($excludedOUsUsers.Count) UO exclue(s))" } else { "non" }))
    Write-Host ("  Postes/Serveurs   : {0}" -f $(if ($applyComputers) { "OUI, > $($thresholds.ComputerDays) j ($($excludedOUsComputers.Count) UO exclue(s))" } else { "non" }))
    Write-Host ("  Groupes exclus    : {0}" -f ($excludedGroups -join ', '))
    Write-Host ("  Mode              : {0}" -f $(if ($reportOnly) { 'RAPPORT SEUL' } else { 'DESACTIVATION REELLE' }))
    Write-Host ("  Intervalle        : tous les {0} jour(s), a 03:00" -f $daysInterval)
    Write-Host ("  Hote              : {0}" -f $targetDC)
    Write-Host ("  Compte            : {0}" -f $(if ($useGmsa) { "gMSA $gmsaName (delegation sur $delegationRoot)" } else { 'SYSTEM' }))

    if (-not (Confirm-Action "Deployer le script et creer la tache planifiee avec ces parametres" -Strong)) { return }
    $wr = Test-WinRmConnectivity -ComputerNames @($targetDC)
    if ($wr.Reachable.Count -eq 0) { Write-Log "DC cible injoignable en WinRM : configuration annulee." -Level ERROR; return }

    # UO cibles creees ici (par l'administrateur), pas par la tache : le compte d'execution n'a
    # ainsi pas besoin du droit de creer des UO a la racine du domaine.
    $null = Confirm-OrCreateOU -Name $Script:DisableUserOUName
    $null = Confirm-OrCreateOU -Name $Script:DisableComputerOUName

    if ($useGmsa) {
        if (-not (Get-OrEnsureKdsRootKey)) { return }
        Invoke-Guarded -Description ("Creation du gMSA {0} (si absent)" -f $gmsaName) -Action {
            if (-not (Get-ADServiceAccount -Filter "Name -eq '$gmsaName'" -ErrorAction SilentlyContinue)) {
                $dcComputer = Get-ADComputer -Identity $targetDC.Split('.')[0]
                New-ADServiceAccount -Name $gmsaName -DNSHostName ("{0}.{1}" -f $gmsaName, $domain.DNSRoot) -PrincipalsAllowedToRetrieveManagedPassword $dcComputer.DistinguishedName -KerberosEncryptionType AES128, AES256 -Enabled $true
            }
        }
        Invoke-Guarded -Description ("Installation/test du gMSA {0} sur {1}" -f $gmsaName, $targetDC) -Action {
            Invoke-OnDC -ComputerName $targetDC -ScriptBlock {
                param($name)
                Import-Module ActiveDirectory -ErrorAction Stop
                Install-ADServiceAccount -Identity $name -ErrorAction Stop
                if (-not (Test-ADServiceAccount -Identity $name)) { throw "Test-ADServiceAccount a echoue (le DC doit peut-etre redemarrer ou purger ses tickets : klist -li 0x3e7 purge)." }
            } -ArgumentList $gmsaName -ErrorAction Stop
        }
        Grant-DisableAutomationPermissions -PrincipalSam "$gmsaName$" -TargetDC $targetDC -DelegationRootDN $delegationRoot
    }

    Invoke-Guarded -Description "Deploiement du script de desactivation automatique (dossier protege)" -Action {
        $content = Get-DisableByDateScheduledScriptContent -DaysUsers $thresholds.UserDays -DaysComputers $thresholds.ComputerDays `
            -ApplyUsers $applyUsers -ApplyComputers $applyComputers -ExcludedOUsUsers $excludedOUsUsers -ExcludedOUsComputers $excludedOUsComputers `
            -ExcludedGroupSids $excludedGroupSids -DisableUserOUName $Script:DisableUserOUName -DisableComputerOUName $Script:DisableComputerOUName -ReportOnly $reportOnly
        Invoke-OnDC -ComputerName $targetDC -ScriptBlock (Protect-RemoteScriptFolderScript) -ArgumentList $Script:RemoteScriptDir, "Disable-ByDate.ps1", $content -ErrorAction Stop
    }

    Invoke-Guarded -Description ("Creation de la tache planifiee (tous les {0} jours) sur {1}" -f $daysInterval, $targetDC) -Action {
        Invoke-OnDC -ComputerName $targetDC -ScriptBlock {
            param($gmsa, $domainNetbios, $intervalDays)
            $taskName = "SEC - Desactivation Auto (date/anciennete)"
            $act = New-ScheduledTaskAction -Execute "powershell.exe" -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "C:\SEC-Scripts\Disable-ByDate.ps1"'
            $trg = New-ScheduledTaskTrigger -Daily -DaysInterval $intervalDays -At "03:00"
            $prn = if ($gmsa) { New-ScheduledTaskPrincipal -UserId "$domainNetbios\$gmsa`$" -LogonType Password -RunLevel Highest }
                   else { New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest }
            $set = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd -ExecutionTimeLimit (New-TimeSpan -Hours 2)
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            Register-ScheduledTask -TaskName $taskName -Action $act -Trigger $trg -Principal $prn -Settings $set -Description "Desactivation automatique des comptes inactifs - deployee par le script de remediation AD" -ErrorAction Stop | Out-Null
        } -ArgumentList $gmsaName, $domain.NetBIOSName, $daysInterval -ErrorAction Stop
    }

    Write-OutcomeLog ("Tache 'SEC - Desactivation Auto (date/anciennete)' creee sur {0} ({1}), tous les {2} jours a 03:00. Journal : {3}\Disable-ByDate.log + journal Application (source SEC-AutoDisable, ID 2001 = echec)." -f $targetDC, $(if ($reportOnly) { 'rapport seul' } else { 'desactivation reelle' }), $daysInterval, $Script:RemoteScriptDir)
    if ($useGmsa) { Write-Log ("RAPPEL : ajoutez {0}\{1}$ au droit 'Ouvrir une session en tant que tache' (Default Domain Controllers Policy) sinon la tache ne demarrera pas." -f $domain.NetBIOSName, $gmsaName) -Level WARN }
    if ($reportOnly) { Write-Log "Mode rapport seul : relancez cette configuration avec la desactivation reelle une fois les CSV valides." -Level INFO }
}

function Invoke-AutomationShowStatus {
    Write-Section "Etat des taches planifiees deployees par le script" Magenta
    $dcs = @(Get-ReachableDCs)
    if ($dcs.Count -eq 0) { return }
    foreach ($dc in $dcs) {
        try {
            $tasks = @(Invoke-OnDC -ComputerName $dc.HostName -ScriptBlock {
                foreach ($t in @(Get-ScheduledTask -TaskName "SEC - *" -ErrorAction SilentlyContinue)) {
                    $i = $t | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
                    $log = switch -Wildcard ($t.TaskName) { '*Desactivation*' { 'C:\SEC-Scripts\Disable-ByDate.log' } '*KRBTGT*' { 'C:\SEC-Scripts\Krbtgt-Rotation.log' } default { $null } }
                    [PSCustomObject]@{
                        Tache = $t.TaskName; Etat = [string]$t.State; Compte = $t.Principal.UserId
                        Derniere = $i.LastRunTime; Prochaine = $i.NextRunTime; Resultat = $i.LastTaskResult
                        Journal = if ($log -and (Test-Path $log)) { @(Get-Content $log -Tail 3) -join ' / ' } else { $null }
                    }
                }
            } -ErrorAction Stop)
            if ($tasks.Count -eq 0) { Write-Host ("{0} : aucune tache 'SEC - *'" -f $dc.HostName) -ForegroundColor DarkGray; continue }
            foreach ($t in $tasks) {
                $ok = ($t.Resultat -in 0, 267011)   # 267011 = jamais executee
                Write-Host ("{0} : '{1}' ({2}, compte {3}) - derniere {4}, prochaine {5}, resultat {6}" -f $dc.HostName, $t.Tache, $t.Etat, $t.Compte, $t.Derniere, $t.Prochaine, $t.Resultat) -ForegroundColor $(if ($ok) { 'Green' } else { 'Yellow' })
                if ($t.Journal) { Write-Host ("    journal : {0}" -f $t.Journal) -ForegroundColor DarkGray }
            }
        } catch {
            Write-Log ("Impossible d'interroger {0} : {1}" -f $dc.HostName, $_.Exception.Message) -Level WARN
        }
    }
}

function Invoke-AutomationRemoveScheduledTask {
    Write-Section "Suppression d'une tache planifiee deployee par le script" Red
    Write-Info "Arrete uniquement l'AUTOMATISATION : les comptes deja desactives/deplaces ne sont pas restaures."

    $dcs = @(Get-DomainControllersList)
    if ($dcs.Count -eq 0) { return }
    $dc = @(Select-FromList -Items $dcs -Prompt "DC hebergeant la tache" -Single -Display { param($d) $d.HostName })
    if ($dc.Count -eq 0) { return }
    $targetDC = $dc[0].HostName
    $names = @("SEC - Desactivation Auto (date/anciennete)", "SEC - Rotation KRBTGT", "SEC - Sauvegarde System State")
    $task = @(Select-FromList -Items $names -Prompt "Tache a supprimer" -Single -Display { param($n) $n })
    if ($task.Count -eq 0) { return }

    if (-not (Confirm-Action ("Supprimer la tache '{0}' sur {1}" -f $task[0], $targetDC) -Strong)) { return }
    Invoke-Guarded -Description ("Suppression de la tache '{0}' sur {1}" -f $task[0], $targetDC) -Action {
        Invoke-OnDC -ComputerName $targetDC -ScriptBlock { param($n) Unregister-ScheduledTask -TaskName $n -Confirm:$false -ErrorAction Stop } -ArgumentList $task[0] -ErrorAction Stop
    }
}

# ============================================================
#  DIAGNOSTIC RAPIDE (tableau de bord, lecture seule, LDAP uniquement)
# ============================================================

function Invoke-QuickDiagnostic {
    <#
        Une passe de controles en LECTURE SEULE, sans WinRM (LDAP/SYSVOL uniquement), qui
        produit un tableau de bord priorise : CRITIQUE / ALERTE / INFO / OK, chaque constat
        renvoyant vers l'item de menu de remediation correspondant ("theme.item").
        Un controle qui echoue est marque ERREUR (jamais OK par defaut).
    #>
    Write-Section "Diagnostic rapide de l'annuaire (lecture seule)" Magenta
    Write-Info "Controles LDAP/SYSVOL uniquement (aucun acces distant aux serveurs). Les controles necessitant" `
               "WinRM (Spooler, signature LDAP/SMB, audit...) sont dans la matrice des DC (theme 8 > 11)."

    $findings = [System.Collections.Generic.List[object]]::new()
    $add = {
        param($cat, $ctl, $st, $val, $reco, $menu)
        $findings.Add([PSCustomObject]@{ Categorie = $cat; Controle = $ctl; Statut = $st; Valeur = [string]$val; Recommandation = $reco; Menu = $menu })
    }
    $checks = [System.Collections.Generic.List[object]]::new()
    $def = { param($cat, $ctl, $menu, [scriptblock]$sb) $checks.Add([PSCustomObject]@{ Cat = $cat; Ctl = $ctl; Menu = $menu; Sb = $sb }) }

    $dom = Get-CachedADDomain
    $sid = $dom.DomainSID.Value
    $now = Get-Date
    $uacDisabled = '(!(userAccountControl:1.2.840.113556.1.4.803:=2))'

    & $def 'Kerberos' 'Age du mot de passe krbtgt' '4.4' {
        $k = Get-ADUser -Identity krbtgt -Properties PasswordLastSet -ErrorAction Stop
        $age = [int]($now - $k.PasswordLastSet).TotalDays
        $st = if ($age -gt 365) { 'CRITIQUE' } elseif ($age -gt 180) { 'ALERTE' } else { 'OK' }
        & $add 'Kerberos' 'Age du mot de passe krbtgt' $st "$age jours" 'Rotation (double reset espace) au moins tous les 180 jours' '4.4'
    }
    & $def 'Resilience' 'Corbeille AD' '13.2' {
        $f = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" -ErrorAction Stop
        $on = @($f.EnabledScopes).Count -gt 0
        & $add 'Resilience' 'Corbeille AD' $(if ($on) { 'OK' } else { 'ALERTE' }) $(if ($on) { 'Activee' } else { 'Desactivee' }) 'Activer la corbeille AD' '13.2'
    }
    & $def 'Resilience' 'Derniere sauvegarde AD' '13.1' {
        $b = @(Get-ADBackupStatus)[0]
        $tsl = Get-TombstoneLifetime
        $st = if (-not $b.DerniereSauvegarde) { 'CRITIQUE' } elseif ($tsl -and $b.AgeJours -ge $tsl) { 'CRITIQUE' } elseif ($b.AgeJours -gt 7) { 'ALERTE' } else { 'OK' }
        & $add 'Resilience' 'Derniere sauvegarde AD' $st $(if ($b.DerniereSauvegarde) { "$($b.AgeJours) jour(s)" } else { 'Jamais' }) 'Sauvegarde System State quotidienne, hors domaine, testee' '13.3'
    }
    & $def 'Resilience' 'Nombre de controleurs de domaine' '8.12' {
        # -Strict : une erreur de lecture donne ERREUR, jamais "0 DC".
        $n = @(Get-DomainControllersList -Refresh -Strict | Where-Object { -not $_.IsReadOnly }).Count
        & $add 'Resilience' 'Nombre de DC inscriptibles' $(if ($n -lt 2) { 'ALERTE' } else { 'OK' }) $n 'Au moins 2 DC inscriptibles par domaine' '8.12'
    }
    & $def 'Resilience' 'Sante de la replication' '8.12' {
        $h = Test-ADReplicationHealth
        & $add 'Resilience' 'Sante de la replication' $(if ($h.Healthy) { 'OK' } else { 'CRITIQUE' }) $(if ($h.Healthy) { 'Saine' } else { ($h.Details | Select-Object -First 2) -join ' ; ' }) 'Corriger les erreurs (repadmin /showrepl)' '8.12'
    }
    & $def 'Infrastructure' 'Niveau fonctionnel du domaine' '8.12' {
        $m = [string]$dom.DomainMode
        $st = if ($m -match '2000|2003|2008') { 'ALERTE' } elseif ($m -match '2012') { 'INFO' } else { 'OK' }
        & $add 'Infrastructure' 'Niveau fonctionnel du domaine' $st $m 'Viser Windows2016Domain (Protected Users, FAST, chiffrement LAPS)' '8.12'
    }
    & $def 'Infrastructure' 'ms-DS-MachineAccountQuota' '8.7' {
        $q = (Get-ADObject -Identity $dom.DistinguishedName -Properties 'ms-DS-MachineAccountQuota' -ErrorAction Stop).'ms-DS-MachineAccountQuota'
        & $add 'Infrastructure' 'Quota de jonction utilisateur (MAQ)' $(if ($q -gt 0) { 'ALERTE' } else { 'OK' }) $q 'Mettre a 0 et deleguer la jonction' '8.7'
    }
    & $def 'Comptes' 'Compte Invite' '8.5' {
        $g = Get-ADUser -Identity "$sid-501" -Properties Enabled -ErrorAction Stop
        & $add 'Comptes' 'Compte Invite' $(if ($g.Enabled) { 'ALERTE' } else { 'OK' }) $(if ($g.Enabled) { 'Actif' } else { 'Desactive' }) 'Desactiver le compte Invite' '8.5'
    }
    & $def 'Privileges' 'Compte Administrateur integre' '1.3' {
        $a = Get-ADUser -Identity "$sid-500" -Properties Enabled, LastLogonDate, PasswordLastSet, ServicePrincipalName -ErrorAction Stop
        $issues = @()
        if ($a.Enabled -and $a.LastLogonDate -and $a.LastLogonDate -gt $now.AddDays(-30)) { $issues += 'utilise recemment' }
        if ($a.PasswordLastSet -and $a.PasswordLastSet -lt $now.AddYears(-1)) { $issues += 'mot de passe > 1 an' }
        if ($a.ServicePrincipalName) { $issues += 'porte un SPN' }
        $st = if ($a.ServicePrincipalName) { 'CRITIQUE' } elseif ($issues) { 'ALERTE' } else { 'OK' }
        & $add 'Privileges' 'Compte Administrateur integre (RID 500)' $st $(if ($issues) { $issues -join ', ' } else { 'RAS' }) 'Usage exceptionnel uniquement, mot de passe renouvele' '1.10'
    }
    & $def 'Privileges' 'Membres Domain Admins' '1.2' {
        $n = @(Get-GroupMembersSafe -Group 'Domain Admins' -Recursive).Count
        & $add 'Privileges' 'Membres de Domain Admins' $(if ($n -gt 10) { 'CRITIQUE' } elseif ($n -gt 5) { 'ALERTE' } else { 'OK' }) $n 'Limiter a quelques comptes nominatifs' '1.2'
    }
    & $def 'Privileges' 'Schema Admins' '1.8' {
        $n = @(Get-GroupMembersSafe -Group 'Schema Admins').Count
        & $add 'Privileges' 'Membres de Schema Admins' $(if ($n -gt 0) { 'ALERTE' } else { 'OK' }) $n 'Groupe vide hors operation de schema' '1.8'
    }
    & $def 'Privileges' 'Groupes operateurs' '1.13' {
        $n = 0
        foreach ($g in 'Account Operators', 'Server Operators', 'Print Operators', 'Backup Operators', 'DnsAdmins') { $n += @(Get-GroupMembersSafe -Group $g -Recursive).Count }
        & $add 'Privileges' 'Membres des groupes operateurs / DnsAdmins' $(if ($n -gt 0) { 'ALERTE' } else { 'OK' }) $n 'Vider ces groupes (chemins d''elevation vers Domain Admins)' '1.13'
    }
    & $def 'Privileges' 'Comptes a privileges' '1.6' {
        $enabled = @(Get-PrivilegedUsers -Groups $Script:AdminGroups -Properties ServicePrincipalName, AccountNotDelegated, PasswordLastSet, Enabled | Where-Object Enabled)
        $spn = @($enabled | Where-Object { $_.ServicePrincipalName })
        & $add 'Privileges' 'Comptes a privileges avec SPN (Kerberoasting)' $(if ($spn.Count) { 'CRITIQUE' } else { 'OK' }) $spn.Count 'Retirer le SPN ou le privilege' '1.5'
        $notSens = @($enabled | Where-Object { -not $_.AccountNotDelegated })
        & $add 'Privileges' "Comptes a privileges delegables (non 'sensibles')" $(if ($notSens.Count) { 'ALERTE' } else { 'OK' }) $notSens.Count "Marquer 'sensible, ne peut etre delegue'" '1.6'
        $old = @($enabled | Where-Object { $_.PasswordLastSet -and $_.PasswordLastSet -lt $now.AddYears(-1) })
        & $add 'Privileges' 'Comptes a privileges avec mot de passe > 1 an' $(if ($old.Count) { 'ALERTE' } else { 'OK' }) $old.Count 'Renouveler les mots de passe des comptes d''administration' '1.9'
        $pu = Get-ExpandedGroupMemberSids -GroupNames @('Protected Users')
        $outPu = @($enabled | Where-Object { -not $pu.Contains($_.SID.Value) })
        & $add 'Privileges' 'Comptes a privileges hors Protected Users' $(if ($outPu.Count) { 'INFO' } else { 'OK' }) $outPu.Count 'Ajouter progressivement les comptes d''administration' '1.7'
    }
    & $def 'Privileges' 'adminCount orphelins' '1.12' {
        $n = @(Get-AdminCountOrphans).Count
        & $add 'Privileges' 'Objets adminCount=1 orphelins' $(if ($n -gt 0) { 'INFO' } else { 'OK' }) $n 'Nettoyer apres verification' '1.14'
    }
    & $def 'Privileges' 'Acces pre-Windows 2000' '1.13' {
        $members = @((Get-ADGroup -Identity 'S-1-5-32-554' -Properties member -ErrorAction Stop).member)
        $bad = @($members | Where-Object { $_ -match '^CN=(S-1-1-0|S-1-5-7),' })
        & $add 'Privileges' "Anonyme/Tout le monde dans 'Acces compatible pre-Windows 2000'" $(if ($bad.Count) { 'CRITIQUE' } else { 'OK' }) $bad.Count 'Retirer Anonyme / Tout le monde du groupe' '1.13'
    }
    & $def 'Kerberos' 'AS-REP Roasting' '4.2' {
        $n = @(Get-ADUser -LDAPFilter "(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)$uacDisabled)").Count
        & $add 'Kerberos' 'Comptes actifs sans pre-authentification Kerberos' $(if ($n) { 'ALERTE' } else { 'OK' }) $n 'Reactiver la pre-authentification' '4.7'
    }
    & $def 'Kerberos' 'Delegations' '4.1' {
        $d = @(Get-DelegationInventory | Where-Object { $_.Actif })
        $unc = @($d | Where-Object { $_.Type -eq 'NonContrainte' -and -not $_.EstDC })
        $crit = @($d | Where-Object { $_.Risque -like 'CRITIQUE*' -and $_.Type -ne 'NonContrainte' })
        $pt = @($d | Where-Object { $_.Type -eq 'Contrainte+TransitionProtocole' })
        & $add 'Kerberos' 'Delegation non contrainte (hors DC)' $(if ($unc.Count) { 'CRITIQUE' } else { 'OK' }) $unc.Count 'Remplacer par une delegation contrainte' '4.12'
        & $add 'Kerberos' 'Delegations vers un DC / RBCD sur un DC' $(if ($crit.Count) { 'CRITIQUE' } else { 'OK' }) $crit.Count 'Supprimer ces delegations' '4.1'
        & $add 'Kerberos' 'Delegation avec transition de protocole' $(if ($pt.Count) { 'ALERTE' } else { 'OK' }) $pt.Count 'Justifier ou restreindre' '4.1'
    }
    & $def 'Kerberos' 'Comptes Kerberoastables' '2.8' {
        $aes = Get-AesKeysIntroductionDate
        $acc = @(Get-ADUser -LDAPFilter "(&(servicePrincipalName=*)(!(sAMAccountName=krbtgt*))$uacDisabled)" -Properties PasswordLastSet, 'msDS-SupportedEncryptionTypes')
        # pwdLastSet vide (mot de passe a changer a la prochaine connexion) : non compte ici.
        $weak = @($acc | Where-Object { $_.PasswordLastSet -and (-not (Test-HasAesEncryptionType $_.'msDS-SupportedEncryptionTypes') -or ($aes -and $_.PasswordLastSet -lt $aes)) -and $_.PasswordLastSet -lt $now.AddYears(-1) })
        & $add 'Kerberos' 'Comptes avec SPN, RC4 et mot de passe > 1 an' $(if ($weak.Count) { 'ALERTE' } else { 'OK' }) ("{0} / {1} comptes avec SPN" -f $weak.Count, $acc.Count) 'Mot de passe long + AES, ou gMSA' '2.8'
    }
    & $def 'Kerberos' 'sIDHistory' '4.10' {
        $objs = @(Get-ADObject -LDAPFilter "(sIDHistory=*)" -Properties sIDHistory)
        $crit = @($objs | Where-Object { @($_.sIDHistory | Where-Object { (Get-SidHistoryRisk -Sid $_.Value -DomainSid $sid) -like 'CRITIQUE*' }).Count -gt 0 })
        $st = if ($crit.Count) { 'CRITIQUE' } elseif ($objs.Count) { 'INFO' } else { 'OK' }
        & $add 'Kerberos' 'Objets avec sIDHistory (dont dangereux)' $st ("{0} (dont {1} dangereux)" -f $objs.Count, $crit.Count) 'Supprimer les sIDHistory apres migration' '4.11'
    }
    & $def 'Kerberos' 'Approbations' '4.3' {
        $bad = @(Get-ADTrust -Filter * -Properties TrustAttributes -ErrorAction Stop | Where-Object {
            $a = [int]$_.TrustAttributes
            ([string]$_.Direction -in 'Outbound', 'BiDirectional') -and -not ($a -band 0x20) -and ((($a -band 0x8) -and ($a -band 0x40)) -or (-not ($a -band 0x8) -and -not ($a -band 0x4)))
        })
        & $add 'Kerberos' 'Approbations sans filtrage SID effectif' $(if ($bad.Count) { 'CRITIQUE' } else { 'OK' }) $bad.Count 'Activer la quarantaine / desactiver le SID History' '4.3'
    }
    & $def 'Mots de passe' 'Politique par defaut' '3.2' {
        $p = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
        $st = if ($p.MinPasswordLength -lt 8) { 'CRITIQUE' } elseif ($p.MinPasswordLength -lt 12) { 'ALERTE' } else { 'OK' }
        & $add 'Mots de passe' 'Longueur minimale (politique du domaine)' $st $p.MinPasswordLength '12 minimum (14 recommande), FGPP pour les comptes sensibles' '3.4'
        & $add 'Mots de passe' 'Verrouillage de compte' $(if ($p.LockoutThreshold -eq 0) { 'ALERTE' } else { 'OK' }) $p.LockoutThreshold 'Seuil entre 5 et 50' '3.4'
    }
    & $def 'Mots de passe' 'Indicateurs de comptes' '3.8' {
        $rev = @(Get-ADUser -LDAPFilter "(&(userAccountControl:1.2.840.113556.1.4.803:=128)$uacDisabled)").Count
        $nr = @(Get-ADUser -LDAPFilter "(&(userAccountControl:1.2.840.113556.1.4.803:=32)(!(userAccountControl:1.2.840.113556.1.4.803:=2048))$uacDisabled)").Count
        $des = @(Get-ADUser -LDAPFilter "(&(userAccountControl:1.2.840.113556.1.4.803:=2097152)$uacDisabled)").Count
        & $add 'Mots de passe' 'Comptes actifs a chiffrement reversible' $(if ($rev) { 'CRITIQUE' } else { 'OK' }) $rev 'Retirer le chiffrement reversible' '3.9'
        & $add 'Mots de passe' "Comptes actifs 'mot de passe non requis'" $(if ($nr) { 'ALERTE' } else { 'OK' }) $nr 'Retirer PASSWD_NOTREQD' '3.3'
        & $add 'Mots de passe' "Comptes actifs 'DES uniquement'" $(if ($des) { 'ALERTE' } else { 'OK' }) $des 'Retirer DES' '4.6'
    }
    & $def 'Mots de passe' 'Mots de passe GPP' '3.7' {
        $root = "\\{0}\SYSVOL\{0}\Policies" -f $dom.DNSRoot
        if (-not (Test-Path -LiteralPath $root)) { throw "SYSVOL inaccessible ($root)" }
        $n = 0
        foreach ($f in @(Get-ChildItem -LiteralPath $root -Recurse -Include 'Groups.xml', 'Services.xml', 'ScheduledTasks.xml', 'DataSources.xml', 'Printers.xml', 'Drives.xml' -File -ErrorAction Stop)) {
            $n += @(Get-GppPasswordEntries -Content (Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop)).Count
        }
        & $add 'Mots de passe' 'Mots de passe GPP (cpassword) dans SYSVOL' $(if ($n) { 'CRITIQUE' } else { 'OK' }) $n 'Supprimer et changer les mots de passe exposes' '3.7'
    }
    & $def 'LDAP' 'dSHeuristics' '7.6' {
        $d = Get-DsHeuristicsState
        & $add 'LDAP' 'Operations LDAP anonymes (dSHeuristics)' $(if ($d.AnonymousLdap) { 'CRITIQUE' } else { 'OK' }) $(if ($d.AnonymousLdap) { 'Autorisees' } else { 'Interdites' }) 'Remettre le 7e caractere a 0' '7.5'
        if ([string]$d.AdminSDExMask -ne '0') { & $add 'LDAP' 'AdminSDExMask (dSHeuristics)' 'ALERTE' $d.AdminSDExMask 'Ne pas soustraire de groupes a AdminSDHolder' '7.6' }
    }
    & $def 'LAPS' 'Couverture LAPS' '9.1' {
        $cov = Get-LapsCoverage
        if (-not $cov.WindowsLapsSchema -and -not $cov.LegacySchema) {
            & $add 'LAPS' 'Schema LAPS' 'CRITIQUE' 'Absent' 'Deployer Windows LAPS' '9.3'
        } elseif (@($cov.Rows).Count -gt 0) {
            $c = @($cov.Rows | Where-Object { $_.LAPS -ne 'Absent' }).Count
            $pct = [math]::Round(100 * $c / @($cov.Rows).Count, 1)
            & $add 'LAPS' 'Couverture LAPS (ordinateurs actifs hors DC)' $(if ($pct -lt 50) { 'CRITIQUE' } elseif ($pct -lt 95) { 'ALERTE' } else { 'OK' }) "$pct %" 'Etendre la GPO Windows LAPS' '9.4'
            $stale = @($cov.Rows | Where-Object ExpireDepuis7j).Count
            if ($stale) { & $add 'LAPS' 'Mots de passe LAPS expires depuis > 7 jours' 'ALERTE' $stale 'Verifier le client LAPS / droits d''ecriture' '9.1' }
        }
    }
    & $def 'Hygiene' 'Comptes inactifs' '18.1' {
        $prot = Get-AlwaysProtectedPrincipalSids
        $u = @(Get-InactiveAccountCandidates -Type User -Cutoff $now.AddDays(-180) -ProtectedSids $prot | Where-Object { -not $_.Exclusion }).Count
        $c = @(Get-InactiveAccountCandidates -Type Computer -Cutoff $now.AddDays(-90) -ProtectedSids $prot -ProtectedComputerDNs (Get-ProtectedDCComputerDNs) | Where-Object { -not $_.Exclusion }).Count
        $tu = @(Get-ADUser -LDAPFilter "(&(objectCategory=person)$uacDisabled)" -ResultSetSize $null).Count
        # Denominateur coherent avec les candidats : ni DC, ni gMSA, ni cluster, ni AZUREADSSOACC.
        $tc = @(Get-ADComputer -LDAPFilter $uacDisabled -Properties PrimaryGroupID, ServicePrincipalName, OperatingSystem -ResultSetSize $null | Where-Object { (Get-ComputerAccountKind -Computer $_) -in 'Computer', 'NonWindows' }).Count
        $pu = if ($tu) { [math]::Round(100 * $u / $tu, 1) } else { 0 }
        $pc = if ($tc) { [math]::Round(100 * $c / $tc, 1) } else { 0 }
        & $add 'Hygiene' 'Utilisateurs actifs inactifs > 180 j' $(if ($pu -gt 10) { 'ALERTE' } elseif ($u) { 'INFO' } else { 'OK' }) "$u ($pu %)" 'Desactiver apres revue' '18.1'
        & $add 'Hygiene' 'Ordinateurs actifs inactifs > 90 j' $(if ($pc -gt 10) { 'ALERTE' } elseif ($c) { 'INFO' } else { 'OK' }) "$c ($pc %)" 'Desactiver apres revue' '18.1'
    }
    & $def 'Obsolescence' 'Systemes hors support' '14.1' {
        $eol = @(Get-ADComputer -Filter 'Enabled -eq $true' -Properties OperatingSystem, OperatingSystemVersion, PrimaryGroupID | Where-Object { (Get-ComputerAccountKind -Computer $_) -ne 'MSA' } | ForEach-Object {
            $st = Get-OsSupportStatus -OS $_.OperatingSystem -Version $_.OperatingSystemVersion
            if ($st.Statut -eq 'EOL') { [PSCustomObject]@{ DC = ($_.PrimaryGroupID -in 516, 521) } }
        })
        $dcEol = @($eol | Where-Object DC).Count
        $st = if ($dcEol) { 'CRITIQUE' } elseif ($eol.Count) { 'ALERTE' } else { 'OK' }
        & $add 'Obsolescence' 'Ordinateurs actifs sur un OS hors support' $st ("{0} (dont {1} DC)" -f $eol.Count, $dcEol) 'Migrer / isoler' '14.3'
    }
    & $def 'Privileges' 'Controle de la racine du domaine (DCSync)' '1.15' {
        $r = @(Get-DomainRootDangerousAces)
        $unexpected = @($r | Where-Object { -not $_.SynchroEntraProbable })
        $st = if ($unexpected.Count) { 'CRITIQUE' } elseif ($r.Count) { 'ALERTE' } else { 'OK' }
        $val = if ($r.Count) { ($r | Select-Object -First 3 | ForEach-Object { $_.Principal }) -join ', ' } else { 'Aucun principal non standard' }
        & $add 'Privileges' 'Principaux non standard avec DCSync / controle de la racine' $st $val 'Retirer ces droits ; proteger le compte Entra Connect en tier 0' '1.15'
    }
    & $def 'Privileges' 'Proprietaires des objets DC' '8.13' {
        $o = @(Get-DCOwnership)
        $bad = @($o | Where-Object { $_.Legitime -eq $false })
        if (@($o | Where-Object { $null -eq $_.Legitime }).Count -gt 0 -and $bad.Count -eq 0) { throw "Proprietaire illisible sur au moins un DC." }
        & $add 'Privileges' 'DC appartenant a un principal non administrateur' $(if ($bad.Count) { 'CRITIQUE' } else { 'OK' }) $bad.Count "Proprietaire = 'Admins du domaine'" '8.13'
    }
    & $def 'Privileges' 'Groupe principal non standard' '1.17' {
        $r = @(Get-NonStandardPrimaryGroupAccounts)
        $crit = @($r | Where-Object { $_.Evaluation -like 'CRITIQUE*' })
        & $add 'Privileges' 'Comptes au groupe principal non standard (dont privilegie)' $(if ($crit.Count) { 'CRITIQUE' } elseif ($r.Count) { 'INFO' } else { 'OK' }) ("{0} (dont {1} privilegie(s))" -f $r.Count, $crit.Count) 'Remettre le groupe principal par defaut' '1.17'
    }
    & $def 'Privileges' 'Comptes a privileges inactifs/desactives' '1.16' {
        $r = @(Get-PrivilegedAccountsHygiene -Days 180)
        $dis = @($r | Where-Object { -not $_.Actif }).Count
        $ina = $r.Count - $dis
        & $add 'Privileges' 'Comptes a privileges inactifs > 180 j (actifs)' $(if ($ina) { 'ALERTE' } else { 'OK' }) $ina 'Retirer des groupes puis desactiver' '1.16'
        & $add 'Privileges' 'Comptes desactives encore membres de groupes a privileges' $(if ($dis) { 'INFO' } else { 'OK' }) $dis 'Retirer des groupes a privileges' '1.16'
    }
    & $def 'Mots de passe' "Mots de passe n'expirant jamais" '3.1' {
        $n = @(Get-ADUser -LDAPFilter "(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=65536)$uacDisabled)" -ResultSetSize $null).Count
        & $add 'Mots de passe' "Utilisateurs actifs au mot de passe n'expirant jamais" $(if ($n) { 'INFO' } else { 'OK' }) $n 'Limiter aux comptes justifies (gMSA pour les services)' '3.1'
    }
    & $def 'Mots de passe' 'Mots de passe dans description/notes' '3.10' {
        $n = @(Get-PasswordInDescriptionCandidates).Count
        & $add 'Mots de passe' 'Motifs de mot de passe dans description/notes (heuristique)' $(if ($n) { 'ALERTE' } else { 'OK' }) $n 'Effacer et changer les mots de passe concernes' '3.10'
    }

    $i = 0
    $Script:StrictGroupQueries = $true
    try {
        foreach ($c in $checks) {
            $i++
            Write-Progress -Activity "Diagnostic rapide" -Status $c.Ctl -PercentComplete ([int](100 * $i / $checks.Count))
            try { & $c.Sb } catch { & $add $c.Cat $c.Ctl 'ERREUR' $_.Exception.Message 'Controle non realise : verifier les droits/la connectivite' $c.Menu }
        }
    } finally {
        $Script:StrictGroupQueries = $false
        Write-Progress -Activity "Diagnostic rapide" -Completed
    }

    $order = @{ 'CRITIQUE' = 0; 'ALERTE' = 1; 'ERREUR' = 2; 'INFO' = 3; 'OK' = 4 }
    $sorted = @($findings | Sort-Object @{ E = { $order[$_.Statut] } }, Categorie, Controle)

    # Evolution par rapport au diagnostic precedent du MEME domaine (historique Logs\Diagnostics).
    $previous = @(Get-DiagnosticSnapshots -Domain $dom.DNSRoot) | Select-Object -Last 1
    Compare-DiagnosticFindings -Current $sorted -Previous $(if ($previous) { $previous.Findings } else { $null })
    $Script:PreviousDiagnostic = $previous
    $Script:LastDiagnostic = [PSCustomObject]@{ Date = Get-Date; Findings = $sorted; Score = (Get-DiagnosticScore -Findings $sorted) }

    Show-DiagnosticTable -Findings $sorted -Previous $previous
    Save-DiagnosticSnapshot -Diagnostic $Script:LastDiagnostic -Domain $dom.DNSRoot
    [void](Export-Report -Rows $sorted -Name "Diagnostic_Rapide")
}

function Get-DiagnosticScore {
    # Indice indicatif : 100 - 10 par constat critique - 3 par alerte (borne a 0). Pas le score PingCastle.
    param([AllowEmptyCollection()][object[]]$Findings)
    $crit = @($Findings | Where-Object { $_.Statut -eq 'CRITIQUE' }).Count
    $warn = @($Findings | Where-Object { $_.Statut -eq 'ALERTE' }).Count
    return [Math]::Max(0, 100 - 10 * $crit - 3 * $warn)
}

function Compare-DiagnosticFindings {
    <#
        Ajoute a chaque constat courant les proprietes Precedent (statut au diagnostic precedent)
        et Evolution : Degrade / Ameliore / Inchange / Nouveau controle / Non verifie.
        Sans diagnostic precedent, Evolution reste vide.
    #>
    param([AllowEmptyCollection()][object[]]$Current, [AllowNull()][object[]]$Previous)
    $rank = @{ 'OK' = 0; 'INFO' = 1; 'ALERTE' = 2; 'CRITIQUE' = 3 }
    $prev = @{}
    foreach ($p in @($Previous | Where-Object { $_ })) { $prev[("{0}|{1}" -f $p.Categorie, $p.Controle)] = $p }
    foreach ($c in $Current) {
        $p = $prev[("{0}|{1}" -f $c.Categorie, $c.Controle)]
        $evo = if (-not $Previous) { $null }
               elseif (-not $p) { 'Nouveau controle' }
               elseif ($c.Statut -eq 'ERREUR' -or $p.Statut -eq 'ERREUR') { 'Non verifie' }
               elseif ($rank[$c.Statut] -gt $rank[$p.Statut]) { 'Degrade' }
               elseif ($rank[$c.Statut] -lt $rank[$p.Statut]) { 'Ameliore' }
               else { 'Inchange' }
        $c | Add-Member -NotePropertyName Precedent -NotePropertyValue $(if ($p) { $p.Statut } else { $null }) -Force
        $c | Add-Member -NotePropertyName Evolution -NotePropertyValue $evo -Force
    }
}

function Get-SafeFileName { param([string]$Text) return ($Text -replace '[^A-Za-z0-9_.-]', '_') }

function Save-DiagnosticSnapshot {
    # Historique JSON (Logs\Diagnostics) : sert au suivi d'evolution et a la courbe du rapport HTML.
    param([Parameter(Mandatory)]$Diagnostic, [Parameter(Mandatory)][string]$Domain)
    try {
        if (-not (Test-Path -LiteralPath $Script:DiagHistoryDir)) { New-Item -Path $Script:DiagHistoryDir -ItemType Directory -Force | Out-Null }
        $path = Join-Path $Script:DiagHistoryDir ("Diagnostic_{0}_{1:yyyyMMdd_HHmmss}.json" -f (Get-SafeFileName $Domain), $Diagnostic.Date)
        [PSCustomObject]@{
            Domaine  = $Domain
            Date     = $Diagnostic.Date.ToString('yyyy-MM-ddTHH:mm:ss')
            Score    = $Diagnostic.Score
            Version  = $Script:Version
            Findings = @($Diagnostic.Findings | Select-Object Categorie, Controle, Statut, Valeur, Recommandation, Menu)
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $path -Encoding UTF8 -ErrorAction Stop
    } catch {
        Write-Log ("Historique du diagnostic non enregistre : {0}" -f $_.Exception.Message) -Level WARN
    }
}

function Get-DiagnosticSnapshots {
    # Diagnostics precedents du domaine, du plus ancien au plus recent. Fichier illisible = ignore.
    param([Parameter(Mandatory)][string]$Domain)
    if (-not (Test-Path -LiteralPath $Script:DiagHistoryDir)) { return @() }
    $files = @(Get-ChildItem -LiteralPath $Script:DiagHistoryDir -Filter ("Diagnostic_{0}_*.json" -f (Get-SafeFileName $Domain)) -File -ErrorAction SilentlyContinue | Sort-Object Name)
    return @(foreach ($f in $files) {
        try {
            $j = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json
            [PSCustomObject]@{
                # PowerShell 7 convertit deja les dates ISO en [datetime] ; 5.1 les laisse en texte.
                Date     = if ($j.Date -is [datetime]) { $j.Date } else { [datetime]::ParseExact([string]$j.Date, 'yyyy-MM-ddTHH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) }
                Score    = [int]$j.Score
                Findings = @($j.Findings)
                Fichier  = $f.FullName
            }
        } catch { Write-Verbose ("Historique illisible ignore : {0}" -f $f.FullName) }
    })
}

function Invoke-DiagnosticHistory {
    Write-Section "Historique des diagnostics (evolution de l'indice et des constats)" Magenta
    Write-Info "Chaque diagnostic rapide (menu D, 16.3, -QuickAudit) est archive dans Logs\Diagnostics." `
               "Planifier '-QuickAudit' (tache hebdomadaire) donne un suivi regulier de l'hygiene AD."
    $dom = Get-CachedADDomain
    $snaps = @(Get-DiagnosticSnapshots -Domain $dom.DNSRoot)
    if ($snaps.Count -eq 0) { Write-Log "Aucun diagnostic archive pour ce domaine : lancez d'abord le diagnostic rapide ([D])." -Level INFO; return }
    $rows = @(foreach ($sn in $snaps) {
        $f = @($sn.Findings)
        [PSCustomObject]@{
            Date      = $sn.Date
            Indice    = $sn.Score
            Critiques = @($f | Where-Object { $_.Statut -eq 'CRITIQUE' }).Count
            Alertes   = @($f | Where-Object { $_.Statut -eq 'ALERTE' }).Count
            Erreurs   = @($f | Where-Object { $_.Statut -eq 'ERREUR' }).Count
        }
    })
    foreach ($r in ($rows | Select-Object -Last 20)) {
        $bar = '#' * [int]([Math]::Round($r.Indice / 5))
        $color = if ($r.Indice -ge 80) { 'Green' } elseif ($r.Indice -ge 50) { 'Yellow' } else { 'Red' }
        Write-Host ("  {0:dd/MM/yyyy HH:mm}  {1,3}/100 " -f $r.Date, $r.Indice) -NoNewline
        Write-Host ("{0,-20}" -f $bar) -ForegroundColor $color -NoNewline
        Write-Host ("  {0} critique(s), {1} alerte(s), {2} erreur(s)" -f $r.Critiques, $r.Alertes, $r.Erreurs) -ForegroundColor DarkGray
    }
    if ($rows.Count -ge 2) {
        $delta = $rows[-1].Indice - $rows[0].Indice
        Write-Log ("Evolution depuis le {0:dd/MM/yyyy} : {1}{2} point(s) d'indice." -f $rows[0].Date, $(if ($delta -ge 0) { '+' } else { '' }), $delta) -Level $(if ($delta -ge 0) { 'OK' } else { 'WARN' })
    }
    [void](Export-Report -Rows $rows -Name "Historique_Diagnostics")
}

function Show-DiagnosticTable {
    param([Parameter(Mandatory)][object[]]$Findings, $Previous)
    $colors = @{ 'CRITIQUE' = 'Red'; 'ALERTE' = 'Yellow'; 'ERREUR' = 'Magenta'; 'INFO' = 'Cyan'; 'OK' = 'Green' }
    $evoText = @{ 'Degrade' = 'PIRE'; 'Ameliore' = 'MIEUX'; 'Nouveau controle' = 'NOUV.'; 'Non verifie' = '?'; 'Inchange' = '=' }
    $evoColor = @{ 'Degrade' = 'Red'; 'Ameliore' = 'Green'; 'Nouveau controle' = 'Cyan'; 'Non verifie' = 'Magenta'; 'Inchange' = 'DarkGray' }
    Write-Host ""
    Write-Host ("{0,-9} {1,-6} {2,-14} {3,-54} {4,-22} {5}" -f 'STATUT', 'EVOL.', 'CATEGORIE', 'CONTROLE', 'VALEUR', 'MENU') -ForegroundColor White
    Write-Host ("-" * 114) -ForegroundColor DarkGray
    $lastStatus = $null
    foreach ($f in $Findings) {
        # Ligne vide entre deux niveaux de gravite : lecture plus rapide.
        if ($lastStatus -and $f.Statut -ne $lastStatus) { Write-Host "" }
        $lastStatus = $f.Statut
        $ctl = if ($f.Controle.Length -gt 54) { $f.Controle.Substring(0, 51) + '...' } else { $f.Controle }
        $val = if ($f.Valeur.Length -gt 22) { $f.Valeur.Substring(0, 19) + '...' } else { $f.Valeur }
        $evo = if ($f.PSObject.Properties['Evolution'] -and $f.Evolution) { $f.Evolution } else { $null }
        Write-Host ("{0,-9} " -f $f.Statut) -ForegroundColor $colors[$f.Statut] -NoNewline
        Write-Host ("{0,-6} " -f $(if ($evo) { $evoText[$evo] } else { '' })) -ForegroundColor $(if ($evo) { $evoColor[$evo] } else { 'Gray' }) -NoNewline
        Write-Host ("{0,-14} {1,-54} {2,-22} {3}" -f $f.Categorie, $ctl, $val, $f.Menu)
    }
    Write-Host ("-" * 114) -ForegroundColor DarkGray
    $summary = $Findings | Group-Object Statut | ForEach-Object { "{0} : {1}" -f $_.Name, $_.Count }
    Write-Host ("Synthese : {0}" -f ($summary -join '  |  ')) -ForegroundColor White
    $score = Get-DiagnosticScore -Findings $Findings
    Write-Host ("Indice indicatif d'hygiene : {0}/100 (-10 par critique, -3 par alerte ; ce n'est PAS le score PingCastle)." -f $score) -ForegroundColor $(if ($score -ge 80) { 'Green' } elseif ($score -ge 50) { 'Yellow' } else { 'Red' })
    if ($Previous) {
        $worse = @($Findings | Where-Object { $_.Evolution -eq 'Degrade' }).Count
        $better = @($Findings | Where-Object { $_.Evolution -eq 'Ameliore' }).Count
        $delta = $score - [int]$Previous.Score
        Write-Host ("Depuis le diagnostic du {0:dd/MM/yyyy HH:mm} (indice {1}) : {2}{3} point(s), {4} controle(s) degrade(s), {5} ameliore(s)." -f $Previous.Date, $Previous.Score, $(if ($delta -ge 0) { '+' } else { '' }), $delta, $worse, $better) -ForegroundColor $(if ($worse -gt 0) { 'Yellow' } else { 'Green' })
    }

    # Plan d'action : les constats a traiter en premier, avec l'action de remediation associee.
    $todo = @($Findings | Where-Object { $_.Statut -in 'CRITIQUE', 'ALERTE' })
    if ($todo.Count -gt 0) {
        Write-Host ""
        Write-Host "PLAN D'ACTION PRIORITAIRE (tapez le numero x.y depuis le menu pour ouvrir l'action) :" -ForegroundColor White
        foreach ($t in ($todo | Select-Object -First 12)) {
            Write-Host ("  {0,-6}" -f $t.Menu) -ForegroundColor $colors[$t.Statut] -NoNewline
            Write-Host (" {0} : {1}" -f $t.Controle, $t.Recommandation)
        }
        if ($todo.Count -gt 12) { Write-Host ("  ... et {0} autre(s) : voir le CSV / le rapport HTML." -f ($todo.Count - 12)) -ForegroundColor DarkGray }
    }
}

function ConvertTo-HtmlSafe { param([string]$Text) return [System.Net.WebUtility]::HtmlEncode($Text) }

function Get-HtmlTrendSvg {
    # Courbe SVG autonome de l'indice d'hygiene (historique des diagnostics du domaine).
    param([AllowEmptyCollection()][object[]]$Snapshots)
    $pts = @($Snapshots | Select-Object -Last 30)
    if ($pts.Count -lt 2) { return '<p class="mut">Historique insuffisant (au moins 2 diagnostics archives) pour tracer une evolution.</p>' }
    $w = 640; $h = 140; $pad = 24
    $step = ($w - 2 * $pad) / ($pts.Count - 1)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $coords = for ($i = 0; $i -lt $pts.Count; $i++) {
        $x = $pad + $i * $step
        $y = $h - $pad - ($h - 2 * $pad) * ([double]$pts[$i].Score / 100)
        [PSCustomObject]@{ X = $x.ToString('0.0', $inv); Y = $y.ToString('0.0', $inv); S = $pts[$i].Score; D = $pts[$i].Date.ToString('dd/MM/yyyy HH:mm') }
    }
    $line = ($coords | ForEach-Object { "{0},{1}" -f $_.X, $_.Y }) -join ' '
    $dots = ($coords | ForEach-Object { "<circle cx='{0}' cy='{1}' r='3.5'><title>{2} : {3}/100</title></circle>" -f $_.X, $_.Y, $_.D, $_.S }) -join ''
    $grid = (0, 50, 80, 100 | ForEach-Object { $gy = ($h - $pad - ($h - 2 * $pad) * ($_ / 100)).ToString('0.0', $inv); "<line x1='$pad' x2='$($w - $pad)' y1='$gy' y2='$gy' class='grid'/><text x='2' y='$gy' class='axis'>$_</text>" }) -join ''
    return "<svg viewBox='0 0 $w $h' class='trend' role='img' aria-label='Evolution de l&#39;indice'>$grid<polyline points='$line' class='curve'/>$dots</svg>" +
           ("<p class='mut'>Du {0} au {1} : {2} diagnostic(s) archive(s).</p>" -f $coords[0].D, $coords[-1].D, $pts.Count)
}

function New-HtmlReport {
    <#
        Rapport HTML autonome (aucune dependance externe, fonctionne hors ligne) : indice et
        evolution, plan d'action, constats filtrables (statut + recherche), courbe historique,
        statistiques et historique de la session, liste des rapports CSV produits.
    #>
    param([switch]$Open)
    if (-not $Script:LastDiagnostic) {
        Write-Host "Aucun diagnostic dans cette session : lancement du diagnostic rapide..." -ForegroundColor DarkGray
        Invoke-QuickDiagnostic
    }
    $dom = Get-CachedADDomain
    $f = @($Script:LastDiagnostic.Findings)
    $count = { param($st) @($f | Where-Object { $_.Statut -eq $st }).Count }
    $score = Get-DiagnosticScore -Findings $f
    $scoreClass = if ($score -ge 80) { 'ok' } elseif ($score -ge 50) { 'warn' } else { 'crit' }
    $prev = $Script:PreviousDiagnostic
    $deltaHtml = if ($prev) {
        $d = $score - [int]$prev.Score
        "<span class='delta {0}'>{1}{2} depuis le {3:dd/MM/yyyy}</span>" -f $(if ($d -ge 0) { 'up' } else { 'down' }), $(if ($d -ge 0) { '+' } else { '' }), $d, $prev.Date
    } else { "<span class='delta'>premier diagnostic archive</span>" }

    $evoLabel = @{ 'Degrade' = 'Degrade'; 'Ameliore' = 'Ameliore'; 'Nouveau controle' = 'Nouveau'; 'Non verifie' = 'Non verifie'; 'Inchange' = 'Inchange' }
    $rowsHtml = foreach ($x in $f) {
        $evo = if ($x.PSObject.Properties['Evolution'] -and $x.Evolution) { "<span class='evo e-$(($x.Evolution -replace '\s', '').ToLower())' title='Statut precedent : $(ConvertTo-HtmlSafe ([string]$x.Precedent))'>$($evoLabel[$x.Evolution])</span>" } else { '' }
        "<tr class='s-$($x.Statut.ToLower())' data-s='$($x.Statut)'><td><span class='badge'>$($x.Statut)</span></td><td>$evo</td><td>$(ConvertTo-HtmlSafe $x.Categorie)</td><td>$(ConvertTo-HtmlSafe $x.Controle)</td><td>$(ConvertTo-HtmlSafe $x.Valeur)</td><td>$(ConvertTo-HtmlSafe $x.Recommandation)</td><td class='menu'>$($x.Menu)</td></tr>"
    }
    $planHtml = foreach ($x in @($f | Where-Object { $_.Statut -in 'CRITIQUE', 'ALERTE' })) {
        "<li class='s-$($x.Statut.ToLower())'><span class='badge'>$($x.Statut)</span> <b>$(ConvertTo-HtmlSafe $x.Controle)</b> ($(ConvertTo-HtmlSafe $x.Valeur)) : $(ConvertTo-HtmlSafe $x.Recommandation) <span class='menu'>[action $($x.Menu)]</span></li>"
    }
    $trendHtml = Get-HtmlTrendSvg -Snapshots @(Get-DiagnosticSnapshots -Domain $dom.DNSRoot)
    $histHtml = foreach ($h in $Script:SessionHistory) { "<li>$(ConvertTo-HtmlSafe ('{0:HH:mm:ss} - {1}' -f $h.Date, $h.Label))</li>" }
    $repHtml = foreach ($r in $Script:SessionReports) { "<li>$(ConvertTo-HtmlSafe $r)</li>" }
    $st = $Script:SessionStats

    $css = @'
:root{--bg:#f6f7f9;--card:#fff;--txt:#1d2330;--mut:#5b6475;--crit:#c62828;--warn:#d97706;--info:#1565c0;--ok:#2e7d32;--err:#8e24aa;--line:#e3e6ec;--hdr:#0d47a1}
@media (prefers-color-scheme: dark){:root{--bg:#14171c;--card:#1d2128;--txt:#e6e9ef;--mut:#9aa3b2;--line:#2c323c;--hdr:#0b3a82}}
*{box-sizing:border-box}body{margin:0;font:14px/1.45 "Segoe UI",Arial,sans-serif;background:var(--bg);color:var(--txt)}
header{padding:22px 32px;background:var(--hdr);color:#fff;display:flex;flex-wrap:wrap;gap:24px;align-items:center;justify-content:space-between}
header h1{margin:0 0 4px;font-size:22px}header p{margin:0;opacity:.85}
.score{text-align:center;background:rgba(255,255,255,.12);border-radius:12px;padding:10px 22px}.score b{display:block;font-size:40px;line-height:1.1}
.score.crit b{color:#ffb4b4}.score.warn b{color:#ffe08a}.score.ok b{color:#b9f6ca}
.delta{display:block;font-size:12px;opacity:.9}.delta.up::before{content:"\25B2 "}.delta.down::before{content:"\25BC "}
main{padding:24px 32px;max-width:1400px;margin:auto}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:20px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;cursor:pointer;text-align:left;color:var(--txt);font:inherit}
.kpi b{display:block;font-size:26px}.kpi.active{outline:2px solid var(--info)}
.kpi.crit b{color:var(--crit)}.kpi.warn b{color:var(--warn)}.kpi.info b{color:var(--info)}.kpi.ok b{color:var(--ok)}.kpi.err b{color:var(--err)}
section{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin-bottom:20px;overflow-x:auto}
h2{font-size:17px;margin:0 0 12px}h3{font-size:14px;margin:14px 0 6px}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;font-weight:700;color:#fff;white-space:nowrap}
.s-critique .badge{background:var(--crit)}.s-alerte .badge{background:var(--warn)}.s-info .badge{background:var(--info)}.s-ok .badge{background:var(--ok)}.s-erreur .badge{background:var(--err)}
.evo{font-size:11px;font-weight:600;white-space:nowrap}.e-degrade{color:var(--crit)}.e-ameliore{color:var(--ok)}.e-nouveaucontrole{color:var(--info)}.e-nonverifie{color:var(--err)}.e-inchange{color:var(--mut)}
.menu{font-family:Consolas,monospace;color:var(--mut);white-space:nowrap}ul{margin:0;padding-left:20px}li{margin:3px 0}
.plan{list-style:none;padding:0}.plan li{padding:6px 0;border-bottom:1px solid var(--line)}
.tools{display:flex;gap:10px;margin-bottom:10px;flex-wrap:wrap}.tools input{flex:1;min-width:200px;padding:7px 10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--txt)}
.mut{color:var(--mut);font-size:12px}.trend{width:100%;max-width:720px;height:auto}.trend .curve{fill:none;stroke:var(--info);stroke-width:2.5}
.trend circle{fill:var(--info)}.trend .grid{stroke:var(--line)}.trend .axis{fill:var(--mut);font-size:9px}
footer{color:var(--mut);font-size:12px;padding:0 32px 24px}
@media (max-width:640px){header,main{padding:16px}footer{padding:0 16px 16px}.kpis{grid-template-columns:repeat(2,1fr)}}
@media print{.tools,.kpi{cursor:default}tr{display:table-row!important}header{background:#fff;color:#000}}
'@
    $js = @'
(function(){var cur='';var q=document.getElementById('q');var rows=[].slice.call(document.querySelectorAll('#t tbody tr'));
function apply(){var t=(q.value||'').toLowerCase();var n=0;rows.forEach(function(r){var ok=(!cur||r.getAttribute('data-s')===cur)&&(!t||r.textContent.toLowerCase().indexOf(t)>=0);r.style.display=ok?'':'none';if(ok)n++;});document.getElementById('n').textContent=n+' constat(s) affiche(s)';}
[].slice.call(document.querySelectorAll('.kpi')).forEach(function(b){b.addEventListener('click',function(){var s=b.getAttribute('data-f');cur=(cur===s)?'':s;[].slice.call(document.querySelectorAll('.kpi')).forEach(function(x){x.classList.toggle('active',x.getAttribute('data-f')===cur&&cur!=='');});apply();});});
q.addEventListener('input',apply);apply();})();
'@
    $html = @"
<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Diagnostic AD - $(ConvertTo-HtmlSafe $dom.DNSRoot)</title>
<style>$css</style></head><body>
<header><div><h1>Diagnostic de securite Active Directory</h1>
<p>Domaine $(ConvertTo-HtmlSafe $dom.DNSRoot) - niveau $(ConvertTo-HtmlSafe ([string]$dom.DomainMode)) - genere le $(Get-Date -Format 'dd/MM/yyyy HH:mm') par $(ConvertTo-HtmlSafe (Get-CurrentUserName))</p></div>
<div class="score $scoreClass"><b>$score</b>/100 indice indicatif$deltaHtml</div></header>
<main>
<div class="kpis">
<button class="kpi crit" data-f="CRITIQUE"><b>$(& $count 'CRITIQUE')</b>Critiques</button><button class="kpi warn" data-f="ALERTE"><b>$(& $count 'ALERTE')</b>Alertes</button>
<button class="kpi err" data-f="ERREUR"><b>$(& $count 'ERREUR')</b>Non verifies</button><button class="kpi info" data-f="INFO"><b>$(& $count 'INFO')</b>Informations</button>
<button class="kpi ok" data-f="OK"><b>$(& $count 'OK')</b>Conformes</button>
</div>
<section><h2>Plan d'action prioritaire</h2>
<ul class="plan">$(if ($planHtml) { $planHtml -join '' } else { '<li>Aucun constat critique ou alerte.</li>' })</ul>
<p class="mut">Le numero d'action (x.y) se saisit directement dans le menu principal du script. Toute remediation se teste d'abord en mode simulation.</p></section>
<section><h2>Constats (diagnostic du $($Script:LastDiagnostic.Date.ToString('dd/MM/yyyy HH:mm')))</h2>
<div class="tools"><input id="q" type="search" placeholder="Filtrer (mot-cle, categorie, numero d'action...)"><span id="n" class="mut"></span></div>
<table id="t"><thead><tr><th>Statut</th><th>Evolution</th><th>Categorie</th><th>Controle</th><th>Valeur</th><th>Recommandation</th><th>Action</th></tr></thead><tbody>
$($rowsHtml -join "`n")
</tbody></table><p class="mut">Cliquez sur un indicateur ci-dessus pour filtrer par statut. ERREUR = controle non realise (droits, connectivite) : jamais compte comme conforme.</p></section>
<section><h2>Evolution de l'indice</h2>$trendHtml</section>
<section><h2>Session</h2><p>Mode : $(if ($Script:SimulationMode) { 'SIMULATION' } else { 'REEL' }) - actions d'ecriture : $($st.Actions) (reussies $($st.Succes), echecs $($st.Echecs), simulees $($st.Simulees))</p>
<h3>Actions lancees</h3><ul>$(if ($histHtml) { $histHtml -join '' } else { '<li>Aucune</li>' })</ul>
<h3>Rapports CSV produits</h3><ul>$(if ($repHtml) { $repHtml -join '' } else { '<li>Aucun</li>' })</ul></section>
</main><footer>Rapport genere par AD_Remediation_Menu.ps1 v$($Script:Version). Controles indicatifs, complementaires d'un audit PingCastle complet ; l'indice n'est pas le score PingCastle.</footer>
<script>$js</script>
</body></html>
"@
    if (-not (Test-Path -LiteralPath $Script:ReportDir)) { New-Item -Path $Script:ReportDir -ItemType Directory -Force | Out-Null }
    $path = Join-Path $Script:ReportDir ("Synthese_AD_{0}.html" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    Set-Content -LiteralPath $path -Value $html -Encoding UTF8
    $Script:SessionReports.Add($path)
    Write-Log ("Rapport HTML genere : {0}" -f $path) -Level OK
    if ($Open) { try { Invoke-Item -LiteralPath $path } catch { } }
    return $path
}

# ============================================================
#  THEME 16 - CONTROLE FINAL / THEME 17 - RAPPORTS TRANSVERSES
# ============================================================

function Invoke-Audit20FinalControlReport {
    Write-Section "Controle final consolide" Magenta
    Write-Info "Enchaine en lecture seule : diagnostic rapide (LDAP), matrice de durcissement des DC" `
               "(WinRM), politique d'audit effective, delegations, groupes a privileges, puis genere le" `
               "rapport HTML de synthese. Chaque etape exporte son CSV dans le dossier de session." `
               "Ne remplace pas un audit PingCastle avant/apres."
    if (-not (Confirm-Action "Lancer le controle final consolide (plusieurs minutes)")) { return }

    $steps = @(
        @{ L = 'Diagnostic rapide';                    F = { Invoke-QuickDiagnostic } }
        @{ L = 'Matrice de durcissement des DC';       F = { Invoke-Audit9DCHardeningMatrix } }
        @{ L = "Politique d'audit effective des DC";   F = { Invoke-Audit19EffectiveAuditPolicy } }
        @{ L = 'Delegations Kerberos';                 F = { Invoke-RiskyReportDelegations } }
        @{ L = 'Membres des groupes a privileges';     F = { Invoke-ReportPrivilegedGroups } }
        @{ L = 'Mots de passe n''expirant jamais';     F = { Invoke-ReportPasswordNeverExpires } }
    )
    $n = 0
    foreach ($st in $steps) {
        $n++
        Write-Host ("`n[{0}/{1}] {2}..." -f $n, ($steps.Count + 1), $st.L) -ForegroundColor DarkCyan
        try { & $st.F } catch { Write-Log ("Etape '{0}' en echec : {1}" -f $st.L, $_.Exception.Message) -Level ERROR }
    }
    Write-Host ("`n[{0}/{0}] Usage NTLMv1/LM (lecture du journal Securite, potentiellement long)..." -f ($steps.Count + 1)) -ForegroundColor DarkCyan
    if (Read-YesNo -Prompt "Inclure l'analyse NTLMv1/LM ?") { Invoke-ReportNtlmV1Usage }
    else { Write-Log "Etape NTLMv1/LM ignoree (theme 5 > 2 pour la lancer separement)." -Level INFO }

    [void](New-HtmlReport)
    Write-Log "Controle final termine. Pensez au registre des exceptions pour tout constat accepte sans correction (item 2)." -Level OK
}

function Invoke-Remediate20InitExceptionsRegister {
    Write-Section "Registre des exceptions (risques acceptes / compenses)" Cyan
    Write-Info "Impact : AUCUN sur l'AD. Fichier CSV (separateur ';') documentant les constats acceptes sans" `
               "correction : risque residuel assume, mesure compensatoire, contrainte metier/technique."

    $path = Join-Path $Script:LogDir "Registre_Exceptions.csv"
    if (Test-Path -LiteralPath $path) {
        Write-Log ("Registre existant : {0}" -f $path) -Level INFO
        try {
            $existing = @(Import-Csv -LiteralPath $path -Delimiter ';')
            Write-Host ("{0} exception(s) enregistree(s)." -f $existing.Count) -ForegroundColor Gray
            $due = @($existing | Where-Object { $d = [datetime]::MinValue; [datetime]::TryParseExact($_.DateRevision, 'dd/MM/yyyy', $null, 'None', [ref]$d) -and $d -lt (Get-Date) })
            if ($due.Count -gt 0) { Write-Log ("{0} exception(s) dont la date de revue est depassee." -f $due.Count) -Level WARN }
        } catch { }
    }
    if (-not (Read-YesNo -Prompt "Ajouter une exception maintenant ?" -Default $true)) { return }

    $entry = [PSCustomObject]@{
        Date         = (Get-Date -Format "dd/MM/yyyy")
        Constat      = Read-Host "Constat (ex : compte de service X toujours en RC4)"
        Raison       = Read-Host "Raison (ex : application legacy non compatible AES)"
        Compensation = Read-Host "Mesure compensatoire (ex : compte isole, surveillance renforcee)"
        Responsable  = Read-Host "Responsable (nom/role)"
        DateRevision = Read-Host "Date de prochaine revue (jj/mm/aaaa)"
    }
    if ([string]::IsNullOrWhiteSpace($entry.Constat)) { Write-Log "Constat vide : rien n'est enregistre." -Level WARN; return }
    try {
        $entry | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8 -Delimiter ';' -Append -ErrorAction Stop
        Write-Log ("Exception ajoutee au registre : {0}" -f $path) -Level OK
    } catch {
        Write-Log ("Ecriture du registre impossible : {0}" -f $_.Exception.Message) -Level ERROR
    }
}

function Invoke-ReportAll {
    Write-Section "Export global (rapports rapides multi-themes, lecture seule)" Magenta
    foreach ($step in @(
        { Invoke-ReportPrivilegedGroups }, { Invoke-ReportPasswordNeverExpires }, { Invoke-RiskyReportDelegations },
        { Invoke-Audit4KerberoastableAccounts }, { Invoke-Audit5AsRepRoasting }, { Invoke-Audit11PasswordHygiene },
        { Invoke-ReportDCHotfixes }
    )) {
        try { & $step } catch { Write-Log ("Etape en echec : {0}" -f $_.Exception.Message) -Level ERROR }
    }
    Write-Log ("Rapports exportes dans : {0}" -f $Script:ReportDir) -Level OK
}

function Open-ReportFolder {
    if (-not (Test-Path -LiteralPath $Script:ReportDir)) { New-Item -Path $Script:ReportDir -ItemType Directory -Force | Out-Null }
    Write-Log ("Dossier des rapports de la session : {0}" -f $Script:ReportDir) -Level INFO
    try { Invoke-Item -LiteralPath $Script:ReportDir } catch { Write-Log "Ouverture de l'explorateur impossible (session sans interface ?)." -Level WARN }
}

# ============================================================
#  MENUS (pilotes par les donnees : une seule definition sert a l'affichage,
#  a la recherche, a l'acces direct "theme.item" et au journal de session)
# ============================================================

function New-MenuItem {
    param([ValidateSet('AUDIT', 'SAFE', 'VALIDER', 'OUTIL')][string]$Tag, [string]$Label, [string]$Fn)
    return [PSCustomObject]@{ Tag = $Tag; Label = $Label; Fn = $Fn }
}

$Script:Themes = @(
    [PSCustomObject]@{ Id = 1; Category = "Identite et comptes"; Name = "Comptes a privileges"; Items = @(
        (New-MenuItem AUDIT   "Export des membres des groupes a privileges (actifs/desactives, SPN...)" 'Invoke-ReportPrivilegedGroups')
        (New-MenuItem AUDIT   "Nombre de membres Domain Admins / Enterprise Admins (vs seuil)" 'Invoke-Audit3DomainAdminsCount')
        (New-MenuItem AUDIT   "Usage du compte Administrateur integre (RID 500)" 'Invoke-Audit3BuiltinAdministratorStatus')
        (New-MenuItem AUDIT   "Comptes a privileges potentiellement non nominatifs/partages" 'Invoke-Audit3NonNominativeAccounts')
        (New-MenuItem AUDIT   "Risque Kerberoasting sur les comptes a privileges" 'Invoke-Audit3KerberoastingRisk')
        (New-MenuItem VALIDER "Marquer les comptes a privileges 'Sensible, ne peut etre delegue'" 'Invoke-RiskySetPrivilegedNotDelegated')
        (New-MenuItem VALIDER "Ajouter les comptes Domain/Enterprise Admins dans 'Protected Users'" 'Invoke-RiskyAddToProtectedUsers')
        (New-MenuItem VALIDER "Nettoyer le groupe Schema Admins" 'Invoke-RiskyCleanupSchemaAdmins')
        (New-MenuItem VALIDER "Forcer l'expiration des mots de passe des comptes a privileges" 'Invoke-RiskyForcePasswordExpirationPrivileged')
        (New-MenuItem VALIDER "Desactiver le compte Administrateur integre (RID 500)" 'Invoke-Remediate3DisableBuiltinAdministrator')
        (New-MenuItem VALIDER "Restreindre les comptes a privileges a des postes dedies (PAW)" 'Invoke-Remediate3RestrictPrivilegedLogonWorkstations')
        (New-MenuItem AUDIT   "Comptes 'adminCount=1' orphelins (anciens administrateurs)" 'Invoke-Audit3AdminCountOrphans')
        (New-MenuItem AUDIT   "Groupes sensibles : pre-Windows 2000, DnsAdmins, operateurs, GPCO" 'Invoke-Audit3SensitiveGroupsMembership')
        (New-MenuItem VALIDER "Nettoyer les comptes 'adminCount=1' orphelins (heritage ACL)" 'Invoke-Remediate3CleanAdminCountOrphans')
        (New-MenuItem AUDIT   "Droits DCSync et controle de la racine du domaine (ACL)" 'Invoke-Audit3DomainRootControl')
        (New-MenuItem AUDIT   "Comptes a privileges inactifs ou desactives" 'Invoke-Audit3PrivilegedAccountsHygiene')
        (New-MenuItem AUDIT   "Groupe principal non standard (appartenance privilegiee cachee)" 'Invoke-Audit3NonStandardPrimaryGroup')
    ) }
    [PSCustomObject]@{ Id = 2; Category = "Identite et comptes"; Name = "Comptes de service"; Items = @(
        (New-MenuItem AUDIT   "Inventaire des comptes de service (SPN / UO choisies)" 'Invoke-Audit4ServiceAccountsInventory')
        (New-MenuItem AUDIT   "Comptes de service en chiffrement faible (RC4/DES, sans cle AES)" 'Invoke-Audit4WeakEncryption')
        (New-MenuItem VALIDER "Forcer AES sur les comptes selectionnes (AES seul ou AES+RC4)" 'Invoke-Remediate4EnableAesOnServiceAccounts')
        (New-MenuItem VALIDER "Interdire la connexion interactive/RDP des comptes selectionnes (GPO)" 'Invoke-Remediate4DenyInteractiveLogon')
        (New-MenuItem VALIDER "Retirer les comptes de service des groupes a privileges" 'Invoke-Remediate4RemoveFromPrivilegedGroups')
        (New-MenuItem VALIDER "Reinitialiser le mot de passe des comptes selectionnes" 'Invoke-Remediate4RotatePassword')
        (New-MenuItem VALIDER "Assistant de creation d'un compte de service gere (gMSA)" 'Invoke-Remediate4CreateGmsa')
        (New-MenuItem AUDIT   "Comptes Kerberoastables (tous comptes avec SPN, priorises)" 'Invoke-Audit4KerberoastableAccounts')
    ) }
    [PSCustomObject]@{ Id = 3; Category = "Identite et comptes"; Name = "Mots de passe et authentification"; Items = @(
        (New-MenuItem AUDIT   "Rapport des comptes avec mot de passe n'expirant jamais" 'Invoke-ReportPasswordNeverExpires')
        (New-MenuItem AUDIT   "Audit de la politique de mot de passe (effective, GPO, FGPP)" 'Invoke-Audit11DefaultPasswordPolicy')
        (New-MenuItem SAFE    "Retirer le flag 'Mot de passe non requis' sur les comptes concernes" 'Invoke-SafeClearPasswordNotRequired')
        (New-MenuItem VALIDER "Corriger la politique de mot de passe par defaut (GPO + domaine)" 'Invoke-Remediate11HardenDefaultPasswordPolicy')
        (New-MenuItem VALIDER "Creer une Fine-Grained Password Policy pour les comptes de service" 'Invoke-Remediate11CreateServiceAccountFGPP')
        (New-MenuItem OUTIL   "Generer les recommandations MFA / Conditional Access (hybride)" 'Invoke-Remediate11GenerateMfaRecommendations')
        (New-MenuItem AUDIT   "Mots de passe GPP (cpassword) dans SYSVOL" 'Invoke-Audit11GppPasswords')
        (New-MenuItem AUDIT   "Hygiene des mots de passe (chiffrement reversible, non requis, DES...)" 'Invoke-Audit11PasswordHygiene')
        (New-MenuItem VALIDER "Retirer le chiffrement reversible des mots de passe" 'Invoke-Remediate11DisableReversibleEncryption')
        (New-MenuItem AUDIT   "Mots de passe stockes dans la description/les notes (heuristique)" 'Invoke-Audit11PasswordInDescription')
    ) }
    [PSCustomObject]@{ Id = 4; Category = "Authentification et protocoles"; Name = "Kerberos et delegations"; Items = @(
        (New-MenuItem AUDIT   "Rapport des delegations Kerberos (non contrainte/contrainte/RBCD)" 'Invoke-RiskyReportDelegations')
        (New-MenuItem AUDIT   "Audit AS-REP Roasting (comptes sans pre-authentification)" 'Invoke-Audit5AsRepRoasting')
        (New-MenuItem AUDIT   "Audit des approbations (filtrage SID, delegation TGT, chiffrement)" 'Invoke-Audit5TrustsEncryption')
        (New-MenuItem VALIDER "Reinitialiser le mot de passe KRBTGT (1 des 2 executions requises)" 'Invoke-RiskyResetKrbtgt')
        (New-MenuItem VALIDER "Configurer la rotation KRBTGT automatique planifiee" 'Invoke-RiskySetupKrbtgtScheduledRotation')
        (New-MenuItem VALIDER "Desactiver DES et forcer AES sur les comptes concernes" 'Invoke-RiskyDisableDesForceAes')
        (New-MenuItem VALIDER "Corriger l'exposition AS-REP Roasting" 'Invoke-Remediate5FixAsRepRoasting')
        (New-MenuItem VALIDER "Activer Kerberos Armoring (FAST)" 'Invoke-Remediate5EnableKerberosArmoring')
        (New-MenuItem AUDIT   "Etat du krbtgt (age, RODC) et de la replication" 'Invoke-Audit5KrbtgtStatus')
        (New-MenuItem AUDIT   "Comptes porteurs d'un sIDHistory" 'Invoke-Audit5SidHistory')
        (New-MenuItem VALIDER "Supprimer des entrees sIDHistory" 'Invoke-Remediate5RemoveSidHistory')
        (New-MenuItem VALIDER "Retirer la delegation non contrainte (hors DC)" 'Invoke-Remediate5RemoveUnconstrainedDelegation')
    ) }
    [PSCustomObject]@{ Id = 5; Category = "Authentification et protocoles"; Name = "NTLM / LM"; Items = @(
        (New-MenuItem SAFE    "Activer l'audit NTLM (detection avant tout blocage)" 'Invoke-SafeEnableNtlmAudit')
        (New-MenuItem AUDIT   "Rapport NTLMv1/LM detecte (journal Securite des DC)" 'Invoke-ReportNtlmV1Usage')
        (New-MenuItem VALIDER "Desactiver NTLMv1/LM (LmCompatibilityLevel) via GPO" 'Invoke-RiskyDisableNtlmV1')
        (New-MenuItem VALIDER "Restreindre le NTLM sortant des DC (Refuser + exceptions)" 'Invoke-Remediate6RestrictNtlmOutgoing')
        (New-MenuItem AUDIT   "Configuration NTLM effective sur les DC" 'Invoke-Audit6NtlmConfiguration')
    ) }
    [PSCustomObject]@{ Id = 6; Category = "Authentification et protocoles"; Name = "SMB, SYSVOL et NETLOGON"; Items = @(
        (New-MenuItem AUDIT   "Detection de l'usage SMBv1 (clients, par DC)" 'Invoke-Audit7Smb1Usage')
        (New-MenuItem AUDIT   "Etat de la signature SMB (client/serveur) sur les DC" 'Invoke-Audit7SmbSigningStatus')
        (New-MenuItem AUDIT   "Audit des partages SMB trop ouverts sur des machines choisies" 'Invoke-Audit7SensitiveShares')
        (New-MenuItem VALIDER "Desactiver SMBv1 (client + serveur) sur les DC" 'Invoke-Remediate7DisableSmb1')
        (New-MenuItem VALIDER "Desactiver SMBv1 sur des postes/serveurs choisis" 'Invoke-Remediate7DisableSmb1OnComputers')
        (New-MenuItem VALIDER "Forcer la signature SMB (client + serveur) via GPO" 'Invoke-Remediate7EnforceSmbSigning')
        (New-MenuItem VALIDER "Durcir les chemins UNC SYSVOL/NETLOGON (Hardened UNC Paths)" 'Invoke-Remediate7HardenedUncPaths')
    ) }
    [PSCustomObject]@{ Id = 7; Category = "Authentification et protocoles"; Name = "LDAP / LDAPS"; Items = @(
        (New-MenuItem AUDIT   "Audit des certificats LDAPS et negociation TLS sur le port 636" 'Invoke-Audit8LdapsCertificates')
        (New-MenuItem AUDIT   "Binds LDAP non signes / en clair (resume 2887 + clients 2889)" 'Invoke-Audit8LdapSimpleBinds')
        (New-MenuItem VALIDER "Exiger la signature LDAP / channel binding sur les DC" 'Invoke-RiskyEnforceLdapSigning')
        (New-MenuItem VALIDER "Desactiver TLS 1.0/1.1 et activer TLS 1.2 (SCHANNEL + .NET)" 'Invoke-Remediate8DisableWeakTls')
        (New-MenuItem VALIDER "Interdire les operations LDAP anonymes (dSHeuristics)" 'Invoke-Remediate8RestrictAnonymousLdap')
        (New-MenuItem AUDIT   "dSHeuristics et configuration LDAP des DC" 'Invoke-Audit8DsHeuristicsAndLdapConfig')
    ) }
    [PSCustomObject]@{ Id = 8; Category = "Infrastructure"; Name = "Controleurs de domaine"; Items = @(
        (New-MenuItem AUDIT   "Correctifs installes sur les DC (dernier correctif)" 'Invoke-ReportDCHotfixes')
        (New-MenuItem AUDIT   "Etat de la synchronisation horaire (NTP)" 'Invoke-Audit9TimeSyncStatus')
        (New-MenuItem AUDIT   "Roles et fonctionnalites a risque installes sur les DC" 'Invoke-Audit9InstalledRoles')
        (New-MenuItem SAFE    "Activer PowerShell Remoting (WinRM) sur les DC injoignables" 'Invoke-SafeEnableWinRmOnDCs')
        (New-MenuItem SAFE    "Desactiver le compte Invite (Guest) s'il est actif" 'Invoke-SafeDisableGuest')
        (New-MenuItem SAFE    "Proteger toutes les OU contre la suppression accidentelle" 'Invoke-SafeProtectOUs')
        (New-MenuItem SAFE    "Limiter le quota de creation d'ordinateurs (MachineAccountQuota = 0)" 'Invoke-SafeSetMachineAccountQuotaZero')
        (New-MenuItem VALIDER "Arreter/desactiver le service Spooler sur les DC" 'Invoke-RiskyDisableSpoolerOnDCs')
        (New-MenuItem VALIDER "Configurer la source NTP externe du PDC Emulator" 'Invoke-Remediate9ConfigurePdcTimeSource')
        (New-MenuItem VALIDER "Activer le pare-feu Windows (3 profils) sur les DC" 'Invoke-Remediate9EnableFirewallBaseline')
        (New-MenuItem AUDIT   "Matrice de durcissement des DC (Spooler, SMB, LDAP, NTLM, pare-feu...)" 'Invoke-Audit9DCHardeningMatrix')
        (New-MenuItem AUDIT   "Sante de la replication, niveaux fonctionnels et roles FSMO" 'Invoke-Audit9ReplicationAndFsmo')
        (New-MenuItem AUDIT   "Proprietaires des objets ordinateur des DC" 'Invoke-Audit9DCOwnership')
    ) }
    [PSCustomObject]@{ Id = 9; Category = "Infrastructure"; Name = "Windows LAPS"; Items = @(
        (New-MenuItem AUDIT   "Etat du deploiement LAPS (schema, couverture, mots de passe perimes)" 'Invoke-Audit10LapsDeployment')
        (New-MenuItem AUDIT   "Audit des droits de lecture du mot de passe LAPS" 'Invoke-Audit10LapsPermissions')
        (New-MenuItem VALIDER "Preparer le schema Active Directory pour Windows LAPS" 'Invoke-Remediate10PrepareSchema')
        (New-MenuItem VALIDER "Deployer la GPO Windows LAPS (+ droit d'ecriture des ordinateurs)" 'Invoke-Remediate10DeployGpo')
        (New-MenuItem VALIDER "Configurer les droits de lecture/reset LAPS" 'Invoke-Remediate10SetPermissions')
    ) }
    [PSCustomObject]@{ Id = 10; Category = "Infrastructure"; Name = "GPO de durcissement (socle GPO-SEC-*)"; Items = @(
        (New-MenuItem AUDIT   "Etat du socle GPO-SEC-* et des sauvegardes de GPO" 'Invoke-Audit12GpoBaselineStatus')
        (New-MenuItem SAFE    "Sauvegarder TOUTES les GPO du domaine" 'Invoke-Remediate12BackupAllGpos')
        (New-MenuItem SAFE    "Creer les GPO manquantes du socle GPO-SEC-* (non liees)" 'Invoke-Remediate12CreateBaselineGpoShells')
        (New-MenuItem AUDIT   "Hygiene des GPO (non liees, vides, modifiables par des non-admins)" 'Invoke-Audit12GpoHygiene')
    ) }
    [PSCustomObject]@{ Id = 11; Category = "Infrastructure"; Name = "Postes et serveurs membres"; Items = @(
        (New-MenuItem AUDIT   "Etat de Microsoft Defender sur des machines choisies" 'Invoke-Audit13DefenderStatus')
        (New-MenuItem AUDIT   "Audit des administrateurs locaux sur des machines choisies" 'Invoke-Audit13LocalAdmins')
        (New-MenuItem VALIDER "Renforcer Microsoft Defender via GPO (Cloud/Reseau/SmartScreen/ASR)" 'Invoke-Remediate13EnableDefenderProtections')
        (New-MenuItem VALIDER "Restreindre RDP via GPO (NLA, TLS, chiffrement eleve)" 'Invoke-Remediate13RestrictRdp')
        (New-MenuItem VALIDER "Retirer des comptes des administrateurs locaux" 'Invoke-Remediate13CleanupLocalAdmins')
        (New-MenuItem SAFE    "Etendre la journalisation PowerShell aux postes/serveurs choisis" 'Invoke-Remediate13EnablePowerShellLoggingExtended')
        (New-MenuItem VALIDER "Bloquer les scripts .vbs/.js (Windows Script Host)" 'Invoke-Remediate13DisableWindowsScriptHost')
        (New-MenuItem VALIDER "Activer le pare-feu Windows (3 profils)" 'Invoke-Remediate13EnableFirewallBaseline')
    ) }
    [PSCustomObject]@{ Id = 12; Category = "Infrastructure"; Name = "Reseau et anti-relay"; Items = @(
        (New-MenuItem AUDIT   "Audit de la Global Query Block List DNS (WPAD/ISATAP)" 'Invoke-Audit14GlobalQueryBlockList')
        (New-MenuItem AUDIT   "Audit des ports/services exposes sur les DC" 'Invoke-Audit14ExposedServices')
        (New-MenuItem VALIDER "Desactiver LLMNR (et mDNS) via GPO" 'Invoke-RiskyDisableLLMNR')
        (New-MenuItem SAFE    "Retablir la Global Query Block List (wpad/isatap)" 'Invoke-Remediate14RestoreGlobalQueryBlockList')
        (New-MenuItem VALIDER "Desactiver NetBIOS sur TCP/IP sur des machines choisies" 'Invoke-Remediate14DisableNetbiosOnComputers')
        (New-MenuItem VALIDER "Durcir RPC (clients non authentifies) - serveurs membres" 'Invoke-Remediate14RestrictRpc')
        (New-MenuItem VALIDER "Durcir WinRM (authentification Basic desactivee, trafic chiffre)" 'Invoke-Remediate14RestrictWinRm')
        (New-MenuItem VALIDER "Restreindre l'enumeration distante SAM/SAMR" 'Invoke-Remediate14RestrictSamEnumeration')
    ) }
    [PSCustomObject]@{ Id = 13; Category = "Resilience et pilotage"; Name = "Sauvegarde et resilience AD"; Items = @(
        (New-MenuItem AUDIT   "Etat des sauvegardes AD (metadonnees annuaire + Windows Server Backup)" 'Invoke-Audit17SystemStateBackupStatus')
        (New-MenuItem SAFE    "Activer la Corbeille Active Directory" 'Invoke-SafeEnableRecycleBin')
        (New-MenuItem VALIDER "Planifier une sauvegarde System State quotidienne" 'Invoke-Remediate17ScheduleSystemStateBackup')
        (New-MenuItem OUTIL   "Generer les procedures de recuperation (objet / DC / foret)" 'Invoke-Remediate17GenerateRecoveryProcedures')
    ) }
    [PSCustomObject]@{ Id = 14; Category = "Resilience et pilotage"; Name = "Obsolescence"; Items = @(
        (New-MenuItem AUDIT   "Inventaire des systemes d'exploitation hors / bientot hors support" 'Invoke-Audit18UnsupportedOS')
        (New-MenuItem AUDIT   "Protocoles obsoletes actifs sur des machines choisies (SMBv1, TLS 1.0/1.1)" 'Invoke-Audit18LegacyProtocolsOnComputers')
        (New-MenuItem OUTIL   "Generer le plan de traitement de l'obsolescence (consolide)" 'Invoke-Remediate18GenerateTreatmentPlan')
    ) }
    [PSCustomObject]@{ Id = 15; Category = "Resilience et pilotage"; Name = "Journalisation et detection"; Items = @(
        (New-MenuItem AUDIT   "Audit du SACL des objets sensibles (racine, AdminSDHolder, GPO)" 'Invoke-Audit19ObjectAuditingStatus')
        (New-MenuItem SAFE    "Activer l'audit avance sur les DC (auditpol + taille du journal)" 'Invoke-SafeEnableDCAuditPolicy')
        (New-MenuItem SAFE    "Activer la journalisation PowerShell (Script Block + modules)" 'Invoke-SafeEnablePowerShellLogging')
        (New-MenuItem VALIDER "Configurer l'audit SACL sur les objets sensibles" 'Invoke-Remediate19ConfigureObjectAuditing')
        (New-MenuItem VALIDER "Configurer la redirection des journaux vers un collecteur (WEF/SIEM)" 'Invoke-Remediate19ConfigureEventForwarding')
        (New-MenuItem AUDIT   "Politique d'audit EFFECTIVE sur les DC" 'Invoke-Audit19EffectiveAuditPolicy')
    ) }
    [PSCustomObject]@{ Id = 16; Category = "Resilience et pilotage"; Name = "Controle final"; Items = @(
        (New-MenuItem AUDIT   "Lancer le controle final consolide (+ rapport HTML)" 'Invoke-Audit20FinalControlReport')
        (New-MenuItem OUTIL   "Registre des exceptions (consulter / ajouter)" 'Invoke-Remediate20InitExceptionsRegister')
        (New-MenuItem AUDIT   "Diagnostic rapide note (tableau de bord, LDAP uniquement)" 'Invoke-QuickDiagnostic')
        (New-MenuItem OUTIL   "Generer le rapport HTML de synthese (diagnostic + session)" 'Invoke-HtmlReportMenu')
        (New-MenuItem AUDIT   "Historique des diagnostics (evolution de l'indice et des constats)" 'Invoke-DiagnosticHistory')
    ) }
    [PSCustomObject]@{ Id = 17; Category = "Resilience et pilotage"; Name = "Rapports transverses"; Items = @(
        (New-MenuItem AUDIT   "Export des comptes inactifs (utilisateurs/ordinateurs)" 'Invoke-ReportInactiveAccounts')
        (New-MenuItem AUDIT   "Export global (rapports rapides multi-themes)" 'Invoke-ReportAll')
        (New-MenuItem OUTIL   "Ouvrir le dossier des rapports de la session" 'Open-ReportFolder')
    ) }
    [PSCustomObject]@{ Id = 18; Category = "Resilience et pilotage"; Name = "Hygiene des comptes inactifs et automatisation"; Items = @(
        (New-MenuItem VALIDER "Desactiver les comptes inactifs par anciennete (quarantaine)" 'Invoke-RiskyDisableInactiveAccounts')
        (New-MenuItem VALIDER "Desactiver postes/utilisateurs a partir d'une DATE choisie" 'Invoke-RiskyDisableByDate')
        (New-MenuItem VALIDER "Configurer la tache planifiee de desactivation automatique" 'Invoke-AutomationSetupScheduledTask')
        (New-MenuItem AUDIT   "Etat des taches planifiees deployees par le script" 'Invoke-AutomationShowStatus')
        (New-MenuItem VALIDER "Supprimer une tache planifiee deployee par le script" 'Invoke-AutomationRemoveScheduledTask')
    ) }
)

$Script:TagStyle = @{
    'AUDIT'   = @{ Text = '[AUDIT]    '; Color = 'Cyan';  Section = 'Audit (lecture seule)' }
    'SAFE'    = @{ Text = '[SAFE]     '; Color = 'Green'; Section = 'Remediation sans impact (SAFE)' }
    'VALIDER' = @{ Text = '[A VALIDER]'; Color = 'Red';   Section = 'Remediation a impact potentiel (A VALIDER)' }
    'OUTIL'   = @{ Text = '[OUTIL]    '; Color = 'Gray';  Section = 'Outils et documentation' }
}

function Invoke-HtmlReportMenu { [void](New-HtmlReport -Open) }

function Get-ThemeById { param([int]$Id) return ($Script:Themes | Where-Object { $_.Id -eq $Id } | Select-Object -First 1) }

function Find-MenuItemByFunction {
    # Retrouve l'entree de menu d'une fonction (raccourcis D/H independants de la numerotation).
    param([Parameter(Mandatory)][string]$Fn)
    foreach ($t in $Script:Themes) {
        for ($i = 0; $i -lt $t.Items.Count; $i++) {
            if ($t.Items[$i].Fn -eq $Fn) { return [PSCustomObject]@{ Theme = $t; Index = $i + 1 } }
        }
    }
    return $null
}

function Get-DiagnosticFlags {
    # "x.y" -> statut le plus grave (CRITIQUE > ALERTE) du dernier diagnostic, pour baliser les menus.
    $flags = @{}
    if (-not $Script:LastDiagnostic) { return $flags }
    foreach ($f in $Script:LastDiagnostic.Findings) {
        if ($f.Statut -notin 'CRITIQUE', 'ALERTE' -or -not $f.Menu) { continue }
        if ($flags[$f.Menu] -ne 'CRITIQUE') { $flags[$f.Menu] = $f.Statut }
    }
    return $flags
}

function Write-ThemeItemLine {
    param([Parameter(Mandatory)][string]$Number, [Parameter(Mandatory)]$Item, [string]$Code, [hashtable]$Flags)
    $style = $Script:TagStyle[$Item.Tag]
    $flag = if ($Flags -and $Code) { $Flags[$Code] } else { $null }
    Write-Host $(if ($flag) { '  !' } else { '   ' }) -ForegroundColor $(if ($flag -eq 'CRITIQUE') { 'Red' } else { 'Yellow' }) -NoNewline
    Write-Host ("{0,3}. " -f $Number) -NoNewline
    Write-Host $style.Text -ForegroundColor $style.Color -NoNewline
    Write-Host (" {0}" -f $Item.Label) -NoNewline
    if ($Code) { Write-Host ("  [{0}]" -f $Code) -ForegroundColor DarkGray } else { Write-Host "" }
}

function Invoke-ThemeItem {
    <#
        Point d'execution unique de toutes les actions : trace dans l'historique de session,
        remet a zero le compteur d'echecs (messages de resultat fiables), et intercepte toute
        erreur inattendue pour qu'elle ne fasse jamais sortir du script.
    #>
    param([Parameter(Mandatory)]$Theme, [Parameter(Mandatory)][int]$Index, [switch]$NoPause)
    $item = $Theme.Items[$Index - 1]
    $label = "{0}.{1} {2}" -f $Theme.Id, $Index, $item.Label
    $Script:CurrentActionFailures = 0
    $Script:LastActionRef = [PSCustomObject]@{ Theme = $Theme; Index = $Index }
    $Script:SessionHistory.Add([PSCustomObject]@{ Date = Get-Date; Label = $label; Tag = $item.Tag })
    Write-Log ("=== Action {0} [{1}] ===" -f $label, $item.Tag) -Level INFO
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        & $item.Fn
    } catch {
        Write-Log ("Erreur inattendue pendant l'action '{0}' : {1}" -f $label, $_.Exception.Message) -Level ERROR
        Write-Log ("Emplacement : {0}" -f ($_.InvocationInfo.PositionMessage -replace "`r?`n", ' ')) -Level ERROR
    }
    $sw.Stop()
    Write-Host ""
    Write-Host ("--- Fin de l'action {0}.{1} ({2:N1} s){3} ---" -f $Theme.Id, $Index, $sw.Elapsed.TotalSeconds, $(if ($Script:CurrentActionFailures -gt 0) { ", $($Script:CurrentActionFailures) echec(s)" } else { '' })) -ForegroundColor $(if ($Script:CurrentActionFailures -gt 0) { 'Yellow' } else { 'DarkGray' })
    if (-not $NoPause) { Pause-Menu }
}

function Resolve-DirectAccess {
    # "4.2", "4-2" ou "4 2" -> @{ Theme; Index } si valide.
    param([string]$Text)
    if ($Text -notmatch '^\s*(\d{1,2})\s*[\.\-/ ]\s*(\d{1,2})\s*$') { return $null }
    $t = Get-ThemeById -Id ([int]$Matches[1])
    $i = [int]$Matches[2]
    if (-not $t -or $i -lt 1 -or $i -gt $t.Items.Count) { return $null }
    return [PSCustomObject]@{ Theme = $t; Index = $i }
}

function Invoke-CommonShortcut {
    <#
        Raccourcis disponibles dans TOUS les menus : acces direct x.y, D, H, R, P, ?.
        Retourne $true si la saisie a ete traitee.
    #>
    param([string]$Choice)
    $direct = Resolve-DirectAccess -Text $Choice
    if ($direct) { Invoke-ThemeItem -Theme $direct.Theme -Index $direct.Index; return $true }
    switch ($Choice.ToUpper()) {
        'D' { $m = Find-MenuItemByFunction 'Invoke-QuickDiagnostic'; Invoke-ThemeItem -Theme $m.Theme -Index $m.Index; return $true }
        'H' { $m = Find-MenuItemByFunction 'Invoke-HtmlReportMenu'; Invoke-ThemeItem -Theme $m.Theme -Index $m.Index; return $true }
        'R' { Invoke-SearchActions; return $true }
        '?' { Show-Help; return $true }
        'P' {
            if ($Script:LastActionRef) { Invoke-ThemeItem -Theme $Script:LastActionRef.Theme -Index $Script:LastActionRef.Index }
            else { Write-Host "Aucune action lancee dans cette session." -ForegroundColor Yellow; Start-Sleep -Milliseconds 900 }
            return $true
        }
    }
    return $false
}

function Show-Help {
    Show-Banner
    Write-Host " AIDE" -ForegroundColor White
    Write-Host ""
    Write-Host " Navigation" -ForegroundColor Cyan
    Write-Info "  1..18     ouvrir un theme             x.y (ex : 4.2)  lancer directement l'action y du theme x" `
               "  D         diagnostic rapide note       H               rapport HTML de synthese" `
               "  R         rechercher une action        P               relancer la derniere action" `
               "  S         basculer simulation / reel   Q / 0           quitter / revenir"
    Write-Host ""
    Write-Host " Lecture des menus" -ForegroundColor Cyan
    Write-Host "  [AUDIT]     " -ForegroundColor Cyan -NoNewline; Write-Host "lecture seule, aucune modification"
    Write-Host "  [SAFE]      " -ForegroundColor Green -NoNewline; Write-Host "modification sans impact sur la production (confirmation O/N)"
    Write-Host "  [A VALIDER] " -ForegroundColor Red -NoNewline; Write-Host "impact possible : saisie de CONFIRMER en mode reel"
    Write-Host "  [OUTIL]     " -ForegroundColor Gray -NoNewline; Write-Host "documentation, procedures, outillage"
    Write-Host "  !           " -ForegroundColor Red -NoNewline; Write-Host "action liee a un constat CRITIQUE (rouge) ou ALERTE (jaune) du dernier diagnostic"
    Write-Host ""
    Write-Host " Selections dans les listes" -ForegroundColor Cyan
    Write-Info "  0,3,7  |  2-6  |  tous  |  vide = annuler. Les selecteurs d'UO acceptent un filtre et un DN complet."
    Write-Host ""
    Write-Host " Securite" -ForegroundColor Cyan
    Write-Info "  Le mode SIMULATION (defaut) journalise ce qui SERAIT fait sans rien modifier." `
               "  Les comptes systeme, DC, comptes d'approbation, gMSA et membres des groupes a privileges" `
               "  ne sont jamais desactives. Aucune suppression de compte n'est jamais effectuee."
    Write-Host ""
    Write-Host " Fichiers" -ForegroundColor Cyan
    Write-Info ("  Journal  : {0}" -f $Script:LogFile) `
               ("  Rapports : {0}" -f $Script:ReportDir) `
               ("  Historique des diagnostics : {0}" -f $Script:DiagHistoryDir)
    Pause-Menu
}

function Show-ThemeMenu {
    param([Parameter(Mandatory)]$Theme)
    do {
        Show-Banner
        $flags = Get-DiagnosticFlags
        Write-Host ("=== {0}. {1} ===" -f $Theme.Id, $Theme.Name.ToUpper()) -ForegroundColor Cyan
        foreach ($tag in 'AUDIT', 'SAFE', 'VALIDER', 'OUTIL') {
            $idx = @(for ($i = 0; $i -lt $Theme.Items.Count; $i++) { if ($Theme.Items[$i].Tag -eq $tag) { $i } })
            if ($idx.Count -eq 0) { continue }
            Write-Host ("  -- {0} --" -f $Script:TagStyle[$tag].Section) -ForegroundColor DarkYellow
            foreach ($i in $idx) { Write-ThemeItemLine -Number ([string]($i + 1)) -Item $Theme.Items[$i] -Code ("{0}.{1}" -f $Theme.Id, ($i + 1)) -Flags $flags }
        }
        Write-Host ""
        Write-Host "     0. Retour    [x.y] autre theme    [P] relancer    [D] diagnostic    [?] aide" -ForegroundColor DarkGray
        $choice = ([string](Read-Host "Votre choix")).Trim()
        if ($choice -eq '') { continue }
        if ($choice -in @('0', 'q', 'Q')) { return }
        if (Invoke-CommonShortcut -Choice $choice) { continue }
        $n = 0
        if ([int]::TryParse($choice, [ref]$n) -and $n -ge 1 -and $n -le $Theme.Items.Count) {
            Invoke-ThemeItem -Theme $Theme -Index $n
        } else {
            Write-Host "Choix invalide." -ForegroundColor Yellow
            Start-Sleep -Milliseconds 700
        }
    } while ($true)
}

function Invoke-SearchActions {
    Write-Section "Recherche d'une action par mot-cle" Magenta
    Write-Info "Recherche dans les libelles ET les noms de themes (plusieurs mots = tous requis)." `
               "Saisissez ensuite le numero de resultat pour lancer l'action, avec ses garde-fous habituels."
    $keyword = Read-Host "Mot(s)-cle(s) (ex : kerberoasting, laps, smb1, admin, rdp...)"
    if ([string]::IsNullOrWhiteSpace($keyword)) { return }
    $words = @($keyword -split '\s+' | Where-Object { $_ })

    $results = @(foreach ($t in $Script:Themes) {
        for ($i = 0; $i -lt $t.Items.Count; $i++) {
            $hay = "{0} {1} {2}" -f $t.Name, $t.Items[$i].Label, $t.Items[$i].Tag
            if (@($words | Where-Object { $hay -notlike "*$_*" }).Count -eq 0) { [PSCustomObject]@{ Theme = $t; Index = $i + 1 } }
        }
    })
    if ($results.Count -eq 0) { Write-Log ("Aucune action ne correspond a '{0}'." -f $keyword) -Level WARN; Pause-Menu; return }

    Write-Host ""
    Write-Host ("{0} resultat(s) pour '{1}' :" -f $results.Count, $keyword) -ForegroundColor Yellow
    for ($r = 0; $r -lt $results.Count; $r++) {
        $res = $results[$r]
        Write-Host ("  [{0,2}] {1,-30} " -f ($r + 1), ("{0}.{1} {2}" -f $res.Theme.Id, $res.Index, $res.Theme.Name).Substring(0, [Math]::Min(30, ("{0}.{1} {2}" -f $res.Theme.Id, $res.Index, $res.Theme.Name).Length))) -NoNewline -ForegroundColor DarkGray
        $item = $res.Theme.Items[$res.Index - 1]
        Write-Host $Script:TagStyle[$item.Tag].Text -ForegroundColor $Script:TagStyle[$item.Tag].Color -NoNewline
        Write-Host (" {0}" -f $item.Label)
    }
    $sel = Read-Host "Numero du resultat a lancer (vide = retour)"
    $n = 0
    if ([int]::TryParse($sel, [ref]$n) -and $n -ge 1 -and $n -le $results.Count) {
        Invoke-ThemeItem -Theme $results[$n - 1].Theme -Index $results[$n - 1].Index
    }
}

function Switch-SimulationMode {
    if ($Script:SimulationMode) {
        Write-Host ""
        Write-Host "Vous allez desactiver le mode simulation : les actions confirmees seront REELLEMENT appliquees." -ForegroundColor Red
        Write-Host "Prerequis conseilles : sauvegarde des GPO (10.2), sauvegarde AD recente (13.1), fenetre de maintenance." -ForegroundColor Yellow
        if ((Read-Host "Tapez EXACTEMENT 'CONFIRMER' pour passer en mode reel") -ceq "CONFIRMER") {
            $Script:SimulationMode = $false
            Write-Log "Mode REEL active par l'operateur." -Level WARN
        }
    } else {
        $Script:SimulationMode = $true
        Write-Log "Retour au mode SIMULATION." -Level INFO
    }
}

function Show-SessionSummary {
    $s = $Script:SessionStats
    Write-Host ""
    Write-Host "=== Synthese de la session ===" -ForegroundColor Cyan
    Write-Host ("  Actions d'ecriture : {0} (reussies {1}, echecs {2}, simulees {3})" -f $s.Actions, $s.Succes, $s.Echecs, $s.Simulees)
    Write-Host ("  Rapports produits  : {0} (dossier {1})" -f $Script:SessionReports.Count, $Script:ReportDir)
    Write-Host ("  Journal            : {0}" -f $Script:LogFile)
    if ($s.Echecs -gt 0) { Write-Host "  Des actions ont echoue : consultez le journal (niveau ERROR)." -ForegroundColor Yellow }
}

function Show-MainMenu {
    do {
        Show-Banner
        $flags = Get-DiagnosticFlags
        Write-Host " MENU PRINCIPAL" -ForegroundColor White
        $lastCat = $null
        foreach ($t in $Script:Themes) {
            if ($t.Category -ne $lastCat) {
                Write-Host ""
                Write-Host (" -- {0} --" -f $t.Category.ToUpper()) -ForegroundColor DarkYellow
                $lastCat = $t.Category
            }
            $nA = @($t.Items | Where-Object Tag -eq 'AUDIT').Count
            $nR = @($t.Items | Where-Object { $_.Tag -in 'SAFE', 'VALIDER' }).Count
            $codes = @($flags.Keys | Where-Object { $_ -like "$($t.Id).*" })
            $nc = @($codes | Where-Object { $flags[$_] -eq 'CRITIQUE' }).Count
            $nw = $codes.Count - $nc
            Write-Host (" {0,3}. " -f $t.Id) -NoNewline
            Write-Host ("{0,-48}" -f $t.Name) -ForegroundColor Cyan -NoNewline
            Write-Host ("{0,2} audit(s), {1,2} remediation(s)" -f $nA, $nR) -ForegroundColor DarkGray -NoNewline
            if ($nc -gt 0) { Write-Host ("  ! {0} critique(s)" -f $nc) -ForegroundColor Red -NoNewline }
            if ($nw -gt 0) { Write-Host ("  ! {0} alerte(s)" -f $nw) -ForegroundColor Yellow -NoNewline }
            Write-Host ""
        }
        Write-Host ""
        Write-Host "  [D] Diagnostic rapide note (lecture seule)   [H] Rapport HTML de synthese" -ForegroundColor Magenta
        Write-Host "  [R] Rechercher une action par mot-cle        [x.y] Acces direct (ex : 4.2)" -ForegroundColor DarkCyan
        Write-Host "  [P] Relancer la derniere action              [?] Aide (raccourcis, legende)" -ForegroundColor DarkCyan
        $modeLabel = if ($Script:SimulationMode) { "Activer le mode REEL (desactiver la simulation)" } else { "Repasser en mode SIMULATION" }
        Write-Host ("  [S] {0}" -f $modeLabel) -ForegroundColor Yellow
        Write-Host "  [Q] Quitter"
        Write-Host ""
        $choice = ([string](Read-Host "Votre choix")).Trim()
        if ($choice -eq '') { continue }
        if (Invoke-CommonShortcut -Choice $choice) { continue }
        switch ($choice.ToUpper()) {
            'S' { Switch-SimulationMode }
            'Q' {
                Show-SessionSummary
                if (($Script:SessionReports.Count -gt 0 -or $Script:SessionStats.Actions -gt 0) -and (Read-YesNo -Prompt "Generer le rapport HTML de synthese avant de quitter ?")) {
                    try { [void](New-HtmlReport) } catch { Write-Log ("Rapport HTML non genere : {0}" -f $_.Exception.Message) -Level WARN }
                }
                return
            }
            default {
                $n = 0
                $t = if ([int]::TryParse($choice, [ref]$n)) { Get-ThemeById -Id $n } else { $null }
                if ($t) { Show-ThemeMenu -Theme $t }
                else { Write-Host "Choix invalide ('?' pour l'aide)." -ForegroundColor Yellow; Start-Sleep -Milliseconds 700 }
            }
        }
    } while ($true)
}

# ============================================================
#  POINT D'ENTREE
# ============================================================

# Script charge par dot-sourcing (tests automatises) : definitions uniquement, aucun menu.
if ($MyInvocation.InvocationName -eq '.') { return }

Show-Banner
Write-Log ("Demarrage du script de remediation AD v{0} (PowerShell {1}, {2})." -f $Script:Version, $PSVersionTable.PSVersion, $env:COMPUTERNAME) -Level INFO

if (-not (Test-Prerequisites)) {
    Write-Log "Prerequis non satisfaits. Corrigez les points ci-dessus avant de continuer." -Level ERROR
    if (-not $QuickAudit) { [void](Read-Host "Appuyez sur Entree pour quitter") }
    exit 1
}

if ($QuickAudit) {
    # Mode non interactif : diagnostic + rapport HTML, code retour 2 si constat critique.
    Invoke-QuickDiagnostic
    [void](New-HtmlReport)
    $crit = @($Script:LastDiagnostic.Findings | Where-Object Statut -eq 'CRITIQUE').Count
    Write-Log ("Fin du diagnostic non interactif ({0} constat(s) critique(s))." -f $crit) -Level INFO
    exit $(if ($crit -gt 0) { 2 } else { 0 })
}

if ($Action) {
    # Lancement direct d'une action (ex : -Action 4.2), puis sortie. Code retour 1 si un echec.
    $direct = Resolve-DirectAccess -Text $Action
    if (-not $direct) { Write-Log ("Action '{0}' inexistante (format theme.item, voir le catalogue)." -f $Action) -Level ERROR; exit 1 }
    if (-not $Simulation) { Switch-SimulationMode }
    if ($Script:SimulationMode) { Write-Log "Execution en mode SIMULATION (aucune modification)." -Level WARN }
    Invoke-ThemeItem -Theme $direct.Theme -Index $direct.Index -NoPause
    Show-SessionSummary
    exit $(if ($Script:SessionStats.Echecs -gt 0) { 1 } else { 0 })
}

Write-Log "Mode simulation actif par defaut. Utilisez [S] dans le menu principal pour appliquer reellement les actions ([?] pour l'aide)." -Level WARN
Pause-Menu
Show-MainMenu
Write-Log "Fin du script." -Level INFO
