<#
    Invoke-SelfTest.ps1
    ------------------------------------------------------------------
    Tests automatises SANS dependance (ni Pester, ni Active Directory) de
    AD_Remediation_Menu.ps1 : syntaxe, coherence des menus et des renvois du
    diagnostic, et logique pure (selections, cycle de vie des OS, GPP, sIDHistory,
    evolution du diagnostic, rapport HTML...).

    Utilisation (Windows PowerShell 5.1 ou PowerShell 7, Windows ou Linux) :
        .\Tests\Invoke-SelfTest.ps1
    Code retour : 0 = tous les tests passent, 1 = au moins un echec.
    ------------------------------------------------------------------
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'AD_Remediation_Menu.ps1'
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("ADRemSelfTest_{0}" -f [guid]::NewGuid().ToString('N'))
New-Item -Path $tmp -ItemType Directory -Force | Out-Null

$results = [System.Collections.Generic.List[object]]::new()
function Test-Case {
    param([string]$Name, [scriptblock]$Body)
    try {
        $r = & $Body
        if ($r -eq $false) { throw "assertion fausse" }
        $results.Add([PSCustomObject]@{ Test = $Name; Ok = $true; Detail = '' })
    } catch {
        $results.Add([PSCustomObject]@{ Test = $Name; Ok = $false; Detail = $_.Exception.Message })
    }
}
function Assert-Equal {
    param($Expected, $Actual, [string]$Label = '')
    if ($Expected -is [array] -or $Actual -is [array]) {
        $e = @($Expected) -join ','; $a = @($Actual) -join ','
        if ($e -ne $a) { throw ("{0} attendu [{1}], obtenu [{2}]" -f $Label, $e, $a) }
    } elseif ($Expected -ne $Actual) { throw ("{0} attendu [{1}], obtenu [{2}]" -f $Label, $Expected, $Actual) }
}

# --- 1. Syntaxe -------------------------------------------------------------
Test-Case "Le script se parse sans erreur" {
    $tokens = $null; $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
    if ($errors.Count -gt 0) { throw (($errors | Select-Object -First 3 | ForEach-Object { "L{0}: {1}" -f $_.Extent.StartLineNumber, $_.Message }) -join ' | ') }
}

Test-Case "Le script est encode en UTF-8 avec BOM (Windows PowerShell 5.1)" {
    $b = [IO.File]::ReadAllBytes($scriptPath)
    ($b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF)
}

# Chargement des definitions (le point d'entree ne s'execute pas en dot-sourcing).
. $scriptPath -LogDir $tmp

# --- 2. Coherence des menus ---------------------------------------------------
Test-Case "Chaque entree de menu pointe vers une fonction existante" {
    $missing = foreach ($t in $Script:Themes) { foreach ($i in $t.Items) { if (-not (Get-Command -Name $i.Fn -CommandType Function -ErrorAction SilentlyContinue)) { "{0}:{1}" -f $t.Id, $i.Fn } } }
    if ($missing) { throw ("Fonctions introuvables : {0}" -f ($missing -join ', ')) }
}

Test-Case "Identifiants de themes uniques et consecutifs" {
    Assert-Equal (1..$Script:Themes.Count) @($Script:Themes | ForEach-Object { $_.Id }) "Ids"
}

Test-Case "Libelles d'actions uniques" {
    $dup = $Script:Themes.Items | Group-Object Label | Where-Object Count -gt 1
    if ($dup) { throw ("Doublons : {0}" -f (($dup | ForEach-Object Name) -join ' | ')) }
}

Test-Case "Chaque fonction n'est referencee qu'une fois dans les menus" {
    $dup = $Script:Themes.Items | Group-Object Fn | Where-Object Count -gt 1
    if ($dup) { throw ("Fonctions en double : {0}" -f (($dup | ForEach-Object Name) -join ', ')) }
}

Test-Case "Tous les renvois x.y du diagnostic existent dans les menus" {
    $text = Get-Content -LiteralPath $scriptPath -Raw
    $start = $text.IndexOf('function Invoke-QuickDiagnostic')
    $end = $text.IndexOf('function Get-DiagnosticScore')
    $body = $text.Substring($start, $end - $start)
    $codes = [regex]::Matches($body, "'(\d{1,2}\.\d{1,2})'") | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
    if (@($codes).Count -lt 20) { throw "Trop peu de renvois trouves ($(@($codes).Count))" }
    $bad = @($codes | Where-Object { -not (Resolve-DirectAccess -Text $_) })
    if ($bad) { throw ("Renvois invalides : {0}" -f ($bad -join ', ')) }
}

Test-Case "Raccourcis D et H resolus par nom de fonction" {
    (Find-MenuItemByFunction 'Invoke-QuickDiagnostic') -and (Find-MenuItemByFunction 'Invoke-HtmlReportMenu') -and -not (Find-MenuItemByFunction 'Fonction-Inexistante')
}

Test-Case "Le code mort Select-AccountsInteractive a ete supprime" {
    -not (Get-Command Select-AccountsInteractive -ErrorAction SilentlyContinue)
}

# --- 3. Saisies ----------------------------------------------------------------
Test-Case "ConvertTo-IndexList : listes, plages, 'tous', bornes" {
    Assert-Equal @(0, 3, 5) @(ConvertTo-IndexList -Selection '0,3,5' -Count 10) "liste"
    Assert-Equal @(2, 3, 4) @(ConvertTo-IndexList -Selection '4-2' -Count 10) "plage inversee"
    Assert-Equal @(0, 1, 2) @(ConvertTo-IndexList -Selection 'tous' -Count 3) "tous"
    Assert-Equal @(1) @(ConvertTo-IndexList -Selection '1,1,99' -Count 3 6>$null) "doublon + hors bornes"
    Assert-Equal 0 @(ConvertTo-IndexList -Selection '' -Count 3).Count "vide"
}

Test-Case "Resolve-DirectAccess : formats acceptes et refuses" {
    $a = Resolve-DirectAccess -Text '4.2'
    $b = Resolve-DirectAccess -Text ' 4-2 '
    ($a.Theme.Id -eq 4 -and $a.Index -eq 2 -and $b.Index -eq 2 -and
     -not (Resolve-DirectAccess -Text '4.99') -and -not (Resolve-DirectAccess -Text '99.1') -and -not (Resolve-DirectAccess -Text 'abc'))
}

# --- 4. Cycle de vie des OS (calcule a une date fixe) ---------------------------
$today = [datetime]'2026-10-04'
$osCases = @(
    @('Windows Server 2012 R2 Standard', '6.3 (9600)', 'EOL'),
    @('Windows Server 2016 Standard', '10.0 (14393)', 'BIENTOT'),
    @('Windows Server 2019 Datacenter', '10.0 (17763)', 'SUPPORTE'),
    @('Windows Server 2022 Standard', '10.0 (20348)', 'SUPPORTE'),
    @('Windows 10 Professionnel', '10.0 (19045)', 'EOL'),
    @('Windows 10 Enterprise LTSC', '10.0 (17763)', 'SUPPORTE'),
    @('Windows 10 Entreprise LTSC', '10.0 (19044)', 'BIENTOT'),
    @('Windows 10 IoT Enterprise LTSC', '10.0 (19044)', 'SUPPORTE'),
    @('Windows 11 Professionnel', '10.0 (22631)', 'EOL'),
    @('Windows 11 Entreprise', '10.0 (22631)', 'BIENTOT'),
    @('Windows 11 Pro', '10.0 (26100)', 'BIENTOT'),
    @('Windows 11 Enterprise', '10.0 (26100)', 'SUPPORTE'),
    @('Windows 11 Enterprise LTSC', '10.0 (26100)', 'SUPPORTE'),
    @('Windows 11 Pro', '10.0 (26300)', 'SUPPORTE'),
    @('Windows 7 Professional', '6.1 (7601)', 'EOL'),
    @('Ubuntu 22.04', '', 'INCONNU'),
    @('', '', 'INCONNU')
)
foreach ($c in $osCases) {
    $os = $c[0]; $ver = $c[1]; $exp = $c[2]
    Test-Case ("Cycle de vie : '{0}' {1} -> {2}" -f $os, $ver, $exp) {
        Assert-Equal $exp (Get-OsSupportStatus -OS $os -Version $ver -Today $today).Statut
    }
}
Test-Case "Cycle de vie : le statut evolue avec la date (pas de libelle fige)" {
    ((Get-OsSupportStatus -OS 'Windows Server 2019 Standard' -Version '10.0 (17763)' -Today ([datetime]'2029-02-01')).Statut -eq 'EOL') -and
    ((Get-OsSupportStatus -OS 'Windows Server 2016 Standard' -Version '10.0 (14393)' -Today ([datetime]'2024-01-01')).Statut -eq 'SUPPORTE')
}

# --- 5. Logique de detection ------------------------------------------------------
Test-Case "GPP : chaque cpassword est associe au compte de SON element" {
    $xml = @'
<Groups><User name="a"><Properties action="U" userName="ADM_A" cpassword="AAAA" /></User>
<User name="b"><Properties action="U" cpassword="BBBB" userName="SVC_B"/></User>
<User name="c"><Properties action="U" userName="SANS_MDP" cpassword="" /></User></Groups>
'@
    $e = @(Get-GppPasswordEntries -Content $xml)
    Assert-Equal 2 $e.Count "nombre"
    Assert-Equal @('ADM_A', 'SVC_B') @($e.Compte) "comptes"
}

Test-Case "sIDHistory : evaluation des SID" {
    $d = 'S-1-5-21-1-2-3'
    ((Get-SidHistoryRisk -Sid "$d-1105" -DomainSid $d) -like 'CRITIQUE*') -and
    ((Get-SidHistoryRisk -Sid 'S-1-5-21-9-9-9-512' -DomainSid $d) -like 'CRITIQUE*') -and
    ((Get-SidHistoryRisk -Sid 'S-1-5-32-544' -DomainSid $d) -like 'CRITIQUE*') -and
    ((Get-SidHistoryRisk -Sid 'S-1-5-21-9-9-9-1500' -DomainSid $d) -like 'A verifier*')
}

Test-Case "Comptes ordinateurs : gMSA, DC, cluster, SSO et non-Windows distingues" {
    (Get-ComputerAccountKind -Computer ([PSCustomObject]@{ ObjectClass = 'msDS-GroupManagedServiceAccount' })) -eq 'MSA' -and
    (Get-ComputerAccountKind -Computer ([PSCustomObject]@{ ObjectClass = 'computer'; PrimaryGroupID = 516 })) -eq 'DC' -and
    (Get-ComputerAccountKind -Computer ([PSCustomObject]@{ ObjectClass = 'computer'; SamAccountName = 'AZUREADSSOACC$' })) -eq 'EntraSSO' -and
    (Get-ComputerAccountKind -Computer ([PSCustomObject]@{ ObjectClass = 'computer'; ServicePrincipalName = @('MSClusterVirtualServer/SQLCL') })) -eq 'Cluster' -and
    (Get-ComputerAccountKind -Computer ([PSCustomObject]@{ ObjectClass = 'computer'; OperatingSystem = 'Ubuntu' })) -eq 'NonWindows' -and
    (Get-ComputerAccountKind -Computer ([PSCustomObject]@{ ObjectClass = 'computer'; PrimaryGroupID = 515; OperatingSystem = 'Windows 11 Pro' })) -eq 'Computer'
}

Test-Case "Mot de passe en description : detection sans faux positif ni fuite du secret" {
    $hit = Get-PasswordExcerpt -Text 'Compte imprimante - mdp : Toto2024!'
    ($hit -and $hit.EndsWith('***') -and $hit -notmatch 'Toto') -and
    (Get-PasswordExcerpt -Text 'password=abc') -and
    -not (Get-PasswordExcerpt -Text "Mot de passe n'expire jamais") -and
    -not (Get-PasswordExcerpt -Text 'Compte de service SQL') -and
    -not (Get-PasswordExcerpt -Text '')
}

Test-Case "Types de chiffrement Kerberos" {
    (Get-SupportedEncryptionTypesLabel -Value 24) -eq 'AES128+AES256' -and
    (Get-SupportedEncryptionTypesLabel -Value 28) -eq 'RC4-HMAC+AES128+AES256' -and
    (Test-HasAesEncryptionType 24) -and -not (Test-HasAesEncryptionType 4) -and -not (Test-HasAesEncryptionType $null)
}

Test-Case "Test-DNUnderAny : sous-arbre uniquement" {
    (Test-DNUnderAny -DN 'CN=a,OU=X,DC=c' -Containers @('OU=X,DC=c')) -and
    -not (Test-DNUnderAny -DN 'CN=a,OU=XY,DC=c' -Containers @('OU=Y,DC=c')) -and
    -not (Test-DNUnderAny -DN 'OU=X,DC=c' -Containers @('OU=X,DC=c'))
}

Test-Case "Mot de passe aleatoire : longueur, 4 classes, unicite" {
    $p1 = New-RandomComplexPassword -Length 32
    $p2 = New-RandomComplexPassword -Length 32
    ($p1.Length -eq 32 -and $p1 -cmatch '[A-Z]' -and $p1 -cmatch '[a-z]' -and $p1 -match '\d' -and $p1 -match '[^A-Za-z0-9]' -and $p1 -ne $p2)
}

Test-Case "Lecture d'un modele de securite (GptTmpl.inf)" {
    $inf = Join-Path $tmp 'GptTmpl.inf'
    Set-Content -LiteralPath $inf -Encoding Unicode -Value "[Unicode]`r`nUnicode=yes`r`n[System Access]`r`nMinimumPasswordLength = 14`r`nLockoutBadCount = 10`r`n[Version]`r`nsignature=`"`$CHICAGO`$`""
    $r = Read-SecurityTemplate -Path $inf
    ($r['System Access']['MinimumPasswordLength'] -eq '14' -and $r['System Access']['LockoutBadCount'] -eq '10')
}

# --- 6. Diagnostic : indice, evolution, historique, rapport HTML -----------------
function New-Finding { param($Cat, $Ctl, $St, $Menu = '1.1') [PSCustomObject]@{ Categorie = $Cat; Controle = $Ctl; Statut = $St; Valeur = 'v'; Recommandation = 'r'; Menu = $Menu } }

Test-Case "Indice d'hygiene : -10 par critique, -3 par alerte, borne a 0" {
    Assert-Equal 87 (Get-DiagnosticScore -Findings @((New-Finding a b CRITIQUE), (New-Finding a c ALERTE), (New-Finding a d OK)))
    Assert-Equal 0 (Get-DiagnosticScore -Findings @(1..11 | ForEach-Object { New-Finding a "x$_" CRITIQUE }))
}

Test-Case "Evolution : degrade / ameliore / inchange / nouveau / non verifie" {
    $prev = @((New-Finding K a OK), (New-Finding K b CRITIQUE), (New-Finding K c ALERTE), (New-Finding K e OK))
    $cur = @((New-Finding K a ALERTE), (New-Finding K b OK), (New-Finding K c ALERTE), (New-Finding K d INFO), (New-Finding K e ERREUR))
    Compare-DiagnosticFindings -Current $cur -Previous $prev
    Assert-Equal @('Degrade', 'Ameliore', 'Inchange', 'Nouveau controle', 'Non verifie') @($cur.Evolution)
}

Test-Case "Evolution : sans diagnostic precedent, colonne vide" {
    $cur = @((New-Finding K a OK))
    Compare-DiagnosticFindings -Current $cur -Previous $null
    $null -eq $cur[0].Evolution
}

Test-Case "Historique : sauvegarde puis relecture des diagnostics (JSON)" {
    $d1 = [PSCustomObject]@{ Date = [datetime]'2026-09-01 10:00:00'; Score = 61; Findings = @((New-Finding K a CRITIQUE)) }
    $d2 = [PSCustomObject]@{ Date = [datetime]'2026-10-01 10:00:00'; Score = 90; Findings = @((New-Finding K a OK)) }
    Save-DiagnosticSnapshot -Diagnostic $d1 -Domain 'corp.local'
    Save-DiagnosticSnapshot -Diagnostic $d2 -Domain 'corp.local'
    Save-DiagnosticSnapshot -Diagnostic $d2 -Domain 'autre.local'
    $s = @(Get-DiagnosticSnapshots -Domain 'corp.local')
    Assert-Equal 2 $s.Count "nombre"
    Assert-Equal @(61, 90) @($s.Score) "indices"
    Assert-Equal ([datetime]'2026-10-01 10:00:00') $s[1].Date "date"
    Assert-Equal 'CRITIQUE' $s[0].Findings[0].Statut "constat"
}

Test-Case "Rapport HTML : genere, autonome, filtres JS valides" {
    $Script:ADDomainCache = [PSCustomObject]@{ DNSRoot = 'corp.local'; DomainMode = 'Windows2016Domain'; PDCEmulator = 'dc1.corp.local'; DistinguishedName = 'DC=corp,DC=local' }
    $f = @((New-Finding Kerberos 'Age <krbtgt>' CRITIQUE '4.4'), (New-Finding LDAP 'dSHeuristics' OK '7.5'))
    Compare-DiagnosticFindings -Current $f -Previous @((New-Finding Kerberos 'Age <krbtgt>' OK '4.4'))
    $Script:LastDiagnostic = [PSCustomObject]@{ Date = Get-Date; Findings = $f; Score = 90 }
    $Script:PreviousDiagnostic = [PSCustomObject]@{ Date = [datetime]'2026-09-01'; Score = 100 }
    $path = New-HtmlReport 6>$null
    $html = Get-Content -LiteralPath $path -Raw
    if ($html -notmatch 'Age &lt;krbtgt&gt;') { throw "contenu non echappe" }
    if ($html -match '<script src|<link ') { throw "dependance externe" }
    if ($html -notmatch "class='evo e-degrade'") { throw "colonne evolution absente" }
    if ($html -notmatch '<svg') { throw "courbe d'evolution absente" }
    $node = Get-Command node -ErrorAction SilentlyContinue
    if ($node) {
        $js = [regex]::Match($html, '(?s)<script>(.*)</script>').Groups[1].Value
        $jsFile = Join-Path $tmp 'report.js'
        Set-Content -LiteralPath $jsFile -Value $js -Encoding UTF8
        & $node.Source --check $jsFile 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "JavaScript du rapport invalide" }
    }
    $true
}

# --- Bilan ------------------------------------------------------------------------
Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
$failed = @($results | Where-Object { -not $_.Ok })
foreach ($r in $results) {
    Write-Host ("[{0}] {1}{2}" -f $(if ($r.Ok) { ' OK ' } else { 'ECHEC' }), $r.Test, $(if ($r.Detail) { " -> $($r.Detail)" } else { '' })) -ForegroundColor $(if ($r.Ok) { 'Green' } else { 'Red' })
}
Write-Host ("`n{0}/{1} test(s) reussi(s)." -f ($results.Count - $failed.Count), $results.Count) -ForegroundColor $(if ($failed.Count) { 'Red' } else { 'Green' })
exit $(if ($failed.Count) { 1 } else { 0 })
