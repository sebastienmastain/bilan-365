<#PSScriptInfo
.VERSION 1.3.1
.GUID 25ee63a4-b719-4f3c-a76b-7151bb4487ff
.AUTHOR Pactio
.COMPANYNAME Pactio
.COPYRIGHT (c) 2026 Sébastien Mastain EI
.TAGS Microsoft365 M365 Intune Entra Audit Security Bilan French Sysadmin MSP
.PROJECTURI https://github.com/sebastienmastain/bilan-365
.REQUIREDMODULES Microsoft.Graph.Authentication
.RELEASENOTES 1.3.1 - SMTP AUTH : licence Entra ID P1/P2 vérifiée avant de lire le journal des connexions, période réellement analysée affichée (7 jours sans P1 : jamais de conclusion « on peut couper »), comptes de copieur / scanner / application repérés avec leur adresse IP (retour de Ludo1377). Correction : nombre de PC, de règles de conformité, d'anneaux de mise à jour et d'accès conditionnel faux (et contrôle « PC qui ne donnent plus de nouvelles » en erreur) dès que le tenant en avait plusieurs. 1.3.0 - licences sur comptes désactivés, réinitialisation du mot de passe en libre-service (SSPR), rôles admin permanents ou éligibles (PIM), usage de SMTP AUTH sur 30 jours, « non vérifiable » qui distingue licence et droit manquants (idées de Ludo1377 sur r/Sysadmin_Fr). 1.2.0 - licences en dépassement ou abonnements en alerte, stockage SharePoint + OneDrive utilisé (idées de ppx32). 1.1.0 - première version publique.
#>

<#
.SYNOPSIS
    Pactio · Bilan 365 (gratuit) : bilan de sécurité d'un tenant Microsoft 365, en lecture seule.

.DESCRIPTION
    Analyse un tenant Microsoft 365 et produit un rapport HTML clair (vert / orange / rouge).
    Lecture seule : rien n'est modifié dans le tenant.
        .\Bilan-365.ps1
        .\Bilan-365.ps1 -Compte admin@entreprise.fr

    Vérifie : administrateurs généraux, rôles admin permanents ou éligibles (PIM), double
    authentification (admins compris), réinitialisation du mot de passe en libre-service, paramètres
    de sécurité par défaut ou accès conditionnel, comptes inactifs, invités, usage de SMTP AUTH,
    inscription automatique dans Intune, utilisateurs administrateurs de leur PC, LAPS, chiffrement
    BitLocker, conformité et synchronisation des PC, règle de conformité, mises à jour Windows
    pilotées, licences libres, licences sur comptes désactivés, licences en dépassement ou
    abonnements en alerte, stockage SharePoint + OneDrive utilisé.

.PARAMETER Compte
    Compte administrateur du tenant (ex. admin@entreprise.fr). Sans ce paramètre, une fenêtre le demande.

.NOTES
    Pactio · Bilan 365 — v1.3.1 (gratuit)
    Prérequis : Windows 10 / 11, PowerShell 5.1. Le module Microsoft.Graph.Authentication est
                installé automatiquement pour l'utilisateur s'il manque.
    Droits    : un compte administrateur du tenant ; Microsoft demande d'accepter des droits de
                LECTURE uniquement (Directory, AuditLog, Policy, Intune en lecture, LAPS en lecture
                de base, rapports d'usage, rôles en lecture).
    Licence   : usage libre, y compris chez vos clients. Redistribution interdite.
#>
[CmdletBinding()]
param([string]$Compte)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
$Police = New-Object System.Drawing.Font("Segoe UI", 10)

# ================= Compte administrateur =================
if (-not $Compte) {
    $Fd = New-Object System.Windows.Forms.Form
    $Fd.Text = "Pactio - Bilan 365 (lecture seule)"; $Fd.Size = New-Object System.Drawing.Size(540, 240); $Fd.StartPosition = "CenterScreen"
    $Fd.Font = $Police; $Fd.FormBorderStyle = "FixedDialog"; $Fd.MaximizeBox = $false; $Fd.TopMost = $true; $Fd.BackColor = [System.Drawing.Color]::White
    $L1 = New-Object System.Windows.Forms.Label; $L1.Text = "Compte administrateur Microsoft 365 (ex : admin@entreprise.fr)"; $L1.Location = "20,20"; $L1.AutoSize = $true
    $T1 = New-Object System.Windows.Forms.TextBox; $T1.Location = "20,50"; $T1.Width = 480
    $L2 = New-Object System.Windows.Forms.Label; $L2.Text = "Lecture seule : ce bilan ne modifie rien dans votre tenant."; $L2.Location = "20,85"; $L2.AutoSize = $true; $L2.ForeColor = [System.Drawing.Color]::DarkGreen
    $L3 = New-Object System.Windows.Forms.Label; $L3.Text = "Microsoft vous demandera d'accepter des droits de lecture."; $L3.Location = "20,108"; $L3.AutoSize = $true; $L3.ForeColor = [System.Drawing.Color]::DimGray
    $B1 = New-Object System.Windows.Forms.Button; $B1.Text = "Lancer le bilan"; $B1.Location = "270,145"; $B1.Size = "140,32"; $B1.DialogResult = "OK"
    $B2 = New-Object System.Windows.Forms.Button; $B2.Text = "Annuler"; $B2.Location = "420,145"; $B2.Size = "80,32"; $B2.DialogResult = "Cancel"
    $Fd.Controls.AddRange(@($L1, $T1, $L2, $L3, $B1, $B2)); $Fd.AcceptButton = $B1; $Fd.CancelButton = $B2
    if ($Fd.ShowDialog() -ne "OK" -or -not $T1.Text.Trim()) { Write-Host "Annulé." -ForegroundColor Red; return }
    $Compte = $T1.Text.Trim()
}
if ($Compte -notmatch "^[^@\s]+@[^@\s]+\.[^@\s]+$") { Write-Host "Adresse invalide : $Compte" -ForegroundColor Red; return }
$Domaine = ($Compte -split "@")[-1]

# ================= Connexion (lecture seule) =================
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    Write-Host "Installation du module Microsoft.Graph.Authentication (une seule fois)..." -ForegroundColor Yellow
    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber
}
Import-Module Microsoft.Graph.Authentication
$Droits = @("Directory.Read.All", "AuditLog.Read.All", "Policy.Read.All", "Policy.Read.DeviceConfiguration",
            "DeviceManagementManagedDevices.Read.All", "DeviceManagementConfiguration.Read.All", "DeviceLocalCredential.ReadBasic.All",
            "Reports.Read.All", "RoleManagement.Read.Directory")
Write-Host "Connexion : choisissez le compte $Compte (la fenêtre Microsoft peut être cachée : Alt+Tab)." -ForegroundColor Cyan
Connect-MgGraph -TenantId $Domaine -Scopes $Droits -NoWelcome
$Ctx = Get-MgContext
if ($Ctx.Account -ne $Compte) {
    [void][System.Windows.Forms.MessageBox]::Show("Vous êtes connecté avec $($Ctx.Account) au lieu de $Compte.`r`nRelancez et choisissez le bon compte.", "Mauvais compte", "OK", "Error")
    & { $WarningPreference = "SilentlyContinue"; Disconnect-MgGraph -ErrorAction SilentlyContinue 3>$null | Out-Null }; return
}

$G1 = "https://graph.microsoft.com/v1.0"; $GB = "https://graph.microsoft.com/beta"
function Lire([string]$Uri) { Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType Hashtable }
function Lire-Tout([string]$Uri, [int]$MaxPages = 0) {
    $Res = New-Object System.Collections.Generic.List[object]; $P = 0
    while ($Uri) {
        $R = Lire $Uri; foreach ($V in $R.value) { $Res.Add($V) }; $Uri = $R.'@odata.nextLink'
        $P++; if ($MaxPages -and $P -ge $MaxPages) { break }
    }
    return , $Res.ToArray()
}

# ================= Résultats =================
$Res = New-Object System.Collections.Generic.List[object]
function Ajouter([string]$Theme, [string]$Controle, [string]$Etat, [string]$Constat, [string]$Conseil = "", [string[]]$Detail = @()) {
    $Res.Add([pscustomobject]@{ Theme = $Theme; Controle = $Controle; Etat = $Etat; Constat = $Constat; Conseil = $Conseil; Detail = $Detail })
    $Coul = @{ OK = "Green"; ORANGE = "Yellow"; ROUGE = "Red"; GRIS = "DarkGray" }[$Etat]
    Write-Host ("  [{0,-6}] {1} : {2}" -f $Etat, $Controle, $Constat) -ForegroundColor $Coul
}
# « Non vérifiable » : on dit si c'est une LICENCE Microsoft qui manque au tenant, ou un DROIT qui manque au compte.
function Raison($Err) {
    $M = "$($Err.Exception.Message) $($Err.ErrorDetails.Message)"
    if ($M -match "NonPremium|PremiumLicense|Premium|licen|SKU|\bP1\b|\bP2\b|not licensed|subscription") {
        return "non vérifiable : licence manquante dans le tenant (fonction réservée à une licence Microsoft supérieure, ex. Entra ID P1/P2)"
    }
    if ($M -match "Authorization_RequestDenied|Insufficient privileges|Forbidden|\b403\b|\b401\b|Unauthorized|AccessDenied|Access is denied|scope|consent") {
        return "non vérifiable : droit manquant (le compte n'a pas le rôle admin nécessaire, ou l'accord de lecture n'a pas été donné)"
    }
    return "non vérifiable ($($M.Trim().Split("`n")[0]))"
}
$Il_y_a90 = (Get-Date).AddDays(-90)

Write-Host ""
Write-Host "=== Bilan 365 - $Domaine ===" -ForegroundColor Cyan
$Org = $null; try { $Org = (Lire "$G1/organization?`$select=displayName").value[0] } catch { }
$NomOrg = if ($Org) { $Org.displayName } else { $Domaine }

# Lectures partagées par plusieurs contrôles (une erreur ici est traitée dans chaque contrôle)
$Skus = $null; try { $Skus = Lire-Tout "$G1/subscribedSkus?`$select=skuId,skuPartNumber,prepaidUnits,consumedUnits,capabilityStatus,servicePlans" } catch { $ErrSkus = $_ }
$NomsSku = @{ SPB = "Microsoft 365 Business Premium"; O365_BUSINESS_PREMIUM = "Microsoft 365 Business Standard"; O365_BUSINESS_ESSENTIALS = "Microsoft 365 Business Basic"
    O365_BUSINESS = "Microsoft 365 Apps for business"; SMB_BUSINESS = "Microsoft 365 Apps for business"; ENTERPRISEPACK = "Office 365 E3"; STANDARDPACK = "Office 365 E1"
    SPE_E3 = "Microsoft 365 E3"; SPE_E5 = "Microsoft 365 E5"; EXCHANGESTANDARD = "Exchange Online (Plan 1)"; EXCHANGEENTERPRISE = "Exchange Online (Plan 2)"
    INTUNE_A = "Microsoft Intune Plan 1"; AAD_PREMIUM = "Microsoft Entra ID P1"; AAD_PREMIUM_P2 = "Microsoft Entra ID P2"; Microsoft_365_Business_Premium_Donation_Non_Profit = "Business Premium (associations)" }
function NomLicence([string]$P) { if ($NomsSku.ContainsKey($P)) { $NomsSku[$P] } else { $P } }
# Licence Entra ID P1/P2 présente ? (lue dans les abonnements, sans se fier au texte des erreurs Microsoft)
$AvecP1 = $null
if ($Skus) {
    $AvecP1 = @($Skus | Where-Object { $_.capabilityStatus -eq "Enabled" -and [int]$_.prepaidUnits.enabled -gt 0 } | ForEach-Object { $_.servicePlans } |
        Where-Object { $_.servicePlanName -match "^AAD_PREMIUM(_P2)?$" -and $_.provisioningStatus -ne "Disabled" }).Count -gt 0
}

# ---- 1. Administrateurs généraux
$Adm = @()
try {
    $Adm = Lire-Tout "$G1/directoryRoles(roleTemplateId='62e90394-69f5-4237-9190-012177145e10')/members?`$select=id,displayName,userPrincipalName"
    $N = $Adm.Count; $Noms = @($Adm | ForEach-Object { "$($_.displayName) ($($_.userPrincipalName))" })
    if ($N -eq 0) { Ajouter "Comptes" "Administrateurs généraux" "ROUGE" "aucun administrateur général actif trouvé" "Vérifier les rôles dans Entra (si PIM est utilisé, voir le contrôle « Rôles admin permanents »)." }
    elseif ($N -eq 1) { Ajouter "Comptes" "Administrateurs généraux" "ORANGE" "1 seul administrateur général" "Prévoir un 2e compte admin de secours, sinon personne ne peut réparer si ce compte est bloqué." $Noms }
    elseif ($N -le 4) { Ajouter "Comptes" "Administrateurs généraux" "OK" "$N administrateurs généraux" "" $Noms }
    else { Ajouter "Comptes" "Administrateurs généraux" "ORANGE" "$N administrateurs généraux (trop)" "Microsoft conseille moins de 5 : chaque compte admin est une porte d'entrée." $Noms }
} catch { Ajouter "Comptes" "Administrateurs généraux" "GRIS" (Raison $_) }

# ---- 1b. Rôles admin permanents ou éligibles (PIM)
try {
    if (-not $Skus) { throw $ErrSkus }
    $AvecP2 = @($Skus | Where-Object { $_.capabilityStatus -eq "Enabled" } | ForEach-Object { $_.servicePlans } |
        Where-Object { $_.servicePlanName -match "^AAD_PREMIUM_P2$|IDENTITY_GOVERNANCE" }).Count -gt 0
    if (-not $AvecP2) {
        Ajouter "Comptes" "Rôles admin permanents ou éligibles (PIM)" "GRIS" "non vérifiable : licence manquante dans le tenant (PIM demande Entra ID P2 ou ID Governance) ; tous les rôles admin sont donc permanents" "Sans PIM, garder peu d'administrateurs généraux et des comptes admin séparés des comptes de tous les jours."
    } else {
        $GA = "62e90394-69f5-4237-9190-012177145e10"
        $ActifsPim = Lire-Tout "$G1/roleManagement/directory/roleAssignmentScheduleInstances?`$filter=roleDefinitionId eq '$GA'"
        $Elig = Lire-Tout "$G1/roleManagement/directory/roleEligibilityScheduleInstances?`$filter=roleDefinitionId eq '$GA'"
        $Perm = @($ActifsPim | Where-Object { $_.assignmentType -eq "Assigned" -and -not $_.endDateTime })
        $Noms = @{}; foreach ($A in $Adm) { if ($A.id) { $Noms[$A.id] = $A.userPrincipalName } }
        function NomPrincipal($Id) {
            if ($Noms.ContainsKey($Id)) { return $Noms[$Id] }
            try { $O = Lire "$G1/directoryObjects/$Id`?`$select=displayName,userPrincipalName"; if ($O.userPrincipalName) { return $O.userPrincipalName } else { return "$($O.displayName) (groupe ou application)" } } catch { return $Id }
        }
        $Det = @($Perm | ForEach-Object { "$(NomPrincipal $_.principalId) : permanent" }) + @($Elig | ForEach-Object { "$(NomPrincipal $_.principalId) : éligible (activation à la demande)" })
        if ($Perm.Count -gt 2) { Ajouter "Comptes" "Rôles admin permanents ou éligibles (PIM)" "ORANGE" "$($Perm.Count) administrateurs généraux permanents, $($Elig.Count) éligible(s)" "PIM est disponible : ne garder en permanent que 1 ou 2 comptes de secours, les autres en éligible (activation limitée dans le temps)." $Det }
        elseif ($Elig.Count -eq 0 -and $Perm.Count -gt 1) { Ajouter "Comptes" "Rôles admin permanents ou éligibles (PIM)" "ORANGE" "PIM disponible mais pas utilisé ($($Perm.Count) administrateurs généraux permanents)" "Passer les comptes admin du quotidien en éligible, garder 1 compte de secours permanent." $Det }
        else { Ajouter "Comptes" "Rôles admin permanents ou éligibles (PIM)" "OK" "$($Perm.Count) permanent(s), $($Elig.Count) éligible(s)" "" $Det }
    }
} catch { Ajouter "Comptes" "Rôles admin permanents ou éligibles (PIM)" "GRIS" (Raison $_) }

# ---- 2. Double authentification
$Reg = $null
try {
    $Reg = Lire-Tout "$G1/reports/authenticationMethods/userRegistrationDetails?`$select=id,userPrincipalName,isMfaRegistered,isAdmin,userType,isSsprEnabled,isSsprRegistered"
    $Membres = @($Reg | Where-Object { $_.userType -ne "guest" })
    $Sans = @($Membres | Where-Object { -not $_.isMfaRegistered })
    $AdmSans = @($Sans | Where-Object { $_.isAdmin })
    if ($Membres.Count -eq 0) { Ajouter "Comptes" "Double authentification" "GRIS" "aucun utilisateur trouvé" }
    elseif ($AdmSans.Count) { Ajouter "Comptes" "Double authentification" "ROUGE" ("{0} admin(s) sans double authentification, {1}/{2} utilisateurs sans" -f $AdmSans.Count, $Sans.Count, $Membres.Count) "Un compte admin sans double authentification, c'est la cible n°1 des pirates : à corriger tout de suite." @($Sans | ForEach-Object { $_.userPrincipalName + $(if ($_.isAdmin) { " (ADMIN)" } else { "" }) }) }
    elseif ($Sans.Count) { Ajouter "Comptes" "Double authentification" "ORANGE" ("{0}/{1} utilisateurs sans double authentification" -f $Sans.Count, $Membres.Count) "Faire enregistrer Microsoft Authenticator à chaque utilisateur." @($Sans | ForEach-Object { $_.userPrincipalName }) }
    else { Ajouter "Comptes" "Double authentification" "OK" ("tous les utilisateurs ({0}) l'ont enregistrée" -f $Membres.Count) }
} catch { Ajouter "Comptes" "Double authentification" "GRIS" (Raison $_) }

# ---- 3. Paramètres de sécurité par défaut / accès conditionnel
try {
    $SD = Lire "$G1/policies/identitySecurityDefaultsEnforcementPolicy"
    $CA = @(); try { $CA = @((Lire-Tout "$G1/identity/conditionalAccess/policies?`$select=displayName,state") | Where-Object { $_.state -eq "enabled" }) } catch { }
    if ($SD.isEnabled) { Ajouter "Comptes" "Protection des connexions" "OK" "paramètres de sécurité par défaut activés" }
    elseif ($CA.Count) { Ajouter "Comptes" "Protection des connexions" "OK" "$($CA.Count) règle(s) d'accès conditionnel active(s)" "" @($CA | ForEach-Object { $_.displayName }) }
    else { Ajouter "Comptes" "Protection des connexions" "ROUGE" "ni paramètres de sécurité par défaut, ni accès conditionnel" "Rien n'oblige la double authentification à la connexion : activer au minimum les paramètres de sécurité par défaut." }
} catch { Ajouter "Comptes" "Protection des connexions" "GRIS" (Raison $_) }

# ---- 4. Comptes inactifs
$Us = $null
try {
    try { $Us = Lire-Tout "$G1/users?`$select=id,displayName,userPrincipalName,accountEnabled,userType,assignedLicenses,createdDateTime,signInActivity" ; $AvecConnexion = $true }
    catch { $ErrConnexion = $_; $Us = Lire-Tout "$G1/users?`$select=id,displayName,userPrincipalName,accountEnabled,userType,assignedLicenses,createdDateTime"; $AvecConnexion = $false }
    $Actifs = @($Us | Where-Object { $_.accountEnabled -and $_.userType -ne "Guest" })
    $Invites = @($Us | Where-Object { $_.userType -eq "Guest" })
    if (-not $AvecConnexion) { Ajouter "Comptes" "Comptes inactifs" "GRIS" ("date de dernière connexion " + (Raison $ErrConnexion)) }
    else {
        $Inactifs = @()
        foreach ($U in $Actifs) {
            if ($U.createdDateTime -and ([datetime]$U.createdDateTime -gt $Il_y_a90)) { continue }   # compte récent : pas encore jugeable
            $Dates = @($U.signInActivity.lastSignInDateTime, $U.signInActivity.lastNonInteractiveSignInDateTime) | Where-Object { $_ } | ForEach-Object { [datetime]$_ }
            $Der = $Dates | Sort-Object -Descending | Select-Object -First 1
            if (-not $Der) { $Inactifs += "$($U.userPrincipalName) : jamais connecté" + $(if ($U.assignedLicenses.Count) { " (licence payée)" } else { "" }) }
            elseif ($Der -lt $Il_y_a90) { $Inactifs += "$($U.userPrincipalName) : dernière connexion le $($Der.ToString('dd/MM/yyyy'))" + $(if ($U.assignedLicenses.Count) { " (licence payée)" } else { "" }) }
        }
        if ($Inactifs.Count) { Ajouter "Comptes" "Comptes inactifs" "ORANGE" "$($Inactifs.Count) compte(s) actif(s) sans connexion depuis plus de 90 jours" "Bloquer les comptes des personnes parties : un compte oublié est une porte ouverte (et souvent une licence payée pour rien)." $Inactifs }
        else { Ajouter "Comptes" "Comptes inactifs" "OK" "aucun compte de plus de 90 jours resté sans connexion" }
    }
    if ($Invites.Count) { Ajouter "Comptes" "Invités externes" "ORANGE" "$($Invites.Count) invité(s) externe(s)" "Vérifier qu'ils ont encore besoin d'accès." @($Invites | ForEach-Object { $_.userPrincipalName }) }
    else { Ajouter "Comptes" "Invités externes" "OK" "aucun invité externe" }
} catch { Ajouter "Comptes" "Comptes inactifs" "GRIS" (Raison $_) }

# ---- 4b. Réinitialisation du mot de passe en libre-service (SSPR)
try {
    if (-not $Reg) { $Reg = Lire-Tout "$G1/reports/authenticationMethods/userRegistrationDetails?`$select=id,userPrincipalName,isAdmin,userType,isSsprEnabled,isSsprRegistered" }
    $Cibles = @($Reg | Where-Object { $_.userType -ne "guest" })
    if ($Us) { $IdsActifs = @{}; foreach ($U in $Us) { if ($U.accountEnabled -and $U.userType -ne "Guest") { $IdsActifs[$U.id] = 1 } }; $Cibles = @($Cibles | Where-Object { $IdsActifs.ContainsKey($_.id) }) }
    $AdminsSspr = $null; try { $AdminsSspr = (Lire "$G1/policies/authorizationPolicy").allowedToUseSSPR } catch { }
    $LigneAdm = switch ($AdminsSspr) { $true { "Administrateurs : réinitialisation en libre-service autorisée (réglage Microsoft par défaut)" } $false { "Administrateurs : réinitialisation en libre-service interdite" } default { "Administrateurs : réglage non lisible" } }
    $Ouverts = @($Cibles | Where-Object { $_.isSsprEnabled })
    $NonEnr = @($Ouverts | Where-Object { -not $_.isSsprRegistered })
    if ($Cibles.Count -eq 0) { Ajouter "Comptes" "Mot de passe oublié (libre-service)" "GRIS" "aucun utilisateur trouvé" }
    elseif ($Ouverts.Count -eq 0) { Ajouter "Comptes" "Mot de passe oublié (libre-service)" "ORANGE" "désactivé pour les utilisateurs" "Chaque mot de passe oublié passe par l'administrateur. Si on l'active : exiger 2 méthodes de vérification." @($LigneAdm) }
    elseif ($NonEnr.Count) { Ajouter "Comptes" "Mot de passe oublié (libre-service)" "ORANGE" ("activé pour {0}/{1} utilisateurs, dont {2} sans méthode enregistrée" -f $Ouverts.Count, $Cibles.Count, $NonEnr.Count) "Ces utilisateurs ne pourront pas réinitialiser seuls : leur faire enregistrer une méthode (Authenticator ou téléphone)." (@($LigneAdm) + @($NonEnr | ForEach-Object { "$($_.userPrincipalName) : aucune méthode enregistrée" + $(if ($_.isAdmin) { " (ADMIN)" } else { "" }) })) }
    else { Ajouter "Comptes" "Mot de passe oublié (libre-service)" "OK" ("activé et prêt pour {0}/{1} utilisateurs" -f $Ouverts.Count, $Cibles.Count) "" @($LigneAdm) }
} catch { Ajouter "Comptes" "Mot de passe oublié (libre-service)" "GRIS" (Raison $_) }

# ---- 4c. SMTP AUTH réellement utilisé (journal des connexions)
# Conservation Microsoft du journal des connexions : 30 jours avec Entra ID P1/P2, 7 jours sans.
$NomSmtp = "SMTP AUTH (envoi par identifiant et mot de passe)"
try {
    $Jours = if ($AvecP1 -eq $true) { 30 } else { 7 }
    $Debut = (Get-Date).AddDays(-$Jours)
    $Periode = "période analysée : du $($Debut.ToString('dd/MM/yyyy')) au $((Get-Date).ToString('dd/MM/yyyy')), soit $Jours jours"
    $Depuis = $Debut.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $Smtp = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($Client in @("Authenticated SMTP", "SMTP")) {
            $F = [uri]::EscapeDataString("clientAppUsed eq '$Client' and createdDateTime ge $Depuis")
            foreach ($S in (Lire-Tout "$G1/auditLogs/signIns?`$filter=$F&`$top=500&`$select=userPrincipalName,userDisplayName,createdDateTime,status,ipAddress" 10)) { $Smtp.Add($S) }
        }
    } catch {
        if ($AvecP1 -eq $false) { throw "licence : pas d'Entra ID P1/P2 dans le tenant, Microsoft ne donne pas accès au journal des connexions (et ne le garde que 7 jours)" }
        throw
    }
    # Comptes qui ressemblent à un copieur, un scanner ou une application (scan vers mail, alertes...)
    $Machine = "scan|copieur|copy|photocop|imprim|print|mfp|multifonction|noreply|no-reply|ne-pas-repondre|smtp|relay|alerte|alert|notif|canon|ricoh|konica|kyocera|xerox|sharp|brother|lexmark|toshiba|epson"
    $ParCompte = @(); $Copieurs = 0
    foreach ($G in @($Smtp | Where-Object { [int]$_.status.errorCode -eq 0 } | Group-Object userPrincipalName | Sort-Object Count -Descending)) {
        $Der = ($G.Group | ForEach-Object { [datetime]$_.createdDateTime } | Sort-Object -Descending | Select-Object -First 1).ToString('dd/MM/yyyy')
        $Ips = @($G.Group | ForEach-Object { $_.ipAddress } | Where-Object { $_ } | Select-Object -Unique)
        $TexteIp = if ($Ips.Count -le 3) { $Ips -join ", " } else { "$(($Ips | Select-Object -First 3) -join ', ') et $($Ips.Count - 3) autre(s)" }
        $EstMachine = ("$($G.Name) $($G.Group[0].userDisplayName)" -match $Machine)
        if ($EstMachine) { $Copieurs++ }
        $ParCompte += "$($G.Name) : $($G.Count) envoi(s) réussi(s), dernier le $Der, depuis $TexteIp" + $(if ($EstMachine) { " → probablement un copieur, un scanner ou une application" } else { "" })
    }
    $Ko = @($Smtp | Where-Object { [int]$_.status.errorCode -ne 0 })
    $Echecs = @($Ko | Group-Object userPrincipalName | Sort-Object Count -Descending | Select-Object -First 15 | ForEach-Object {
        "$($_.Name) : $($_.Count) tentative(s) refusée(s) depuis $(@($_.Group | ForEach-Object { $_.ipAddress } | Select-Object -Unique).Count) adresse(s) IP" })
    $Avant = "Avant toute coupure : repérer le copieur (scan vers mail) et les logiciels qui envoient des mails, souvent avec un compte que plus personne ne connaît. C'est le premier truc qui casse. Le réglage SMTP AUTH lui-même (par boîte ou pour le tenant) ne se lit qu'avec le module Exchange Online, pas en lecture seule Graph."
    if ($ParCompte.Count) {
        $Txt = "$($ParCompte.Count) compte(s) l'utilisent" + $(if ($Copieurs) { ", dont $Copieurs qui ressemble(nt) à un copieur, un scanner ou une application" } else { "" }) + " ($Periode)"
        Ajouter "Comptes" $NomSmtp "ORANGE" $Txt "Ce protocole ne passe pas par la double authentification : le garder seulement sur ces comptes (mot de passe long, accès conditionnel), ou mieux, basculer le copieur sur un connecteur d'envoi, puis le couper ailleurs. $Avant" (@($ParCompte) + @($Echecs))
    }
    elseif ($Ko.Count) { Ajouter "Comptes" $NomSmtp "ORANGE" "aucun envoi réussi, mais $($Ko.Count) tentative(s) refusée(s) ($Periode)" "Des robots testent des mots de passe par ce biais. $(if ($Jours -lt 30) { 'Sur 7 jours seulement, on ne peut pas conclure que personne ne s''en sert.' } else { 'Personne ne s''en sert sur 30 jours : il peut sans doute être désactivé pour tout le tenant.' }) $Avant" $Echecs }
    elseif ($Jours -lt 30) { Ajouter "Comptes" $NomSmtp "GRIS" "non concluant : aucune connexion SMTP AUTH vue, mais seulement 7 jours de journal ($Periode, pas de licence Entra ID P1/P2)" "Un copieur qui scanne une fois par mois n'apparaît pas forcément : ne pas couper SMTP AUTH sur ce seul résultat. $Avant" }
    else { Ajouter "Comptes" $NomSmtp "OK" "aucune connexion SMTP AUTH ($Periode)" "Il peut sans doute être désactivé pour tout le tenant. $Avant" }
} catch {
    if ("$($_.Exception.Message)" -like "licence : *") { Ajouter "Comptes" $NomSmtp "GRIS" ("non vérifiable : " + "$($_.Exception.Message)".Substring(10)) "Sans journal des connexions, impossible de savoir qui utilise SMTP AUTH : ne pas le couper à l'aveugle (copieur, logiciels métier)." }
    else { Ajouter "Comptes" $NomSmtp "GRIS" (Raison $_) }
}

# ---- 5. Inscription automatique Intune
try {
    $MDM = Lire "$GB/policies/mobileDeviceManagementPolicies/0000000a-0000-0000-c000-000000000000"
    switch ($MDM.appliesTo) {
        "all"      { Ajouter "Postes" "Inscription automatique dans Intune" "OK" "activée pour tous les utilisateurs" }
        "selected" { Ajouter "Postes" "Inscription automatique dans Intune" "ORANGE" "activée pour certains utilisateurs seulement" "Vérifier que tous les utilisateurs de PC sont dans le groupe choisi." }
        default    { Ajouter "Postes" "Inscription automatique dans Intune" "ROUGE" "désactivée" "Les PC joints à Microsoft 365 ne sont pas gérés : aucun réglage de sécurité ne peut leur être appliqué." }
    }
} catch { Ajouter "Postes" "Inscription automatique dans Intune" "GRIS" (Raison $_) }

# ---- 6. Droits admin à la jonction + LAPS activé
try {
    $DRP = Lire "$GB/policies/deviceRegistrationPolicy"
    $Type = "$($DRP.azureADJoin.localAdmins.registeringUsers.'@odata.type')"
    if ($Type -match "noDeviceRegistrationMembership") { Ajouter "Postes" "Utilisateurs administrateurs de leur PC" "OK" "l'utilisateur qui joint un PC n'en devient pas administrateur" }
    else { Ajouter "Postes" "Utilisateurs administrateurs de leur PC" "ROUGE" "l'utilisateur qui joint un PC en devient administrateur" "Un utilisateur admin installe n'importe quoi, virus compris : passer ce réglage à « Aucun » dans Entra." }
    if ($DRP.localAdminPassword.isEnabled) { Ajouter "Postes" "LAPS activé dans Entra" "OK" "oui" }
    else { Ajouter "Postes" "LAPS activé dans Entra" "ROUGE" "non" "Sans LAPS, le mot de passe admin local est souvent le même partout : un PC piraté = tous les PC." }
} catch { Ajouter "Postes" "Réglages de jonction des PC" "GRIS" (Raison $_) }

# ---- 7. PC gérés : chiffrement, conformité, synchro, LAPS par PC
try {
    $PCs = @((Lire-Tout "$G1/deviceManagement/managedDevices?`$select=deviceName,operatingSystem,complianceState,isEncrypted,lastSyncDateTime,userPrincipalName,azureADDeviceId") | Where-Object { $_.operatingSystem -eq "Windows" })
    if ($PCs.Count -eq 0) { Ajouter "Postes" "PC Windows gérés par Intune" "ROUGE" "aucun PC Windows géré" "Les PC ne sont pas dans Intune : aucune règle de sécurité ne s'applique." }
    else {
        Ajouter "Postes" "PC Windows gérés par Intune" "OK" "$($PCs.Count) PC"
        $NonChiffres = @($PCs | Where-Object { -not $_.isEncrypted })
        if ($NonChiffres.Count) { Ajouter "Postes" "Chiffrement BitLocker" "ROUGE" "$($NonChiffres.Count)/$($PCs.Count) PC non chiffré(s)" "Un portable volé non chiffré = toutes les données lisibles." @($NonChiffres | ForEach-Object { $_.deviceName }) }
        else { Ajouter "Postes" "Chiffrement BitLocker" "OK" "tous les PC sont chiffrés" }
        $NonConf = @($PCs | Where-Object { $_.complianceState -ne "compliant" })
        if ($NonConf.Count) { Ajouter "Postes" "Conformité des PC" "ORANGE" "$($NonConf.Count)/$($PCs.Count) PC non conforme(s)" "Voir dans Intune ce qui manque sur ces PC." @($NonConf | ForEach-Object { "$($_.deviceName) ($($_.complianceState))" }) }
        else { Ajouter "Postes" "Conformité des PC" "OK" "tous les PC sont conformes" }
        $Muets = @($PCs | Where-Object { $_.lastSyncDateTime -and ([datetime]$_.lastSyncDateTime -lt (Get-Date).AddDays(-30)) })
        if ($Muets.Count) { Ajouter "Postes" "PC qui ne donnent plus de nouvelles" "ORANGE" "$($Muets.Count) PC sans synchronisation depuis 30 jours" "PC perdu, éteint ou cassé ? Il ne reçoit plus les mises à jour de sécurité." @($Muets | ForEach-Object { "$($_.deviceName) (dernier contact $(([datetime]$_.lastSyncDateTime).ToString('dd/MM/yyyy')))" }) }
        else { Ajouter "Postes" "PC qui ne donnent plus de nouvelles" "OK" "tous les PC se sont synchronisés dans les 30 derniers jours" }
        try {
            $Laps = @(Lire-Tout "$G1/directory/deviceLocalCredentials?`$select=deviceName,lastBackupDateTime")
            $AvecLaps = @($Laps | ForEach-Object { $_.deviceName })
            $SansLaps = @($PCs | Where-Object { $AvecLaps -notcontains $_.deviceName })
            if ($SansLaps.Count) { Ajouter "Postes" "Mot de passe admin local (LAPS) sauvegardé" "ROUGE" "$($SansLaps.Count)/$($PCs.Count) PC sans mot de passe LAPS dans Entra" "Créer une stratégie Windows LAPS dans Intune. Pour un PC joint à un domaine Active Directory, le mot de passe peut être sauvegardé dans l'AD local plutôt que dans Entra : le vérifier là-bas avant de conclure." @($SansLaps | ForEach-Object { $_.deviceName }) }
            else { Ajouter "Postes" "Mot de passe admin local (LAPS) sauvegardé" "OK" "tous les PC" }
        } catch { Ajouter "Postes" "Mot de passe admin local (LAPS) sauvegardé" "GRIS" (Raison $_) }
    }
} catch { Ajouter "Postes" "PC Windows gérés par Intune" "GRIS" (Raison $_) }

# ---- 8. Règles de conformité et mises à jour
try {
    $Comp = @((Lire-Tout "$GB/deviceManagement/deviceCompliancePolicies?`$select=displayName") | Where-Object { $_.'@odata.type' -match "windows10CompliancePolicy" })
    if ($Comp.Count) { Ajouter "Postes" "Règle de conformité Windows" "OK" "$($Comp.Count) règle(s)" "" @($Comp | ForEach-Object { $_.displayName }) }
    else { Ajouter "Postes" "Règle de conformité Windows" "ORANGE" "aucune" "Sans règle, Intune ne sait pas dire si un PC est à risque (non chiffré, sans antivirus...)." }
} catch { Ajouter "Postes" "Règle de conformité Windows" "GRIS" (Raison $_) }
try {
    $WU = @((Lire-Tout "$GB/deviceManagement/deviceConfigurations?`$select=displayName") | Where-Object { $_.'@odata.type' -match "windowsUpdateForBusinessConfiguration" })
    if ($WU.Count) { Ajouter "Postes" "Mises à jour Windows pilotées" "OK" "$($WU.Count) anneau(x) de mise à jour" "" @($WU | ForEach-Object { $_.displayName }) }
    else { Ajouter "Postes" "Mises à jour Windows pilotées" "ORANGE" "aucun anneau de mise à jour" "Chaque PC fait comme il veut : certains peuvent rester des mois sans correctif." }
} catch { Ajouter "Postes" "Mises à jour Windows pilotées" "GRIS" (Raison $_) }

# ---- 9. Licences inutilisées
try {
    if (-not $Skus) { throw $ErrSkus }
    $Libres = @($Skus | Where-Object { $_.capabilityStatus -eq "Enabled" -and ($_.prepaidUnits.enabled - $_.consumedUnits) -gt 0 -and $_.prepaidUnits.enabled -lt 10000 })
    $TotLibres = 0; foreach ($S in $Libres) { $TotLibres += ($S.prepaidUnits.enabled - $S.consumedUnits) }
    if ($Libres.Count) { Ajouter "Licences" "Licences payées non attribuées" "ORANGE" "$TotLibres licence(s) libre(s)" "Des licences payées chaque mois sans utilisateur : à réduire si personne n'arrive." @($Libres | ForEach-Object { "{0} : {1} libre(s) sur {2}" -f (NomLicence $_.skuPartNumber), ($_.prepaidUnits.enabled - $_.consumedUnits), $_.prepaidUnits.enabled }) }
    else { Ajouter "Licences" "Licences payées non attribuées" "OK" "aucune licence libre" }
} catch { Ajouter "Licences" "Licences payées non attribuées" "GRIS" (Raison $_) }

# ---- 9b. Licences attribuées à des comptes désactivés
try {
    if (-not $Us) { $Us = Lire-Tout "$G1/users?`$select=id,userPrincipalName,accountEnabled,userType,assignedLicenses" }
    $NomParId = @{}; if ($Skus) { foreach ($S in $Skus) { $NomParId["$($S.skuId)"] = NomLicence $S.skuPartNumber } }
    $Bloques = @($Us | Where-Object { -not $_.accountEnabled -and $_.assignedLicenses.Count })
    $NbLic = 0; foreach ($U in $Bloques) { $NbLic += $U.assignedLicenses.Count }
    if ($Bloques.Count) {
        Ajouter "Licences" "Licences sur comptes désactivés" "ORANGE" "$($Bloques.Count) compte(s) désactivé(s) gardent $NbLic licence(s)" "Licences payées pour des comptes bloqués : les retirer (sauf besoin voulu, ex. boîte partagée de plus de 50 Go ou archivage)." @($Bloques | ForEach-Object {
            $L = @($_.assignedLicenses | ForEach-Object { if ($NomParId.ContainsKey("$($_.skuId)")) { $NomParId["$($_.skuId)"] } else { "$($_.skuId)" } }) -join ", "
            "$($_.userPrincipalName) : $L" })
    } else { Ajouter "Licences" "Licences sur comptes désactivés" "OK" "aucun compte désactivé ne garde de licence" }
} catch { Ajouter "Licences" "Licences sur comptes désactivés" "GRIS" (Raison $_) }

# ---- 10. Licences en dépassement / abonnements en alerte
try {
    if (-not $Skus) { throw $ErrSkus }
    $Pb = @()
    foreach ($S in $Skus) {
        $Nom = NomLicence $S.skuPartNumber
        $Ach = [int]$S.prepaidUnits.enabled; $Uti = [int]$S.consumedUnits
        $Av = [int]$S.prepaidUnits.warning; $Su = [int]$S.prepaidUnits.suspended
        if ($Uti -gt ($Ach + $Av + $Su) -and ($Ach + $Av + $Su) -gt 0) { $Pb += "$Nom : $Uti attribuée(s) pour $($Ach + $Av + $Su) achetée(s) (dépassement de $($Uti - $Ach - $Av - $Su))" }
        if ($Av -gt 0) { $Pb += "$Nom : $Av licence(s) en période de grâce (abonnement expiré ou non renouvelé)" }
        if ($Su -gt 0) { $Pb += "$Nom : $Su licence(s) suspendue(s) (bientôt supprimées)" }
    }
    if ($Pb.Count) { Ajouter "Licences" "Licences en dépassement ou en alerte" "ROUGE" "$($Pb.Count) problème(s) de licences" "Des utilisateurs risquent de perdre l'accès à leur messagerie ou à leurs fichiers : vérifier la facturation dans le centre d'administration." $Pb }
    else { Ajouter "Licences" "Licences en dépassement ou en alerte" "OK" "aucun dépassement, aucun abonnement en alerte" }
} catch { Ajouter "Licences" "Licences en dépassement ou en alerte" "GRIS" (Raison $_) }

# ---- 11. Stockage SharePoint + OneDrive utilisé
function Taille([double]$O) { if ($O -ge 1TB) { "{0:N2} To" -f ($O / 1TB) } elseif ($O -ge 1GB) { "{0:N1} Go" -f ($O / 1GB) } else { "{0:N0} Mo" -f ($O / 1MB) } }
function Dernier-Stockage([string]$Rapport) {
    $R = Lire "$GB/reports/$Rapport(period='D7')?`$format=application/json"
    $L = @($R.value | Where-Object { $_.storageUsedInBytes -ne $null } | Sort-Object { [datetime]$_.reportDate } -Descending)
    if (-not $L.Count) { return $null }
    return $L[0]
}
try {
    $SP = Dernier-Stockage "getSharePointSiteUsageStorage"; $OD = Dernier-Stockage "getOneDriveUsageStorage"
    if (-not $SP -and -not $OD) { Ajouter "Stockage" "Stockage SharePoint + OneDrive" "GRIS" "aucune donnée de stockage (tenant récent : Microsoft met 2 à 3 jours à les produire)" }
    else {
        $OSP = if ($SP) { [double]$SP.storageUsedInBytes } else { 0 }; $OOD = if ($OD) { [double]$OD.storageUsedInBytes } else { 0 }
        $Date = if ($SP) { ([datetime]$SP.reportDate).ToString('dd/MM/yyyy') } else { ([datetime]$OD.reportDate).ToString('dd/MM/yyyy') }
        Ajouter "Stockage" "Stockage SharePoint + OneDrive" "OK" ("{0} utilisés au total (relevé Microsoft du {1})" -f (Taille ($OSP + $OOD)), $Date) "Le quota du tenant n'est pas lisible en lecture seule : le comparer dans le centre d'administration SharePoint > Stockage." @("SharePoint (sites et Teams) : $(Taille $OSP)", "OneDrive (tous les utilisateurs) : $(Taille $OOD)")
    }
} catch { Ajouter "Stockage" "Stockage SharePoint + OneDrive" "GRIS" (Raison $_) }

try { & { $WarningPreference = "SilentlyContinue"; Disconnect-MgGraph -ErrorAction SilentlyContinue 3>$null | Out-Null } } catch { }

# ================= Rapport HTML =================
function E([string]$T) { [System.Net.WebUtility]::HtmlEncode($T) }
$NbOK = @($Res | Where-Object Etat -eq "OK").Count; $NbOr = @($Res | Where-Object Etat -eq "ORANGE").Count
$NbRo = @($Res | Where-Object Etat -eq "ROUGE").Count; $NbGr = @($Res | Where-Object Etat -eq "GRIS").Count
$Verdict = if ($NbRo) { "Des risques importants sont à corriger." } elseif ($NbOr) { "Bonne base, quelques points à améliorer." } else { "Très bonne configuration." }
$Lignes = ""
foreach ($Theme in @("Comptes", "Postes", "Licences", "Stockage")) {
    $Lignes += "<h2>$(E $Theme)</h2>"
    foreach ($R in @($Res | Where-Object Theme -eq $Theme)) {
        $Lib = @{ OK = "OK"; ORANGE = "À améliorer"; ROUGE = "Risque"; GRIS = "Non vérifiable" }[$R.Etat]
        $Det = ""
        if ($R.Detail.Count) { $Det = "<details><summary>Voir le détail ($($R.Detail.Count))</summary><ul>" + (($R.Detail | ForEach-Object { "<li>$(E $_)</li>" }) -join "") + "</ul></details>" }
        $Cons = if ($R.Conseil) { "<p class='cons'>$(E $R.Conseil)</p>" } else { "" }
        $Lignes += "<div class='c $($R.Etat)'><div class='t'><span class='b'>$Lib</span><b>$(E $R.Controle)</b></div><p>$(E $R.Constat)</p>$Cons$Det</div>"
    }
}
$Date = Get-Date -Format "dd/MM/yyyy HH:mm"
$Html = @"
<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Bilan 365 - $(E $NomOrg)</title>
<style>
body{font-family:'Segoe UI',Arial,sans-serif;background:#f4f6f9;color:#1d2733;margin:0}
header{background:#1F3A5F;color:#fff;padding:24px 32px}header h1{margin:0;font-size:26px}header p{margin:6px 0 0;opacity:.85}
main{max-width:900px;margin:0 auto;padding:24px 16px}
.score{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:8px}.score div{flex:1;min-width:120px;background:#fff;border-radius:10px;padding:14px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.score b{display:block;font-size:30px}.v b{color:#1e8e3e}.o b{color:#d97a00}.r b{color:#c62828}.g b{color:#777}
.verdict{font-size:18px;margin:16px 0}
h2{margin:28px 0 10px;font-size:20px;color:#1F3A5F}
.c{background:#fff;border-radius:10px;padding:14px 18px;margin:10px 0;border-left:6px solid #999;box-shadow:0 1px 3px rgba(0,0,0,.06)}
.c p{margin:6px 0}.c .cons{color:#444;font-style:italic}.t{display:flex;gap:10px;align-items:center}
.b{font-size:12px;font-weight:600;padding:3px 8px;border-radius:10px;color:#fff;background:#999;white-space:nowrap}
.OK{border-color:#1e8e3e}.OK .b{background:#1e8e3e}.ORANGE{border-color:#d97a00}.ORANGE .b{background:#d97a00}
.ROUGE{border-color:#c62828}.ROUGE .b{background:#c62828}.GRIS .b{background:#888}
details{margin-top:6px}summary{cursor:pointer;color:#1F3A5F}ul{margin:6px 0 0 18px;padding:0}
footer{max-width:900px;margin:0 auto;padding:16px;color:#666;font-size:13px;border-top:1px solid #dde}
a{color:#1F3A5F}
</style></head><body>
<header><h1>Bilan 365 - $(E $NomOrg)</h1><p>Tenant $(E $Domaine) - analysé le $Date par $(E $Compte) - lecture seule, rien n'a été modifié</p></header>
<main>
<div class="score"><div class="v"><b>$NbOK</b>OK</div><div class="o"><b>$NbOr</b>À améliorer</div><div class="r"><b>$NbRo</b>Risques</div><div class="g"><b>$NbGr</b>Non vérifiables</div></div>
<p class="verdict">$Verdict</p>
$Lignes
</main>
<footer>Bilan 365 v1.3.1 (gratuit) - Pactio. Pour corriger ces points en une fois (BitLocker, LAPS, administrateurs, OneDrive, sécurité, imprimantes) : <a href="https://pactiofr.gumroad.com">pactiofr.gumroad.com</a>.<br>Ce bilan donne une photographie à la date indiquée ; il ne remplace pas un audit complet.</footer>
</body></html>
"@
$Sortie = Join-Path ([Environment]::GetFolderPath("Desktop")) ("Bilan365_{0}_{1}.html" -f ($Domaine -replace '[^\w\.-]', '_'), (Get-Date -Format "yyyy-MM-dd_HH-mm"))
[System.IO.File]::WriteAllText($Sortie, $Html, (New-Object System.Text.UTF8Encoding($true)))
Write-Host ""
Write-Host ("Résultat : {0} OK, {1} à améliorer, {2} risque(s), {3} non vérifiable(s)" -f $NbOK, $NbOr, $NbRo, $NbGr) -ForegroundColor Cyan
Write-Host "Rapport : $Sortie" -ForegroundColor Cyan
Start-Process $Sortie
