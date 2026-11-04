# Bilan 365 — le bilan de sécurité d'un tenant Microsoft 365 en 2 minutes

![Aperçu du rapport](apercu.png)

Script PowerShell **gratuit**, en français, pour les informaticiens qui gèrent des TPE/PME sous Microsoft 365.
Il analyse un tenant et produit un **rapport HTML clair** (vert / orange / rouge), lisible par le client, avec un conseil pour chaque point.

**Lecture seule : rien n'est modifié dans le tenant.** Le script lit, puis écrit uniquement son rapport sur votre Bureau.

## Ce qui est vérifié

| Thème | Contrôles |
|---|---|
| Comptes | Administrateurs généraux (trop ou pas assez), double authentification (admins compris), paramètres de sécurité par défaut ou accès conditionnel, comptes inactifs depuis 90 jours, invités externes |
| Postes | Inscription automatique dans Intune, utilisateurs administrateurs de leur PC, LAPS activé et mot de passe sauvegardé pour chaque PC, chiffrement BitLocker, conformité, PC qui ne se synchronisent plus, règle de conformité, mises à jour Windows pilotées |
| Licences | Licences payées mais attribuées à personne |

Quand un contrôle ne peut pas être fait (licence absente, droit refusé), il est marqué « non vérifiable » : le bilan ne s'arrête jamais en route.

## Lancer le bilan

**En une commande**, depuis la [PowerShell Gallery](https://www.powershellgallery.com/packages/Bilan-365) :

```powershell
Install-Script -Name Bilan-365 -Scope CurrentUser
Set-ExecutionPolicy -Scope Process Bypass -Force
Bilan-365.ps1
```

**Ou à la main** : téléchargez **[Bilan-365.ps1 (lien direct)](https://raw.githubusercontent.com/sebastienmastain/bilan-365/main/Bilan-365.ps1)** (clic droit > « Enregistrer le lien sous »), puis :

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\Bilan-365.ps1
```

⚠️ Ne faites pas « Enregistrer sous » sur la page GitHub du fichier : vous obtiendriez la page web, pas le script (erreurs « Jeton inattendu » au lancement).

Une fenêtre demande le compte administrateur du tenant (ex. `admin@entreprise.fr`), puis Microsoft vous demande de vous connecter et d'accepter les droits. Le rapport s'ouvre tout seul à la fin et reste sur le Bureau. Ctrl+P pour en faire un PDF.

Sans fenêtre : `Bilan-365.ps1 -Compte admin@entreprise.fr`

## Droits demandés (tous en lecture)

`Directory.Read.All`, `AuditLog.Read.All`, `Policy.Read.All`, `Policy.Read.DeviceConfiguration`, `DeviceManagementManagedDevices.Read.All`, `DeviceManagementConfiguration.Read.All`, `DeviceLocalCredential.ReadBasic.All` (sait seulement si un mot de passe LAPS existe, ne le lit pas).

Prérequis : Windows 10 ou 11, PowerShell 5.1, un compte administrateur du tenant. Le module `Microsoft.Graph.Authentication` s'installe tout seul pour votre utilisateur s'il manque. Certains contrôles (dernière connexion, double authentification) demandent une licence Entra ID P1, incluse dans Microsoft 365 Business Premium.

## Aller plus loin

Les autres outils Pactio (bilan de PC, GPO pour TPE, scripts Microsoft 365 et Intune, contrats de maintenance) : **[pactiofr.gumroad.com](https://pactiofr.gumroad.com)**

Un bilan de PC Windows, gratuit lui aussi : **[Bilan express](https://github.com/sebastienmastain/bilan-express)**

## Licence

Usage libre, y compris chez vos clients. Redistribution interdite. Fourni en l'état.

Pactio est un nom commercial de Sébastien Mastain EI, administrateur systèmes et réseaux depuis 27 ans (Isère).
