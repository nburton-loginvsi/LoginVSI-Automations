# LoginEnterprise-Automations
A general-purpose repo for various automation tasks.
---
**totp-tool**\
Used for testing TOTP generations, as well as extracting secrets from QR codes. This uses Zxing.org's POST capabilities, so https/tcp-443 to their site must be allowed.

<img width="550" height="477" alt="image" src="https://github.com/user-attachments/assets/4173af03-713f-4cc1-be17-4099d2d4bc3b" />

<img width="293" height="241" alt="image" src="https://github.com/user-attachments/assets/a9ff3f43-4bbd-43ba-902d-2ca5cc5f179b" />

<img width="560" height="365" alt="image" src="https://github.com/user-attachments/assets/29ac489b-fa26-42ec-93a8-af8ed07f5510" />
---
**Get-LEScreenshots.ps1**\
Used for fetching all screenshots from an appliance using a mix of the events and screenshots APIs. Example use:
.\Get-LEScreenshots.ps1 -BaseUrl "https://nick-loginent2.nick.local" -ApiKey "eyJ..." -OutDir "C:\Temp\LE" -TrustAllCerts
See https://docs.loginvsi.com/login-enterprise/6.3/using-the-public-api for API details. 
