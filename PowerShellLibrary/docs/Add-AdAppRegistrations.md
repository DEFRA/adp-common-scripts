---

---
# Add-AdAppRegistrations documentation

AAD App-Registration(s) can be created and configured by referencing a `json manifest file`.

The manifest structure is loosly based on [Azure Active Directory app manifest](https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-app-manifest) schema and supports the definition in a similar way of apis ([oauth2PermissionScopes](https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-app-manifest#oauth2permissions-attribute)), api-roles ([appRoles](https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-app-manifest#approles-attribute)) and authorisations ([requiredResourceAccess](https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-app-manifest#requiredresourceaccess-attribute)).

In addition, an AAD App-Registration id, secret or any property can be added to a KeyVault store.

The json manifest file can be parameterised by adding place-holder (e.g. `#{{ yamlVariableName }}`). The place-holder will be replaced with values set in the yaml variable templates.

#### **AAD App-Registration tenant avaliability**
AAD App-Registration creation is available in any Defra AAD/B2C tenant. However, the renewal functionality is only available in the following DEFRA tenants:
 1. DefraCloudDev
 2. O365_DefraDev
 3. DefraCloudPre
 4. DefraCloud
 5. Defra

#### **Not supported features**

  * Renewal of app registration secret in **`Azure Active Directory B2C`** .

  * **`Restarting Application:`** The renewed secret will be added in keyvault by the service, consumer is responsible for restarting any application if required.

  * **`Keyvault behind VNET:`**  This is a known issue and will be resolved shortly.

#### **Supported tenants for KeyVault in a different tenant to the AAD App-Registration**

| AAD App-Registration Tenant | KeyVault Tenant |
| -------- | ------------------ |
| defraCloudDev |	defra |
| defraCloudDev	| O365DefraDev |
| o365DefraDev	| defraCloudDev |
| o365DefraDev	| defra |
| defra	| defraCloudDev |
| defra	| o365DefraDev |
| defraCloudPre	| defra |
| defra	| defraCloudPre |
| defraCloud | defra |
| defra	| defraCloud |

#### **Via pipeline-template `common-infrastructure-deploy.yaml` and its optional parameter `appRegManifestJsonPath`**
using .

| :memo: The service-principal of the service-connection used will be added as the owner of the AAD App-Registration when created. |
|:----------|

```yaml
extends:
  template: /templates/pipelines/common-infrastructure-deploy.yaml@PipelineCommon
  parameters:
    projectName: MyProjectName
    appRegManifestJsonPath: manifest.json
    groupedTemplates:
      - name: MyGroupName
        templates:
          - name: ArmTemplateName
            isDeployToSecondaryRegions: false
            path: ArmTemplateFolder
            scope: Resource Group
            resourceGroupName: MyResourceGroupName
```


#### **Via the common PowerShell script Add-AdAppRegistrations.ps1**

It can be used as a `preDeployScriptsList` or `postDeployScriptsList` of the pipeline-template `common-infrastructure-deploy.yaml` or `scriptsList` of the pipeline-template `common-scripts-deploy.yaml`.

| :memo: The service-principal of the service-connection used will be added as the owner of the AAD App-Registration when created. |
|:----------|

```yaml
extends:
  template: /templates/pipelines/common-infrastructure-deploy.yaml@PipelineCommon
  parameters:
    projectName: MyProjectName  
    groupedTemplates:
      - name: MyGroupName
        templates:
          - name: ArmTemplateName
            path: ArmTemplateFolder
            scope: Resource Group
            resourceGroupName: MyResourceGroupName
            postDeployScriptsList:
              - displayName: Create or Update App Registrations
                filePathsForTransform: 
                  - 'manifest.json'
                scriptPath: 'Add-AdAppRegistrations.ps1@PipelineCommon'
                ScriptArguments: >
                  -AppRegJsonPath manifest.json
```
#### **Structure of the manifest file**
Example `manifest.json` file
```json
{
  "applications": [
    {
      "displayName": "AAD App-Registration display name",
      "originalDisplayName": "AAD App-Registration original display name (used for renaming an AAD App-Registration original)",
      "IdentifierUris": "",
      "secretAutoRenewalEnabled": false,
      "renewalNotificationEmailAddress": "Email address to receive AAD App-Reg Secret renewal notification"
      "notes": "Add information relevant to the management of this application." ,
      "keyVault":
      {
        "name": "KeyVault resource name",
        "resourceGroup": "KeyVault resource-group name",
        "secrets": [
          {
            "key": "KeyVault secret name",
            "clientSecretDescriptionPrefix": "description text" (only used for type ClientSecret) 
            "type": "ClientSecret or ClientId",
            "validityInDays": 000 (optional, default is 6 months and max is 365 days)
          }
        ]
      },
      "api": {
        "oauth2PermissionScopes": [
            {
                "id": "00000000-0000-0000-0000-000000000000",
                "adminConsentDisplayName": "admin display name",
                "adminConsentDescription": "admin description",
                "userConsentDisplayName": "user consent display name",
                "userConsentDescription": "user consent description",
                "isEnabled": true,
                "lang": null,
                "origin": "Application",
                "type": "User",
                "value": "user_impersonation"
            }
        ]
      },
      "appRoles": [
        {
          "allowedMemberTypes": [ "Application" ],
          "description": "role description",
          "displayName": "role title",
          "id": "",
          "isEnabled": true,
          "lang": null,
          "origin": "Application",
          "value": "role value"
        }
      ],
      "requiredResourceAccess": [
        {
          "resourceAppId": "00000000-0000-0000-0000-000000000000",
          "resourceAccess": [
            {
              "id": "00000000-0000-0000-0000-000000000000",
              "type": "Scope"
            }
          ]
        }
      ]
      "signInAudience": "AzureADMyOrg",
      "publicClient": {
        "redirectUris": []
      },
      "web": {
        "homePageUrl": "https://consento.com",
        "logoutUrl": "https://consento.com/logout",
        "redirectUris": [],
        "implicitGrantSettings": {
            "enableAccessTokenIssuance": false,
            "enableIdTokenIssuance": true
        }
      }
    }
  ]
}
```

#### Mandatory properties
* `displayName` AAD App-Registration display name

#### Optional properties
* `originalDisplayName` AAD App-Registration original display name. This is used when `displayName` is changing (renaming the AAD App-Registration).

  Example `manifest.json` file
  ```json
  {
    "applications": [
      {
        "displayName": "newName",
        "originalDisplayName": "currentName"
      }
    ]
  }
  ```

* **`api`** sets the collection of OAuth 2.0 permission scopes that the web API (resource) app exposes to client apps (further information in [documentation](https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-app-manifest#oauth2permissions-attribute)).
  
  Example
  ```json
  "api": {
      "oauth2PermissionScopes": [
          {
              "id": "3dde05d7-464b-4485-8838-3206a63059dc",
              "adminConsentDisplayName": "admin display name",
              "adminConsentDescription": "admin description",
              "userConsentDisplayName": "user consent display name",
              "userConsentDescription": "user consent description",
              "isEnabled": true,
              "lang": null,
              "origin": "Application",
              "type": "User",
              "value": "user_impersonation"
          }
      ]
    }
  ```
* **`appRoles`** sets the collection of roles that an AAD App-Registration may declare. These roles can be assigned to users, groups, or service principals (further information in [documentation](https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-app-manifest#approles-attribute)).
  
  Example
  ```json
  "appRoles": [
      {
          "allowedMemberTypes": ["User"],
          "description": "Read-only access to device information",
          "displayName": "Read Only",
          "id": "601790de-b632-4f57-9523-ee7cb6ceba95",
          "isEnabled": true,
          "value": "ReadOnly"
      }
    ]
  ```
* **`identifierUris`** User-defined URI(s) that uniquely identify a web app within its Azure AD tenant or verified customer owned domain (further information in [documentation](https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-app-manifest#identifieruris-attribute)). It allows you to specify one or more URIs. The value can be either a string or an array of strings.
  
  Example with a single URI
  ```json
  "identifierUris": "https://product.contoso.com"
  ```
  Example with multiple URIs
  ```json
  "identifierUris": [
      "https://product.contoso.com",
      "https://product.contoso.com/subproduct"
    ]
  ```

* **`secretAutoRenewalEnabled`** Toggle for AAD App-Registration Secret auto renewal.

  Example
  ```json
  "secretAutoRenewalEnabled": true
  ```

  Default value
  ```json
  "secretAutoRenewalEnabled": false
  ````

* **`renewalNotificationEmailAddress`** Email address for AppReg Secret renewal notification. This address will be used to get notification when an AAD App-Reg secret is renewed.

  Example
  ```json
  "renewalNotificationEmailAddress": "someemailaccount@xyz.com"
  ```

* **`notes`** Add any relevant information about the app-reg (e.g. app-reg for xyz purpose) and instructions about what to do when an app-reg secret is renewed. In addition to user provided notes this will also append Keyvault store name, Keyvault secret name where the app-reg secret is added as well as text to an indicate that the app-reg was created automatically as part of automation tooling.

  Example
  ```json
  "notes": "This app-reg used by xyz application, and restart the app when secret is renewed"
  ```

  Default value
  ```json
  "notes": "{Keyvault Store name} and {Keyvault Secret name} + This app-reg was created automatically as part of automation tooling."
  ````  

* **`keyVault`** sets the list of AAD App-Registration properties to be added to a KeyVault store.

  * Add a new AAD App-Registration secret to KeyVault. Set `type` to `ClientSecret`.  The `subscriptionName` is required if the KeyVault is in a different subscription to the ADO Service Connection subscription.
  
    Example
    ```json
    "keyVault": {
        "name": "MyKeyVaultStore",
        "resourceGroup": "MyResourceGroup",
        "subscriptionName": "MyKeyVaultSubscriptionName",
        "secrets": [
            {
              "key": "MyKeyVaultSecret",
              "clientSecretDescriptionPrefix": "some desciption", (optional, if missing it will be set to "ADO automatic")
              "type": "ClientSecret",
              "validityInDays": 365 (optional, default is 6 months and max is 365 days)
            }
        ]
    }
    ```

  * Add a new AAD App-Registration secret to KeyVault that exist in a different tenant. Set `type` to `ClientSecret`, set the `tenant` information:  `id`, `subscriptionName` and `credential`. Note that an AAD App-Registration is required to access the different tenant and its credential are stored in a KeyVault store in the current tenant. 

    Example

    ```json
    "keyVault": {
      "name": "KeyVaultInAnotherTenant",
      "resourceGroup": "MyResourceGroupInAnotherTenant",
      "tenant": {
        "id": "MyOtherTenantId",
        "subscriptionName": "MyKeyVaultSubscriptionName",
        "credential": {
          "keyvaultName": "MyKeyVaultStoreInCurrentTenant",
          "clientId": "AppRegClientIdForAccessInAnotherTenant",
          "secretName": "KeyVaultSecretWhereAppRegPasswordIsStored"
        }
      },
      "secrets": [
        {
          "key": "MyKeyVaultSecret",
          "clientSecretDescriptionPrefix": "some desciption", (optional, if missing it will be set to "ADO automatic")
          "type": "ClientSecret"
        }
      ]
    }
    ```
  
  * Add the AAD App-Registration client id to a KeyVault store. Set `type` to **`ClientId`**
  
    Example
    ```json
    "keyVault": {
        "name": "MyKeyVaultStore",
        "resourceGroup": "MyResourceGroup",
        "secrets": [
            {
            "key": "MyKeyVaultSecret",
            "type": "ClientId"
            }
        ]
    }
    ```

  * Add an AAD App-Registration property to a KeyVault store. Set **`type`** to **`ClientProperty`** and set the name of the property in `propertyName`.
    ```json
    "keyVault": {
        "name": "MyKeyVaultStore",
        "resourceGroup": "MyResourceGroup",
        "secrets": [
            {
            "key": "MyKeyVaultSecret",
            "type": "ClientProperty",
            "propertyName": "objectId"
            }
        ]
    }
    ```
  
  * Add an AAD App-Registration service principal property to a KeyVault store. Set **`type`** to **`ServicePrincipalProperty`** and set the name of the property in `propertyName`.
    ```json
    "keyVault": {
        "name": "MyKeyVaultStore",
        "resourceGroup": "MyResourceGroup",
        "secrets": [
            {
            "key": "MyKeyVaultSecret",
            "type": "ServicePrincipalProperty",
            "propertyName": "id"
            }
        ]
    }
    ```
* **`isPublicClient`** sets toggle for allowing the public client flow (further information in [documentation](https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-app-manifest#allowpublicclient-attribute)).
  
  Example
  ```json
  "isPublicClient": true
  ```

  Default value
  ```json
  "isPublicClient": false
  ````

* **`publicClient`** sets the list of public client URIs. `isPublicClient`need to be set to `true`.

  Example
  ```json
  "publicClient": {
    "redirectUris": [
      "https://consento.com/redirect"
    ]
  }
  ```

* **`requiredResourceAccess`** sets the list of resource the AAD App-Registration requires access to (further information in [documentation](https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-app-manifest#requiredresourceaccess-attribute)).
  * `resourceAppId` is the unique identifier for the resource that the app requires access to. This value should be equal to the appId declared on the target resource app.
  * `resourceAccess` is an array that lists the OAuth2.0 permission scopes and app roles that the app requires from the specified resource. Contains the `id` and `type` values of the specified resources.
  
  Example
  ```json
  "requiredResourceAccess": [
    {
      "resourceAppId": "2d43759f-4948-4e90-80ee-93d58605f7d1",
      "resourceAccess": [
        {
          "id": "08a2cf14-53bf-44f6-94da-4a8eb9782d5b",
          "type": "Scope"
        }
      ]
    }
  ]
  ```
* **`selfApiPermission`** adds a requires access to itself for an AAD App-Registration. See `requiredResourceAccess`.
  
  Example
  ```json
  "selfApiPermission": true
  ```

    Default value
  ```json
  "selfApiPermission": false
  ````
* **`signInAudience`** sets what Microsoft accounts are accepted by the AAD App-Registration (further information in [documentation](https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-app-manifest#signinaudience-attribute)).
  
  Example
  ```json
  "signInAudience": "AzureADMyOrg"
  ````

  Supported values
  * `AzureADMyOrg` - Users with a Microsoft work or school account in my organization's Azure AD tenant (for example, single tenant)
  * `AzureADMultipleOrgs` - Users with a Microsoft work or school account in any organization's Azure AD tenant (for example, multi-tenant)
  * `AzureADandPersonalMicrosoftAccount` - Users with a personal Microsoft account, or a work or school account in any organization's Azure AD tenant
  * `PersonalMicrosoftAccount` - Personal accounts that are used to sign in to services like Xbox and Skype.

  Default value
  ```json
  "signInAudience": "AzureADMyOrg"
  ````
* **`web`** sets authentication information for the web-application the AAD App-Registration relates to.
  
  Example
  ```json
  "web": {
    "homePageUrl": "https://consento.com",
    "logoutUrl": "https://consento.com/logout",
    "redirectUris": [
        "https://consento.com/redirect"
    ],
    "implicitGrantSettings": {
        "enableAccessTokenIssuance": true,
        "enableIdTokenIssuance": false
    }
  }
  ```

#### Enabling AAD App Registration Secret Auto Renewal

Follow the below steps to activate the automatic renewal of secrets:

1. Create a manifest file with AAD App-Registration with at least one AAD App-Registration toggle `secretAutoRenewalEnabled` set to `true`
2. Deploy AAD App-Registration [Via the common PowerShell script Add-AdAppRegistrations.ps1](#**via-the-common-powershell-script-add-adappregistrations.ps1**)
   - Set `AppRegJsonPath` when calling Add-AdAppRegistrations.ps1 script.  The `AppRegJsonPath` is the path to your manifest file in your repository



Example
```yaml
extends:
  template: /templates/pipelines/common-infrastructure-deploy.yaml@PipelineCommon
  parameters:
    projectName: MyProjectName  
    groupedTemplates:
      - name: MyGroupName
        templates:
          - name: ArmTemplateName
            isDeployToSecondaryRegions: false
            path: ArmTemplateFolder
            scope: Resource Group
            resourceGroupName: MyResourceGroupName
            postDeployScriptsList:
              - displayName: Create or Update App Registrations
                filePathsForTransform: 
                  - 'manifest.json'
                scriptPath: 'Add-AdAppRegistrations.ps1@PipelineCommon'
                ScriptArguments: >
                  -AppRegJsonPath manifest.json
```

### Helper variables for authorising third-party applications
The following variables can be used to add resource-access of an AAD App-Registration.

| :warning: For an exhaustive list of variables see yaml variable file [thirdpartyapp.yaml](templates/vars/thirdpartyapp.yaml) |
|:----------|

| Variable name | Application name | Description |
| ------------- | ---------------- | ----------- |
| `apps.dynamicscrm.appId` | Dynamics CRM | Application Id |
| `apps.dynamicscrm.roles.userImpersonation` | Dynamics CRM | Resource Id for `user_impersonation` |
