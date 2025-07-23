# Using the App

This document describes common use-cases and scenarios for this App.

## General Usage

## Use-cases and common workflows

### Using Keeper Secrets Provider with Device Custom Fields

The Keeper Secrets Provider can retrieve secrets from Keeper Secrets Manager using a UID stored in a custom field on a Device or its Location. This allows for a more dynamic and flexible approach to secret management:

1. The provider automatically creates a custom field named `cf_keeper_uid` if it doesn't exist
2. You can assign a Keeper UID to a Device by setting the value in the `cf_keeper_uid` custom field
3. If a Device doesn't have a UID, the provider will check its Location for the same custom field
4. If no UID is found in either place, the provider falls back to using the parameters specified in the Secret configuration

This approach is particularly useful for managing credentials for network devices, as it allows you to:
- Store device-specific credentials in Keeper and reference them by UID
- Group devices by location and share common credentials
- Easily update credentials by changing the UID reference without modifying the Secret configuration

## Screenshots

![Screenshot of installed apps](../images/secrets-providers-installed-apps.png "App landing page")

---

![Screenshot of plugin home page](../images/light/secrets-providers-home.png#only-light "App Home page")
![Screenshot of plugin home page](../images/dark/secrets-providers-home.png#only-dark "App Home page")

---

![Screenshot of secret using AWS Secrets Manager](../images/aws-secrets-manager-secrets-provider-add.png "Secret using AWS Secrets Manager")

---

![Screenshot of secret using HashiCorp Vault](../images/hashicorp-vault-secrets-provider-add.png "Secret using HashiCorp Vault")

---

![Screenshot of secret using Delinea Secret Server by ID](../images/delinea-id-secrets-provider-add.png "Secret using Delinea Secret Server by ID")

---

![Screenshot of secret using Delinea Secret Server by Path](../images/delinea-path-secrets-provider-add.png "Secret using Delinea Secret Server by Path")

---

![Screenshot of secret using Azure Key Vault](../images/azure-key-vault-secrets-provider-add.png "Secret using Azure Key Vault")

---

![Screenshot of secret using 1Password](../images/light/1password-vault-secrets-provider-add.png#only-light "Secret using 1Password")
![Screenshot of secret using 1Password](../images/dark/1password-vault-secrets-provider-add.png#only-dark "Secret using 1Password")

---

![Screenshot of secret using Keeper Secrets Manager](../images/keeper-secrets-provider-add.png "Secret using Keeper Secrets Manager")
