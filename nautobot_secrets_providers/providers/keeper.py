"""Secrets Provider for Keeper."""
import os

# from pathlib import Path
# import base64
# import json

try:
    from keeper_secrets_manager_core import SecretsManager
    from keeper_secrets_manager_core.core import KSMCache
    from keeper_secrets_manager_core.exceptions import KeeperError, KeeperAccessDenied
    from keeper_secrets_manager_core.storage import FileKeyValueStorage  # , InMemoryKeyValueStorage

    # from keeper_secrets_manager_core.utils import get_totp_code
except (ImportError, ModuleNotFoundError):
    keeper = None

from django import forms
from django.conf import settings

# from django.core.exceptions import ValidationError

from nautobot.apps.secrets import exceptions, SecretsProvider
from nautobot.utilities.forms import BootstrapMixin

from .choices import KeeperTypeChoices


__all__ = ("KeeperSecretsProvider",)


try:
    plugins_config = settings.PLUGINS_CONFIG["nautobot_secrets_providers"]
    KEEPER_TOKEN = plugins_config["keeper"]["token"]
except KeyError:
    KEEPER_TOKEN = None


class KeeperSecretsProvider(SecretsProvider):
    """A secrets provider for Keeper Secrets Manager."""

    slug = "keeper-secret-manager"
    name = "Keeper Secret Manager"

    class ParametersForm(BootstrapMixin, forms.Form):
        """Parameters for Keeper Secrets Manager."""

        name = forms.CharField(
            label="Secret Name",
            help_text="The name of the secret record in Keeper (optional if UID is provided)",
            max_length=30,
            min_length=5,
            required=False,
        )
        uid = forms.CharField(
            label="Secret UID",
            help_text="The unique identifier of the secret record in Keeper (optional if Name is provided)",
            max_length=25,
            min_length=20,
            required=False,
        )
        token = forms.CharField(
            label="Access Token",
            widget=forms.PasswordInput,
            help_text="Keeper access token (optional if config is provided)",
            max_length=40,
            min_length=20,
            initial=KEEPER_TOKEN,
            required=False,
        )
        config = forms.JSONField(
            label="Configuration",
            help_text="Keeper configuration in JSON format (optional if token is provided)",
            max_length=500,
            min_length=70,
            required=False,
            validators=[
                lambda value: validate_keeper_config(value)
            ]
        )
        type = forms.ChoiceField(
            label="Secret Type",
            required=True,
            choices=KeeperTypeChoices.CHOICES,
            help_text="Type of information to retrieve from the secret record",
        )

        def clean(self):
            """Validate form data and ensure required fields are present."""
            cleaned_data = super().clean()
            
            # Validate secret identifier
            if not cleaned_data.get("name") and not cleaned_data.get("uid"):
                raise forms.ValidationError(
                    "Either secret name or UID must be provided"
                )
            
            # Validate authentication
            if not cleaned_data.get("token") and not cleaned_data.get("config"):
                raise forms.ValidationError(
                    "Either access token or configuration must be provided"
                )
            
            # Validate config JSON if provided
            if cleaned_data.get("config"):
                try:
                    validate_keeper_config(cleaned_data["config"])
                except ValueError as e:
                    raise forms.ValidationError(str(e))
            
            return cleaned_data

    def validate_keeper_config(config):
        """Validate Keeper configuration JSON structure."""
        required_fields = ["hostname", "clientId", "privateKey"]
        if not isinstance(config, dict):
            raise ValueError("Configuration must be a JSON object")
        
        for field in required_fields:
            if field not in config:
                raise ValueError(f"Missing required field: {field}")
            
        if not isinstance(config.get("hostname"), str):
            raise ValueError("hostname must be a string")
            
        return True

    @classmethod
    def get_value_for_secret(cls, secret, obj=None, **kwargs):
        """Return the secret value."""
        # First, try to get the UID from the custom field if an object is provided
        if obj:
            from nautobot.extras.models import CustomField
            # Automatically create the custom field if it does not exist
            if not CustomField.objects.filter(name="cf_keeper_uid").exists():
                CustomField.objects.create(name="cf_keeper_uid", type="text", label="Keeper UID")
            
            uid_value = None
            # Prioritize device's cf_keeper_uid
            if hasattr(obj, "custom_field_data") and "cf_keeper_uid" in obj.custom_field_data:
                uid_value = obj.custom_field_data["cf_keeper_uid"]
            # Fall back to location's cf_keeper_uid if not found on device
            elif hasattr(obj, "location") and obj.location and hasattr(obj.location, "custom_field_data"):
                uid_value = obj.location.custom_field_data.get("cf_keeper_uid")
            
            if uid_value:
                # If we found a UID in the custom field, use it directly
                return uid_value
        
        # If no object provided or no UID found in custom fields, fall back to standard behavior
        # Extract the parameters from the Secret
        parameters = secret.rendered_parameters(obj=obj)
        
        if keeper is None:
            raise exceptions.SecretProviderError(
                secret, cls, "The Python dependency keeper_secrets_manager_core is not installed"
            )
        
        try:
            secret_name = None
            secret_uid = None
            if "name" in parameters:
                secret_name = parameters["name"]
            if "uid" in parameters:
                secret_uid = parameters["uid"]
            token = parameters.get("token", KEEPER_TOKEN)
            config = None
            if "config" in parameters:
                config = parameters["config"]
            type = parameters.get("type")
        except KeyError as err:
            msg = f"The secret parameter could not be retrieved for field {err}"
            raise exceptions.SecretParametersError(secret, cls, msg) from err
        
        if not KEEPER_TOKEN and not token and not config:
            raise exceptions.SecretProviderError(
                secret, cls, "Nor the Token or config is configured, at least 1 is required!"
            )
        
        if not secret_name and not secret_uid:
            raise exceptions.SecretProviderError(secret, cls, "At least the secret's name or uid must be provided!")
        
        # Ensure required parameters are set
        if not token and not config:
            raise exceptions.SecretProviderError(
                secret, cls, "Keeper Secret Manager is not configured!"
            )
        
        try:
            # Create a Secrets Manager client.
            secrets_manager = SecretsManager(
                token=token,
                # config=InMemoryKeyValueStorage(config),
                config=FileKeyValueStorage("config.json"),
                log_level="DEBUG" if os.environ.get("DEBUG", None) else "ERROR",
                custom_post_function=KSMCache.caching_post_function,
            )
        except (KeeperError, KeeperAccessDenied) as err:
            msg = f"Unable to connect to Keeper Secret Manager {err}"
            raise exceptions.SecretProviderError(secret, cls, msg) from err
        except Exception as err:
            msg = f"Unable to connect to Keeper Secret Manager {err}"
            raise exceptions.SecretProviderError(secret, cls, msg) from err
        
        keeper_secret = None
        if secret_uid:
            try:
                keeper_secret = secrets_manager.get_secrets(uids=secret_uid)[0]
                # # https://docs.keeper.io/secrets-manager/secrets-manager/about/keeper-notation
                # secret = secrets_manager.get_notation(f'{secret_uid}/field/{type}')[0]
            except Exception as err:
                msg = f"The secret could not be retrieved using uid {err}"
                raise exceptions.SecretValueNotFoundError(secret, cls, msg) from err
        elif secret_name:
            try:
                keeper_secret = secrets_manager.get_secret_by_title(secret_name)
            except Exception as err:
                msg = f"The secret could not be retrieved using name {err}"
                raise exceptions.SecretValueNotFoundError(secret, cls, msg) from err
        else:
            msg = f"At least the secret's name or uid must be provided"
            raise exceptions.SecretValueNotFoundError(secret, cls, msg)
        
        try:
            my_secret_info = keeper_secret.field(type, single=True)
            # api_key = secret.custom_field('API Key', single=True)
            # url = secret.get_standard_field_value('oneTimeCode', True)
            # totp = get_totp_code(url)
            # https://github.com/Keeper-Security/secrets-manager/blob/master/sdk/python/core/keeper_secrets_manager_core/utils.py#L124C24-L124C24:
        except Exception as err:
            msg = f"The secret field could not be retrieved {err}"
            raise exceptions.SecretValueNotFoundError(secret, cls, msg) from err
        
        return my_secret_info
