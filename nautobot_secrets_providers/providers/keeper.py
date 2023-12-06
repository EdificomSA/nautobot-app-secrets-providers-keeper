"""Secrets Provider for Keeper."""
import os
from pathlib import Path
import base64
import json

try:
    from keeper_secrets_manager_core import SecretsManager
    from keeper_secrets_manager_core.core import KSMCache
    from keeper_secrets_manager_core.exceptions import KeeperError, KeeperAccessDenied
    from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
except (ImportError, ModuleNotFoundError):
    keeper = None

from django import forms
from django.conf import settings

from nautobot.utilities.forms import BootstrapMixin
from nautobot.extras.secrets import exceptions, SecretsProvider

from .choices import KeeperTypeChoices


__all__ = ("KeeperSecretsProvider")


try:
    plugins_config = settings.PLUGINS_CONFIG["nautobot_secrets_providers"]
    KEEPER_TOKEN = plugins_config["keeper"]["token"]
except KeyError:
    KEEPER_TOKEN = None

class KeeperSecretsProvider(SecretsProvider):
    """A secrets provider for Keeper Secrets Manager."""

    slug = "keeper"
    name = "Keeper"
    is_available = keeper is not None

    class ParametersForm(BootstrapMixin, forms.Form):
        """Required parameters for Keeper Secrets Manager."""

        name = forms.CharField(
            required=True,
            help_text="The name of the Keeper Secrets Manager secret",
            max_length=300,
            min_length=3,
        )
        uid = forms.CharField(
            required=True,
            help_text="The uid of the Keeper Secrets Manager secret",
            max_length=300,
            min_length=3,
        )
        token = forms.CharField(
            widget=forms.PasswordInput,
            # required=True,
            help_text="The token of the Keeper Secrets Manager",
            max_length=300,
            min_length=3,
        )
        # config = forms.FileField(
        #     required=True,
        #     help_text="The configuration file for the Keeper Secrets Manager",
        # )
        config = forms.JSONField(
            required=True,
            help_text="The JSON configuration for the Keeper Secrets Manager",
            max_length=300,
            min_length=30,
        )
        # config = forms.CharField(
        #     required=True,
        #     help_text="The base64 configuration for the Keeper Secrets Manager",
        #     max_length=300,
        #     min_length=30,
        # )
            # hostname
            # clientId
            # privateKey
            # serverPublicKeyId
            # appKey
            # appOwnerPublicKey
        type = forms.ChoiceField(
            required=True,
            choices=KeeperTypeChoices.CHOICES,
            help_text="The type of info in the Keeper Secrets Manager",
        )

    @classmethod
    def get_value_for_secret(cls, secret, obj=None, **kwargs):
        """Return the secret value."""
        # Extract the parameters from the Secret.

        parameters = secret.rendered_parameters(obj=obj)

        try:
            secret_name = parameters.get("name")
            secret_uid = parameters.get("uid")
            token = parameters.get("token", KEEPER_TOKEN)
            config = parameters.get("config")
            type = parameters.get("type")
        except KeyError as err:
            msg = f"The secret parameter could not be retrieved for field {err}"
            raise exceptions.SecretParametersError(secret, cls, msg) from err

        if not KEEPER_TOKEN and not token:
            raise exceptions.SecretProviderError(secret, cls, "The Keeper Token is not configured!")
        
        if not secret_name and not secret_uid:
            raise exceptions.SecretProviderError(secret, cls, "The Keeper Secret Name and UID are not configured!")

        # Ensure required parameters are set
        if any(
            [not all([secret_name, secret_uid, token, config, type])]
        ):
            raise exceptions.SecretProviderError(
                secret,
                """Keeper Secret Manager is not configured!
                """,
            )

        try:
            # Create a Secrets Manager client.
            secrets_manager = SecretsManager(
                token=token,
                config=InMemoryKeyValueStorage(config),
                custom_post_function=KSMCache.caching_post_function
            )
        except (KeeperError, KeeperAccessDenied) as err:
            msg = f"Unable to connect to Keeper Secret Manager {err}"
            raise exceptions.SecretProviderError(secret, msg) from err
        except Exception as err:
            msg = f"Unable to connect to Keeper Secret Manager {err}"
            raise exceptions.SecretProviderError(secret, msg) from err

        if secret_uid:
            try:
                secret = secrets_manager.get_secrets(uids=secret_uid)[0]
                # # https://docs.keeper.io/secrets-manager/secrets-manager/about/keeper-notation
                # secret = secrets_manager.get_notation(f'{secret_uid}/field/{type}')[0]
            except Exception as err:
                msg = f"The secret could not be retrieved using uid {err}"
                raise exceptions.SecretValueNotFoundError(secret, cls, msg) from err
        if secret_name:
            try:
                secret = secrets_manager.get_secret_by_title(secret_name)
            except Exception as err:
                msg = f"The secret could not be retrieved using name {err}"
                raise exceptions.SecretValueNotFoundError(secret, cls, msg) from err

        try:
            my_secret_info = secret.field(type, single=True)
            # api_key = secret.custom_field('API Key', single=True)
        except Exception as err:
            msg = f"The secret field could not be retrieved {err}"
            raise exceptions.SecretValueNotFoundError(secret, cls, msg) from err

        return my_secret_info
