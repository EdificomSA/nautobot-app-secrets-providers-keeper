"""Unit tests for Keeper Secrets Provider."""

from unittest.mock import patch, MagicMock

from django.test import TestCase, tag
from nautobot.extras.models import Secret, CustomField
from nautobot.extras.secrets import exceptions

from nautobot_secrets_providers.providers import KeeperSecretsProvider


@tag("unit")
class KeeperSecretsProviderTestCase(TestCase):
    """Tests for KeeperSecretsProvider."""

    def setUp(self):
        """Set up test environment."""
        self.provider = KeeperSecretsProvider
        
        # Create a test secret
        self.secret = Secret.objects.create(
            name="test-keeper-secret",
            provider=self.provider.slug,
            parameters={
                "name": "test-secret",
                "type": "password",
            },
        )
        
        # Create a test device with custom field
        self.cf = CustomField.objects.create(
            name="cf_keeper_uid",
            type="text",
            label="Keeper UID"
        )
        
        # Mock device object with custom field data
        self.device = MagicMock()
        self.device.custom_field_data = {"cf_keeper_uid": "test-uid-123"}
        
        # Mock device with location that has custom field data
        self.device_with_location = MagicMock()
        self.device_with_location.custom_field_data = {}
        self.device_with_location.location = MagicMock()
        self.device_with_location.location.custom_field_data = {"cf_keeper_uid": "location-uid-456"}

    @patch("nautobot_secrets_providers.providers.keeper.keeper", None)
    def test_missing_dependency(self):
        """Test error when keeper_secrets_manager_core is not installed."""
        with self.assertRaises(exceptions.SecretProviderError) as err:
            self.provider.get_value_for_secret(self.secret)
        
        self.assertIn("not installed", str(err.exception))

    def test_no_object_provided(self):
        """Test that an error is raised when no object is provided and no parameters are set."""
        # Create a secret with no parameters
        empty_secret = Secret.objects.create(
            name="empty-keeper-secret",
            provider=self.provider.slug,
            parameters={},
        )
        
        with self.assertRaises(exceptions.SecretProviderError) as err:
            self.provider.get_value_for_secret(empty_secret)
        
        self.assertIn("At least the secret's name or uid must be provided", str(err.exception))

    def test_device_custom_field(self):
        """Test retrieving UID from device custom field."""
        with patch("nautobot_secrets_providers.providers.keeper.keeper", MagicMock()):
            uid = self.provider.get_value_for_secret(self.secret, obj=self.device)
            self.assertEqual(uid, "test-uid-123")

    def test_location_custom_field(self):
        """Test retrieving UID from location custom field when device doesn't have it."""
        with patch("nautobot_secrets_providers.providers.keeper.keeper", MagicMock()):
            uid = self.provider.get_value_for_secret(self.secret, obj=self.device_with_location)
            self.assertEqual(uid, "location-uid-456")

    def test_custom_field_creation(self):
        """Test that the custom field is created if it doesn't exist."""
        # Delete the custom field if it exists
        CustomField.objects.filter(name="cf_keeper_uid").delete()
        
        # Verify it doesn't exist
        self.assertFalse(CustomField.objects.filter(name="cf_keeper_uid").exists())
        
        # Call the method with a device
        with patch("nautobot_secrets_providers.providers.keeper.keeper", MagicMock()):
            with self.assertRaises(exceptions.SecretValueNotFoundError):
                # This should create the custom field but raise an error since the mock device has no UID
                self.provider.get_value_for_secret(self.secret, obj=MagicMock(custom_field_data={}))
        
        # Verify the custom field was created
        self.assertTrue(CustomField.objects.filter(name="cf_keeper_uid").exists())
        cf = CustomField.objects.get(name="cf_keeper_uid")
        self.assertEqual(cf.type, "text")
        self.assertEqual(cf.label, "Keeper UID")

    @patch("nautobot_secrets_providers.providers.keeper.SecretsManager")
    def test_fallback_to_parameters(self, mock_secrets_manager):
        """Test fallback to parameters when no UID is found in custom fields."""
        # Mock the SecretsManager and its methods
        mock_manager = MagicMock()
        mock_secrets_manager.return_value = mock_manager
        
        mock_secret = MagicMock()
        mock_manager.get_secret_by_title.return_value = mock_secret
        mock_secret.field.return_value = "secret-value"
        
        # Call with a device that has no custom field data
        with patch("nautobot_secrets_providers.providers.keeper.keeper", True):
            result = self.provider.get_value_for_secret(self.secret, obj=MagicMock(custom_field_data={}))
            
            # Verify it fell back to using parameters
            mock_manager.get_secret_by_title.assert_called_once_with("test-secret")
            mock_secret.field.assert_called_once_with("password", single=True)
            self.assertEqual(result, "secret-value")