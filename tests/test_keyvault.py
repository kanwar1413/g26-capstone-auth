import unittest
from unittest.mock import patch, MagicMock
from azure.keyvault.secrets import SecretClient

from keyvault import CapstoneKeyVault

class KeyVaultAccessTest(unittest.TestCase):
    def test_get_secret_value(self):
        mock_secret_value = "Test Value." # returned value instead of getting value from azure

        # essentially this line results in replacing the SecretClient.get_secret return value with the test mock value.
        # we are doing this to avoid actually calling the azure service. From a test perspective, we assume this to already
        # work.
        with patch.object(SecretClient, 'get_secret', return_value=MagicMock(value=mock_secret_value)):
            # should technically be in a config file. but that is not important right now and the url alone is not enough to
            # access the vault. Should change in future but not a priority at the moment.
            key_vault_url = "https://notreal.vault.azure.net/" 
            capstone_keyvault = CapstoneKeyVault(key_vault_url)

            # name of secret defined in Azure Key Vault
            secret_name = "Test-Secret"
            secret_value = capstone_keyvault.get_secret_value(secret_name)

            assert secret_value == mock_secret_value
