from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient


class CapstoneKeyVault:
    def __init__(self, key_vault_url):
        try:
            self.key_vault_url = key_vault_url
            # Note: This assumes that either this is running on an Azure resource with access to 
            # the Key Vault, or the device is logged in through Azure CLI. (ie. successful az login)
            self.credential = DefaultAzureCredential()
            self.secret_client = SecretClient(vault_url=key_vault_url, credential=self.credential)
        except Exception as e:
            print(f"{str(e)}")

            raise Exception(f"Error: {str(e)}")
        

    def get_secret_value(self, secret_name):
        try:
            secret = self.secret_client.get_secret(secret_name)
            return secret.value
        except Exception as e:
            print(f"{str(e)}")
            raise Exception(f"Error retrieving secret: {str(e)}")