import os
import sys
from fastapi import FastAPI, HTTPException
from keyvault import CapstoneKeyVault
from dotenv import load_dotenv

key_vault = None

load_dotenv()
try:
    # set up azure key vault
    key_vault = CapstoneKeyVault(os.getenv("KEY_VAULT_URL"))
    if not key_vault:
        # this service relies on the key vault right now.
        # so exits the app if the keyvault is not successfully set. 
        raise Exception("Key Vault not made.")
except Exception as e:
    print(f"Issue: {str(e)}")
    sys.exit(-1)

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Hello, World!"}

# Returns a test secret value that shows Azure Key Vault is connected to the Fast Api backend.
@app.get("/test-secret")
def test_secret():
    try:
        if key_vault is None:
            raise Exception("Key Vault not initialized properly.")
        return {"test-secret-value": f"{key_vault.get_secret_value('Test-Secret')}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving secret: {str(e)}")
    
# def main():
#     import uvicorn
#     uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

# if __name__ == "__main__":
#     main()