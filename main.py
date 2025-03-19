import os
import sys
from fastapi import FastAPI, HTTPException
from keyvault import CapstoneKeyVault
from dotenv import load_dotenv
from database import get_connection
from fastapi.middleware.cors import CORSMiddleware

load_dotenv()

key_vault = None
sql_conn = None

try:
    # set up azure key vault
    key_vault = CapstoneKeyVault(os.getenv("KEY_VAULT_URL"))
    if not key_vault:
        # this service relies on the key vault right now.
        # so exits the app if the keyvault is not successfully set. 
        raise Exception("Key Vault not made.")
    user = os.getenv("SQL_SERVER_USER")
    pwd = os.getenv("SQL_SERVER_PWD")
    sql_conn = get_connection(key_vault.get_secret_value("SQL-SERVER-NAME"), 
                              key_vault.get_secret_value("SQL-DB-NAME"), user, pwd)
except Exception as e:
    print(f"Issue: {str(e)}")
    sys.exit(-1)


app = FastAPI()

allowed_origins = [
    "http://localhost:5173",  # Local React URL
    "https://g26-capstone-front-end-dcdfabdfhkakegcq.canadacentral-01.azurewebsites.net/"  # Production React URL on Azure
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,  # Allow these origins
    allow_credentials=True,
    allow_methods=["GET", "POST"],  # Allow these HTTP methods
    allow_headers=["*"],  # Allow all headers
)


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


@app.get("/test-sql")
def test_secret():
    try:
        if sql_conn is None:
            raise Exception("SQL Connection not initialized properly.")
        
        cursor = sql_conn.cursor()
        cursor.execute("SELECT @@VERSION")
        row = cursor.fetchone()
        return {"sql-response": f"{row[0]}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving secret: {str(e)}")

# def main():
#     import uvicorn
#     uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

# if __name__ == "__main__":
#     main()