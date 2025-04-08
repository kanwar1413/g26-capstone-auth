import os
import sys
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from keyvault import CapstoneKeyVault
from dotenv import load_dotenv
from database import get_connection

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

origins = [
    "http://localhost:5173", 
    "https://g26-capstone-front-end-dcdfabdfhkakegcq.canadacentral-01.azurewebsites.net/"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True, # Important for cookies/auth headers
    allow_methods=["*"],    # Allows all standard methods
    allow_headers=["*"],    # Allows all headers
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
