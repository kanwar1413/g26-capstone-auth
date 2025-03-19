import os
import sys
from fastapi import FastAPI, HTTPException
from keyvault import CapstoneKeyVault
from dotenv import load_dotenv
from database import get_connection
from fastapi.middleware.cors import CORSMiddleware
import secrets
from datetime import datetime, timedelta
import bcrypt
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

# Authentication Helpers

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(plain_password, hashed_password) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))

def create_session_token():
    return secrets.token_hex(32)  # Secure random token

# Authentication Endpoints
@app.post("/register")
def register_user(username: str, password: str):
    try:
        cursor = sql_conn.cursor()
        hashed_password = hash_password(password)
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        sql_conn.commit()
        return {"message": "User registered successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error registering user: {str(e)}")

@app.post("/login")
def login(response: Response, form_data: OAuth2PasswordRequestForm = Depends()):
    try:
        cursor = sql_conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (form_data.username,))
        user = cursor.fetchone()
        if not user or not verify_password(form_data.password, user[0]):
            raise HTTPException(status_code=401, detail="Invalid credentials")

        session_token = create_session_token()
        cursor.execute("INSERT INTO sessions (username, session_token) VALUES (?, ?)", (form_data.username, session_token))
        sql_conn.commit()

        response.set_cookie(key="session_token", value=session_token, httponly=True, max_age=SESSION_EXPIRY_MINUTES * 60)
        return {"message": "Login successful"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error during login: {str(e)}")

@app.get("/protected")
def protected_route(request: Request):
    try:
        session_token = request.cookies.get("session_token")
        if not session_token:
            raise HTTPException(status_code=401, detail="Not authenticated")

        cursor = sql_conn.cursor()
        cursor.execute("SELECT username FROM sessions WHERE session_token = ?", (session_token,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=401, detail="Invalid session")

        return {"message": "Authenticated", "user": user[0]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error verifying session: {str(e)}")

@app.post("/logout")
def logout(response: Response, request: Request):
    try:
        session_token = request.cookies.get("session_token")
        if session_token:
            cursor = sql_conn.cursor()
            cursor.execute("DELETE FROM sessions WHERE session_token = ?", (session_token,))
            sql_conn.commit()

        response.delete_cookie("session_token")
        return {"message": "Logged out successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error during logout: {str(e)}")

@app.get("/")
def root():
    return {"message": "Authentication service is running"}

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