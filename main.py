import os
import sys
from fastapi import FastAPI, HTTPException
from dotenv import load_dotenv
from database import get_connection
from fastapi.middleware.cors import CORSMiddleware
import pyodbc
from pydantic import BaseModel
from datetime import timedelta
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import timedelta,datetime

# Define the token expiration time (in minutes)
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # You can adjust this value

load_dotenv()

# Secret key to encode the JWT token (you should store this in an environment variable for production)
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"

key_vault = None
sql_conn = None

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Function to create the JWT token
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)  # Default expiration time if not provided
    to_encode.update({"exp": expire})
    
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Function to hash the password
def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

# Function to verify the password
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

    
# Pydantic model to validate user input
class UserIn(BaseModel):
    first_name: str
    last_name: str
    username: str
    password: str  # Pre-hashed password from front-end
    email: str  # Add email field
class LoginUser(BaseModel):
    username: str
    password: str


try:
    user = os.getenv("SQL_SERVER_USER")
    pwd = os.getenv("SQL_SERVER_PWD")
    url = os.getenv("SQL_SERVER_URL")
    db_name = os.getenv("SQL_SERVER_DN_NAME")
    sql_conn = get_connection(url, db_name, user, pwd)
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

@app.get("/recipes")
def get_recipes():
    try:
        cursor = sql_conn.cursor()
        cursor.execute("SELECT * FROM Recipes")
        rows = cursor.fetchall()

        # Create a list of dictionaries for each recipe
        recipes = []
        for row in rows:
            recipes.append({
                "id": row[0],
                "name": row[1],
                "description": row[2],
                "ingredients": row[3],
                "instructions": row[4],
                "difficulty": row[5]
            })
        return {"recipes": recipes}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving recipes: {str(e)}")
    
@app.get("/products")
def get_products():
    try:
        cursor = sql_conn.cursor()
        cursor.execute("SELECT * FROM Products")
        rows = cursor.fetchall()

        products = []
        for row in rows:
            products.append({
                "ingredient_name": row[0],
                "quantity": row[1]
            })

        return {"products": products}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving products: {str(e)}")
    
@app.post("/register")
def register(user: UserIn):
    try:
        cursor = sql_conn.cursor()

        # Check if the username already exists
        cursor.execute("SELECT * FROM Users WHERE username = ?", user.username)
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Username already exists.")

        # Insert new user into the Users table (password is already hashed from front-end)
        cursor.execute("INSERT INTO Users (first_name, last_name, username, password, email) VALUES (?, ?, ?, ?, ?)",
                       user.first_name, user.last_name, user.username, user.password, user.email)
        sql_conn.commit()

        return {"message": "User registered successfully"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error registering user: {str(e)}")

# Example route for login
@app.post("/login")
def login(user: LoginUser):
    try:
        cursor = sql_conn.cursor()

        # Check if the user exists and the password matches
        cursor.execute("SELECT password FROM Users WHERE username = ?", user.username)
        row = cursor.fetchone()
        if not row or not verify_password(user.password, row[0]):
            raise HTTPException(status_code=401, detail="Invalid username or password.")

        # Create JWT token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)

        return {"message": "User loggedIn successfully", "access_token": access_token, "token_type": "bearer"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error logging in: {str(e)}")


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

@app.post("/verify_token")
def verify_token(token_data: dict):
    try:
        token = token_data.get("token")
        if not token:
            raise HTTPException(status_code=400, detail="Token is required")
        
        # Get secret key from Key Vault
        # secret_key = key_vault.get_secret_value("JWT-SECRET-KEY")
        secret_key = SECRET_KEY  # Use the same secret key as above
        
        # Verify token
        payload = jwt.decode(token, secret_key, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            return {"valid": False}
            
        return {"valid": True, "username": username}
        
    except JWTError:
        return {"valid": False}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error verifying token: {str(e)}")

# def main():
#     import uvicorn
#     uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

# if __name__ == "__main__":
#     main()
