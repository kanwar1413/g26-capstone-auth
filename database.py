import os
import pyodbc
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get Azure SQL credentials from .env
server = os.getenv("AZURE_SQL_SERVER")
database = os.getenv("AZURE_SQL_DATABASE")
username = os.getenv("AZURE_SQL_USERNAME")
password = os.getenv("AZURE_SQL_PASSWORD")
driver = os.getenv("AZURE_SQL_DRIVER")  # Should be 'ODBC Driver 18 for SQL Server'

# Create connection
def get_connection():
    conn = pyodbc.connect(
        f"DRIVER={{{driver}}};"
        f"SERVER={server};"
        f"DATABASE={database};"
        f"UID={username};"
        f"PWD={password};"
        f"Encrypt=yes;"
        f"TrustServerCertificate=no;"
        f"Connection Timeout=30;"
    )
    return conn
