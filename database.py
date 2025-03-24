import os
import pyodbc
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get Azure SQL driver from .env
driver = os.getenv("AZURE_SQL_DRIVER")  # Should be 'ODBC Driver 18 for SQL Server'

# Create connection
def get_connection(server, database, username, password):
    conn = pyodbc.connect(
        f"DRIVER={{ODBC Driver 18 for SQL Server}};"
        f"SERVER={server};"
        f"DATABASE={database};"
        f"UID={username};"
        f"PWD={password};"
        f"Encrypt=yes;"
        f"TrustServerCertificate=no;"
        f"Connection Timeout=30;"
    )
    return conn
