from database import get_connection

conn = get_connection()
cursor = conn.cursor()

cursor.execute("SELECT @@VERSION")
row = cursor.fetchone()

print("Connected to:", row[0])

conn.close()
