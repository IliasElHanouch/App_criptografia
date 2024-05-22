import sqlite3
import os
from database_management import db_management
current_directory = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
database = current_directory + r"/database_management/app_database.db"
conn = sqlite3.connect(database)
cursor = conn.cursor()



sql_query = f"SELECT * from user_data;"
cursor.execute(sql_query)
info = cursor.fetchall()
for row in info:
    print(row)

