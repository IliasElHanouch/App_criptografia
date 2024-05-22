import os
import re
import sqlite3

current_directory = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
database = current_directory + r"/database_management/app_database.db"
conn = sqlite3.connect(database)
cursor = conn.cursor()

cursor.execute("Select * from usuarios;")
info = cursor.fetchall()
print(info)
print(database)


