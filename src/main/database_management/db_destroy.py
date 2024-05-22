"""Este codigo se usa UNICA Y EXCLUSIVAMENTE en el caso de que se desee destruir al completo la BBDD
    * No usar si no se desea llevar a cabo una accion irreversible *
"""
import config_files
import sqlite3
import os

current_directory = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
database = current_directory + r"/database_management/app_database.db"
conn = sqlite3.connect(database)


def destroy():
    cursor = conn.cursor()
    cursor.execute(f"DROP TABLE USER_DATA;")
    cursor.execute(f"DROP TABLE USER_INFO;")
    cursor.execute(f"DROP TABLE USUARIOS;")

# (Adicional, para destruir la bbdd hay que eliminar los certificados y claves de usuario...)
config_files.resetear_directorios()
# Descomentar en caso de que se quiera destruir la base de datos
destroy()

