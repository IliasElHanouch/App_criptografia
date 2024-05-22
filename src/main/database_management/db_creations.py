import sqlite3
import os
current_directory = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
database = current_directory + r"/database_management/app_database.db"
conn = sqlite3.connect(database)


def create():
    """Scripts de creacion de cada una de las tablas de usuario"""
    cursor = conn.cursor()
    """Tabla 1:
        -Nickname (univoco para cada usuario)
        -Pwd_token y su salt (para no guardar las passwords en claro en la BBDD)
    """
    cursor.execute("""CREATE TABLE IF NOT EXISTS usuarios (
                        NICKNAME VARCHAR(21),
                        PWD_TOKEN VARCHAR(100) NOT NULL,
                        SALT VARCHAR(100) NOT NULL,
                        PRIMARY KEY(NICKNAME)
                    );""")
    """Tabla 2; USER_DATA:
        -Nickname (univoco para cada usuario), clave ajena referenciando a USUARIOS
        -Todos los nonces para los datos del usuario (cada nonce es DISTINTO)
        -Clave usada para ese usuario y ENCRIPTADA con una CLAVE MAESTRA
        -La clave maestra requiere de un nonce, aunque la clave sea igual, UNICO
    """
    cursor.execute("""CREATE TABLE IF NOT EXISTS user_data (
                        USER VARCHAR(21),
                        MONEY_NONCE VARCHAR(100) NOT NULL,
                        EMAIL_NONCE VARCHAR(100) NOT NULL,
                        NAME_NONCE VARCHAR(100) NOT NULL,
                        SURNAME1_NONCE VARCHAR(100) NOT NULL,
                        KEY_USED VARCHAR(100) NOT NULL,
                        NONCE_MASTER_KEY VARCHAR(100) NOT NULL,
                        PRIMARY KEY(USER),
                        FOREIGN KEY(USER) references USUARIOS(NICKNAME) ON DELETE CASCADE
                    );""")
    """Tabla 3; USER_INFO:
        -Nickname (univoco para cada usuario), clave ajena referenciando a USUARIOS
        -Todos los datos que ha especificado el usuario al registrarse (o el dinero cada vez que es cambiado)
         ENCRIPTADOS haciendo uso de las claves/nonces guardadas PARA CADA USUARIO en la tabla anterior
    """
    cursor.execute("""CREATE TABLE IF NOT EXISTS user_info (
                        USER VARCHAR(21),
                        MONEY NUMERIC(10,2),
                        EMAIL VARCHAR(50),
                        NAME VARCHAR(30),
                        SURNAME1 VARCHAR(50),
                        PRIMARY KEY(USER),
                        FOREIGN KEY(USER) references USUARIOS(NICKNAME) ON DELETE CASCADE
                    );""")


