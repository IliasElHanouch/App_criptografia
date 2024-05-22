import sqlite3
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

"""Se establece conexion con la base de datos"""
current_directory = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
database = current_directory + r"/database_management/app_database.db"
conn = sqlite3.connect(database)

def master_key_encrypt(data):
    """Creamos un objeto clave maestra con su propio nonce cada vez que llamamos a encriptar una clave para el usuario"""
    master_chacha = ChaCha20Poly1305(bytes.fromhex(os.environ["MASTER_KEY"]))
    master_nonce = os.urandom(12)
    # Se procedera a encriptar y desencriptar todas las claves sin datos adicionales asociades (aad)
    encrypted_key = master_chacha.encrypt(master_nonce, data, None)
    # Se retornan para poder almacenarlos en la BBDD
    return encrypted_key, master_nonce


def master_key_decrypt(encrypted_data, nonce_data):
    """Realizamos el proceso inverso al anterior cada vez que llamamos a desencriptar una clave para el usuario"""
    master_chacha = ChaCha20Poly1305(bytes.fromhex(os.environ["MASTER_KEY"]))
    decrypted_key = master_chacha.decrypt(nonce_data, encrypted_data, None)
    # Se retorna la clave desencriptada para poder descifrar los demas datos del usuario
    return decrypted_key


def generate_token(pwd):
    """Se genera el token y el salt para derivar la password"""
    salt = os.urandom(16)
    # Se usa la funcion de derivacion de clave de Scrypt (disponible desde la version 1.6 de Cryptography)
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2 ** 14,
        r=8,
        p=1,
    )
    token = kdf.derive(bytes(pwd, 'UTF-8'))
    return token, salt


def get_token_salt(username):
    """Se obtiene el token y salt de la BBDD para poder autenticar los datos del usuario cada vez que inicia sesion"""
    cursor = conn.cursor()
    sql_query = f"SELECT pwd_token, salt FROM usuarios WHERE nickname = '{username}';"
    cursor.execute(sql_query)
    info = cursor.fetchall()
    return (info[0][0]), (info[0][1])


def verify_user_password(username, pwd):
    """Se verifica que el usuario ha introducido su password correctamente cuando se loguea"""
    pwd_token, salt = get_token_salt(username)
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2 ** 14,
        r=8,
        p=1,
    )
    kdf.verify(bytes(pwd, 'ASCII'), pwd_token)


def insert_new_user(username, pwd):
    """Se llama a esta funcion cada vez que insertamos un nuevo miembro en la BBDD junto al token y salt de su password"""
    cursor = conn.cursor()
    # Llamamos a la funcion generate token
    token, salt = generate_token(pwd)
    sql_query = f"INSERT INTO usuarios(nickname,pwd_token,salt) values (?,?,?);"
    valores_insert = [username, token, salt]
    cursor.execute(sql_query, valores_insert)
    commit_changes()


def encrypt_user_info(email, money, name, surname1):
    """Funcion que encripta la informacion del usuario"""
    # Generamos una key usando el algoritmo de cifrado y autenticado de ChaCha20
    key = os.urandom(32)
    chacha = ChaCha20Poly1305(key)
    # Generamos y asignamos un nonce unico para cada dato del usuario
    nonce_data = [os.urandom(12) for _ in range(4)]
    money_nonce, email_nonce, name_nonce, surname1_nonce = nonce_data[0], nonce_data[1], nonce_data[2], nonce_data[3]
    # Se lleva a capo el proceso de encriptamiento
    encrypted_money = chacha.encrypt(money_nonce, str(money).encode('UTF-8'), None)
    encrypted_email = chacha.encrypt(email_nonce, email.encode('UTF-8'), None)
    encrypted_name = chacha.encrypt(name_nonce, name.encode('UTF-8'), None)
    encrypted_surname1 = chacha.encrypt(surname1_nonce, surname1.encode('UTF-8'), None)
    # Llamamos al cifrado de la clave maestra y devolvemos el nonce unico generado para este usuario
    encrypted_key, nonce_encrypted_key = master_key_encrypt(key)
    # Los datos se devuelven para ser almacenados en la BBDD
    return (encrypted_email, encrypted_money, encrypted_name, encrypted_surname1, money_nonce, email_nonce,
            name_nonce, surname1_nonce, encrypted_key, nonce_encrypted_key)


def insert_new_user_details(username: str, money: float, email: str, name: str, surname1: str) -> None:
    """Se lleva a cabo la insercion de la informacion mostrada por pantalla del usuario en la BBDD
        Notese que previamente se lleva a cabo un proceso de encriptamiento de los datos a almacenar
    """
    # Se llama a encrypt_user_info
    (encrypted_email, encrypted_money, encrypted_name, encrypted_surname1, money_nonce, email_nonce, name_nonce,
     surname1_nonce, encrypted_key, nonce_encrypted_key) = encrypt_user_info(email, money, name, surname1)
    cursor = conn.cursor()
    # Se insertan la informacion en user_info y los datos del nonce y clave (encriptada) usados en user_data respectivamente
    sql_user_info = f"INSERT INTO user_info (USER, MONEY, EMAIL, NAME, SURNAME1) VALUES (?, ?, ?, ?, ?)"
    sql_user_data = f"INSERT INTO user_data (USER, MONEY_NONCE, EMAIL_NONCE, NAME_NONCE, SURNAME1_NONCE, KEY_USED, NONCE_MASTER_KEY) VALUES (?, ?, ?, ?, ?, ?, ?)"
    valores_user_info = [username, encrypted_money, encrypted_email, encrypted_name, encrypted_surname1]
    valores_user_data = [username, money_nonce, email_nonce, name_nonce, surname1_nonce, encrypted_key, nonce_encrypted_key]
    cursor.execute(sql_user_info, valores_user_info)
    cursor.execute(sql_user_data, valores_user_data)
    commit_changes()


def search_user(username: str) -> bool:
    """Funcion para buscar un usuario en la BBDD"""
    cursor = conn.cursor()
    sql_query = f"SELECT * FROM usuarios WHERE nickname = '{username}';"
    cursor.execute(sql_query)
    info = cursor.fetchall()
    return len(info) > 0


def delete_user(username: str):
    """Funcion para borrar a un usuario si existe en la BBDD"""
    cursor = conn.cursor()
    # Para depuracion, aunque el usuario exista al iniciar sesion
    if search_user(username):
        sql_statement1 = f"DELETE FROM user_data WHERE user = '{username}';"
        cursor.execute(sql_statement1)
        sql_statement2 = f"DELETE FROM user_info WHERE user = '{username}';"
        cursor.execute(sql_statement2)
        sql_statement3 = f"DELETE FROM usuarios WHERE nickname = '{username}';"
        cursor.execute(sql_statement3)
        commit_changes()


def obtain_encrypted_money(username):
    """Funcion que obtiene el dinero (encriptado) de la BBDD del usuario"""
    cursor = conn.cursor()
    query_money = f"SELECT money FROM user_info WHERE USER = '{username}';"
    cursor.execute(query_money)
    info = cursor.fetchall()
    obtained_money = info[0][0]
    return obtained_money


def obtain_money_nonce(username):
    """Funcion que obtiene el nonce relacionado al dinero del usuario para que pueda este ser desencriptado"""
    cursor = conn.cursor()
    query_money = f"SELECT money_nonce FROM user_data WHERE USER = '{username}';"
    cursor.execute(query_money)
    info = cursor.fetchall()
    obtained_nonce = info[0][0]
    return obtained_nonce

def obtain_key(username):
    """Funcion que obtiene la key del usuario para que algun dato del usuario pueda ser desencriptado"""
    cursor = conn.cursor()
    query_money = f"SELECT key_used FROM user_data WHERE USER = '{username}';"
    cursor.execute(query_money)
    info = cursor.fetchall()
    obtained_key = info[0][0]
    return obtained_key

def obtain_mk_nonce(username):
    """Funcion que devuelve el nonce de la clave maestra para poder desencriptar la del usuario que a su vez
        desencriptara otro dato de la informacion
    """
    cursor = conn.cursor()
    query_money = f"SELECT nonce_master_key FROM user_data WHERE USER = '{username}';"
    cursor.execute(query_money)
    info = cursor.fetchall()
    obtained_nonce_mk = info[0][0]
    return obtained_nonce_mk


def get_acc_money(username):
    """Funcion que obtiene los datos de dinero del usuario para poder devolverlos"""
    encrypted_money = obtain_encrypted_money(username)
    money_nonce = obtain_money_nonce(username)
    mk_nonce = obtain_mk_nonce(username)
    key_used = obtain_key(username)
    key = ChaCha20Poly1305(master_key_decrypt(key_used, mk_nonce))
    money = key.decrypt(money_nonce, encrypted_money, None)
    return float(money.decode('utf-8'))

def set_new_money(current_money, new_money, operation_type):
    """Funcion que establece una nueva cantidad de dinero para el usuario"""
    if operation_type == "ingreso":
        # Hay un limite superior del dinero, y este tiene que estar siempre redondeado a 2 cifras para los centimos
        money = current_money + float(new_money)
        if money > 9999999:
            money = 9999999
    elif operation_type == "retirada":
        # Hay un limite inferior del dinero, y este tiene que estar siempre redondeado a 2 cifras para los centimos
        money = current_money - float(new_money)
        if money < 0:
            money = 0
    else:
        # Para depuracion (no usado, se establece el dinero a 0)
        money = 0
    return round(money,2)


def encrypt_money(username, money):
    """Funcion que encripta el dinero de un usuario cuando es modificado y antes de reinsertarlo en la BBDD"""
    key_used = obtain_key(username)
    mk_nonce = obtain_mk_nonce(username)
    # Notese que se genera un nuevo nonce dado que no se puede reutilizar el que habia para el dinero
    nonce = os.urandom(12)
    key = ChaCha20Poly1305(master_key_decrypt(key_used, mk_nonce))
    encrypted_money = key.encrypt(nonce, str(money).encode('UTF-8'), None)
    # Se devuelve el dato cifrado junto a su nonce
    return encrypted_money, nonce

def update_money(encrypted_money, username):
    """Funcion que actualiza en la tabla BBDD de user_info el dinero encriptado"""
    cursor = conn.cursor()
    sql_statement = f"UPDATE user_info SET money = ? WHERE user = ?;"
    update_data = [encrypted_money, username]
    cursor.execute(sql_statement, update_data)
    commit_changes()


def update_nonce(new_nonce, username):
    """Funcion que actualiza en la tabla BBDD de user_data el nuevo nonce para el dinero encriptado"""
    cursor = conn.cursor()
    sql_statement = f"UPDATE user_data SET money_nonce = ? WHERE user = ?;"
    update_data = [new_nonce, username]
    cursor.execute(sql_statement, update_data)
    commit_changes()


def modify_money(username, new_money, operation_type):
    """
    Funcion que modifica el dinero cuando el usuario hace un ingreso o un pago:
        1. Se obtiene el dinero y desencripta
        2. Se establece una nueva cantidad
        3. Se encripta de nuevo
        4. Se inserta en la BBDD el dinero encriptado y su nonce
    """
    current_money = get_acc_money(username)
    money = set_new_money(current_money, new_money, operation_type)
    encrypted_money, nonce_money = encrypt_money(username, money)
    update_money(encrypted_money, username)
    update_nonce(nonce_money,username)


def obtain_user_info(username):
    """Funcion que obtiene los datos encriptados del usuario, preparados para ser desencriptados"""
    cursor = conn.cursor()
    sql_query = f"SELECT money, email, name, surname1 from user_info where user = '{username}';"
    cursor.execute(sql_query)
    info = cursor.fetchall()
    return info[0][0], info[0][1], info[0][2], info[0][3]


def obtain_user_nonces(username):
    """Funcion que obtiene los nonces de los datos del usuario, preparados para ser usados al descifrar"""
    cursor = conn.cursor()
    sql_query = f"SELECT money_nonce, email_nonce, name_nonce, surname1_nonce from user_data where user = '{username}';"
    cursor.execute(sql_query)
    info = cursor.fetchall()
    return info[0][0], info[0][1], info[0][2], info[0][3]


def _decrypt_user_info(username):
    """
    Se desencripta la informacion del usuario como procede de la siguiente manera:
        1. Se obtienen los datos y sus nonces
        2. Se obtiene la clave maestra y su nonce para desencriptar la clave de usuuario
        3. Una vez desencriptada la clave de usuario, se desencripta cada dato (con su nonce)
        4. Se devuelven todos esos datos para ser usados en un metodo publico que recogera la interfaz
        """
    encrypted_money, encrypted_email, encrypted_name, encrypted_surname1 = obtain_user_info(username)
    money_nonce, email_nonce, name_nonce, surname1_nonce = obtain_user_nonces(username)
    key_used = obtain_key(username)
    mk_nonce = obtain_mk_nonce(username)
    key = ChaCha20Poly1305(master_key_decrypt(key_used, mk_nonce))
    money = key.decrypt(money_nonce, encrypted_money, None)
    email = key.decrypt(email_nonce, encrypted_email, None)
    name = key.decrypt(name_nonce, encrypted_name, None)
    surname1 = key.decrypt(surname1_nonce, encrypted_surname1, None)
    return money, email, name, surname1


def get_user_info(username):
    """Funcion publica a la que accede la interfaz para poder mostrar los datos desencriptados por pantalla"""
    money, email, name, surname = _decrypt_user_info(username)
    return float(money.decode('utf-8')), email.decode('utf-8'), name.decode('utf-8'), surname.decode('utf-8')


"""Funcion aparte de la BBDD para establecer un commit cada vez que hay una insercion, borrado y/o actualizacion"""
def commit_changes():
    cursor = conn.cursor()
    sql_statement = f"commit;"
    cursor.execute(sql_statement)
