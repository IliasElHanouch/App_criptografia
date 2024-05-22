import shutil
import subprocess

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.oid import NameOID

from cryptography.hazmat.primitives.serialization import load_pem_public_key
import os

"""Definimos en varaibles de entorno las pwd utilizadas donde corresponda: al serializar y al interactuar con openSSL
 Notese que normalmente deberian cargarse de un archivo de configuracion, pero por el contexto de la practica, se mantiene asi
 """
os.environ["pwd_key"] = b'2023_pwd_p2'.hex()
os.environ["openssl_pwd"] = "elbicho7"

def generate_key(user):
    """Funcion encargada de generar una clave publica para un usuario"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    # Se guarda la la clave en un fichero especifico al usuario (ya se vera que antes se ha de serializar)
    save_to_file(user, private_key)
    return private_key


def serialize(private_key):
    """Funcion que serializa una clave privada para poder guardarla en un fichero de salida asociado al usuario"""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(bytes.fromhex(os.environ["pwd_key"]))
    )
    return pem


def return_path_key(privacy_type, username):
    """Funcion que devuelve la ruta entera a un fichero dependiendo de si es publico o privado para acceder al
       directorio correspondiente
    """
    if privacy_type == "public":
        directorio_actual = os.path.dirname(os.path.abspath(__file__))
        ruta_absoluta = os.path.join(directorio_actual, '..', 'user_public_files')
        file_path = os.path.join(ruta_absoluta, f"{username}_public_key.pem")
    elif privacy_type == "private":
        directorio_actual = os.path.dirname(os.path.abspath(__file__))
        ruta_absoluta = os.path.join(directorio_actual, '..', 'user_private_files')
        file_path = os.path.join(ruta_absoluta, f"{username}_private_key.pem")
    else:
        return " "
    return file_path


def save_to_file(username, private_key):
    file_path = return_path_key("private", username)
    """Funcion encargada de guardar en un fichero asociado al usuario su clave privada serializada"""
    try:
        # Se serializa la clave privada
        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(bytes.fromhex(os.environ["pwd_key"]))
        )
        # Escritura en el archivo de la clave serializada
        with open(file_path, 'wb') as file:
            file.write(priv_pem)
        public_key = private_key.public_key()
        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        file_path = return_path_key("public", username)
        # Escritura en el archivo de la clave serializada
        with open(file_path, 'wb') as file:
            file.write(pub_pem)
        print(f"Se ha guardado la clave para el usuario '{username}' en el archivo: {file_path}")
    # Captura de cualquier excepcion mediante depuracion por terminal
    except Exception as e:
        print(f"Error al guardar en el archivo: {e}")


def deserialize(data, privacy_type):
    """Funcion que lleva a cabo la tarea de deserializar una clave 'data' junto a su password asociado"""
    if privacy_type == "public":
        key = load_pem_public_key(data)
        return key
    private_key = serialization.load_pem_private_key(
        data,
        password=bytes.fromhex(os.environ["pwd_key"]),
        backend=default_backend()
    )
    return private_key


def read_file(username, privacy_type):
    """Funcion encargada de leer un fichero que alberga una clave privada, y deserializarla"""
    file_path = return_path_key(privacy_type, username)
    try:
        if not os.path.exists(file_path):
            print(f"El archivo para el usuario '{username}' no existe.")
            return None
        with open(file_path, 'rb') as file:
            pem_content = file.read()
        # Si ha ido bien, se deserializa y devuelve el contenido de la clave privada
        print(f"Se ha leído el contenido del archivo para el usuario '{username}'.")
        content = deserialize(pem_content, privacy_type)
        return content
    # Trata de excepciones
    except Exception as e:
        print(f"Error al leer el archivo: {e}")
        return None


def signing(mensaje, user):
    """Funcion que lleva a cabo el proceso de firma por el mensaje de la accion realizada por el usuario"""
    mensaje_bytes = mensaje.encode('utf-8')
    # Se lee la clave deserializada
    private_key = read_file(user, "private")
    # Proceso de firma
    signature = private_key.sign(
        mensaje_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    # Obtencion de la clave publica a partir de la clave privada
    return signature


def verify_signature(user, signature, mensaje):
    """Funcion que verifica la firma de un usuario cuando realiza una determinada transaccion"""
    # Obtencion de la clave publica
    certificado = return_deserialized_cert(user)[0] # Devuelvo el certificado deserializado de usuario
    # public_key = read_file(user, "public")
    public_key = certificado.public_key()
    mensaje_bytes = mensaje.encode('utf-8')
    # Se intenta verificar la firma a traves de la clave publica mediante trata de excepciones
    try:
        public_key.verify(
            signature,
            mensaje_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature as e:
        raise e


def certificate_request(user, key):
    directorio_actual = os.path.dirname(os.path.abspath(__file__))
    ruta_absoluta = os.path.join(directorio_actual, '..', 'A')
    # Se obtiene la ruta del fichero que se creara con el ID del usuario para la solictud del certificado
    file_path = os.path.join(ruta_absoluta, f"{user}_request.pem")
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Leganes"),
        x509.NameAttribute(NameOID.USER_ID, f"{user}"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"{user}mysite.com"),
    ])).add_extension(
        x509.SubjectAlternativeName([
            # Aplicamos algunas divergencias para diferenciar los certificados nuevamente
            x509.DNSName(f"{user}.mysite.com"),
            x509.DNSName("www.mysite.com"),
            x509.DNSName("subdomain.mysite.com"),
        ]),
        critical=False,
    ).sign(key, hashes.SHA256())  # Se firma el CSR con la clave privada del usuari
    # Se escribe en el fichero la peticion
    with open(file_path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    # Se llama a la funcion que envia el fichero a AC2 para procesar su proceso de certificacion
    send_request_AC2(user)
    # Se llama a la funcion que certifica esta solicitud y la trae de vuelta a la carpeta de certificados en A
    certificate(user)


def send_request_AC2(user):
    """Funcion que envia la request solicitada por parte del usuario a la autoridad AC2 para que la certifique"""
    # Ejecucion del comando de copy
    comando = f"cp ../A/{user}_request.pem ../AC2/solicitudes"
    subprocess.run(comando, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)


def certificate(user):
    """Funcion encargada de certificar el request del usuario mediante la emision del certificado por parte de una
       autoridad superior
    """
    # Cambiar al directorio AC2 antes de ejecutar los mandatos de openssl
    directorio_actual = os.getcwd()
    os.chdir("../AC2")
    directorio_nuevoscerts = "nuevoscerts"
    if not os.path.exists(directorio_nuevoscerts):
        os.makedirs(directorio_nuevoscerts)
    # Comando para ejecutar openssl ca para procesar la solicitud
    password = os.environ["openssl_pwd"]
    confirmacion = "y"
    confirmacion_2 = "y"
    comando_ca = f"openssl ca -in solicitudes/{user}_request.pem -notext -config AC2-72198.cnf"
    # Utilizar input para proporcionar las respuestas a las solicitudes interactivas por parte de terminal
    entrada_interactiva = f"{password}\n{confirmacion}\n{confirmacion_2}\n"
    entrada_interactiva_bytes = entrada_interactiva.encode('utf-8')  # Codificar a bytes
    subprocess.run(comando_ca, input=entrada_interactiva_bytes, shell=True)
    # Restaurar el directorio de trabajo a su estado original
    lista_archivos = os.listdir("nuevoscerts")
    if lista_archivos:
        # Mover el primer (por la dimension del programa, el unico) archivo al directorio de certificados de usuario
        archivo_a_mover = lista_archivos[0]
        shutil.move(f"nuevoscerts/{archivo_a_mover}", f"../A/user_certificados/certificate_{user}.pem")
    # Reestablecer directorio original
    os.chdir(directorio_actual)


def verify_certificate(user):
    """ Funcion que verifica la firma del certificado de usuario"""
    cert_user, cert_ac2, cert_ac1 = return_deserialized_cert(user) # Certificados deserializados

    # Se verifica con la clave de 'AC2' a  'A'
    cert_ac2.public_key().verify(
        cert_user.signature,
        cert_user.tbs_certificate_bytes,
        cert_user.signature_algorithm_parameters,
        cert_user.signature_hash_algorithm,
    )
    # Se verifica con la clave de 'AC1' a 'AC2'. Como se nota, 'AC1' no tiene necesidad de verificarse
    cert_ac1.public_key().verify(
        cert_ac2.signature,
        cert_ac2.tbs_certificate_bytes,
        cert_ac2.signature_algorithm_parameters,
        cert_ac2.signature_hash_algorithm,
    )

"""def verify_files(user):
    #Funcion alternativa que verifica el certificado asociado al usuario con los de AC2 (que usa su clave publica) que a su vez
       #usa la clave publica de AC1 para verificarse
    comando = f"openssl verify -CAfile ../A/certs.pem ../A/user_certificados/certificate_{user}.pem"
    subprocess.run(comando, shell=True)"""


def return_deserialized_cert(username):
    """Funcion que devuelve el certificado deserializado para poder verificarlo"""
    directorio_actual = os.path.dirname(os.path.abspath(__file__))
    ruta_absoluta = os.path.join(directorio_actual, '..', 'A', 'user_certificados')
    file_path = os.path.join(ruta_absoluta, f"certificate_{username}.pem")
    with open(file_path, 'rb') as file:
        pem_content = file.read()
    # Funcion load content para poder deserializarlo lo procesado del fichero del usuario
    cert = x509.load_pem_x509_certificate(pem_content)
    directorio_actual = os.path.dirname(os.path.abspath(__file__))
    ruta_absoluta = os.path.join(directorio_actual, '..', 'AC2')
    file_path = os.path.join(ruta_absoluta, f"ac2cert.pem")
    with open(file_path, 'rb') as file:
        pem_content = file.read()
    # Funcion load content para poder deserializarlo lo procesado del fichero del usuario
    cert2 = x509.load_pem_x509_certificate(pem_content)
    directorio_actual = os.path.dirname(os.path.abspath(__file__))
    ruta_absoluta = os.path.join(directorio_actual, '..', 'AC1')
    file_path = os.path.join(ruta_absoluta, f"ac1cert.pem")
    with open(file_path, 'rb') as file:
        pem_content = file.read()
    # Funcion load content para poder deserializarlo lo procesado del fichero del usuario
    cert3 = x509.load_pem_x509_certificate(pem_content)
    return cert, cert2, cert3


if __name__ == "__main__":
    user = "ili13"
    generate_key(user)
    key = read_file(user, "private")
    certificate_request(user, key)
