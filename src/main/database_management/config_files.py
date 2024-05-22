import subprocess
import os
import re


def resetear_directorios():
    # Cambiar al directorio AC2
    ruta_ac2 = '../AC2'
    os.chdir(ruta_ac2)
    # Borrar archivos en el directorio 'solicitudes' dentro de AC2
    subprocess.run('rm -rf solicitudes/*', shell=True)
    # Borrar archivos específicos dentro de AC2
    subprocess.run('rm index.txt.attr.old', shell=True)
    subprocess.run('rm index.txt.old', shell=True)
    subprocess.run('rm index.txt', shell=True)
    subprocess.run('rm index.txt.attr', shell=True)
    subprocess.run('touch index.txt', shell=True)
    # Resetear el archivo serial a '02'
    subprocess.run('echo 02 > serial', shell=True)
    # Borrar el fichero serial
    subprocess.run('rm serial.old', shell=True)
    # Cambiar de nuevo al directorio original
    os.chdir('..')
    # Ruta del directorio A
    ruta_a = './A'
    os.chdir(ruta_a)
    subprocess.run('rm -rf user_certificados/*', shell=True)
    # Borrar archivos en el directorio 'user_certificados' dentro de A
    lista_archivos = os.listdir()
    # Definir el patrón de expresión regular para coincidir con la estructura '*_cert.pem'
    patron = re.compile(r'.*_request\.pem')
    # Borrar archivos que coincidan con el patrón
    for archivo in lista_archivos:
        if patron.match(archivo):
            os.remove(archivo)
    # Cambiar de nuevo al directorio original para borrar los archivos de clave
    os.chdir('..')
    subprocess.run('rm -rf user_private_files/*', shell=True)
    subprocess.run('rm -rf user_public_files/*', shell=True)
