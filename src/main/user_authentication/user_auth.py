import re


def check_username_syntax(username: str):
    """ Comprueba que el nombre de usuario sigue el patrón definido como correcto por la expresion regular
        El patrón sigue estas reglas:
        - Debe contener al menos una letra
        - La longitud debe estar entre 4-20 caracteres
        """
    validation_pattern = r"^(?=.*[a-zA-Z]).{4,20}$"
    my_regex = re.compile(validation_pattern)
    result = my_regex.fullmatch(username)
    if not result:
        print(username)
        return False
    return True


def check_pwd_syntax(pwd: str):
    """ Comprueba que la password sigue el patron definido como correcto por la expresion regular
        El patrón sigue estas reglas:
        - Debe contener al menos una mayuscula
        - Debe contener al menos un digito numerico
        - Debe contener al menos un caracter especial del tipo {!~@_/:+}
        - La longitud debe ser de minimo 8 caracteres
        """
    validation_pattern = r"^(?=.*[A-Z])(?=.*\d)(?=.*[!~@_/:+]).{8,}$"
    my_regex = re.compile(validation_pattern)
    result = my_regex.fullmatch(pwd)
    if not result:
        print(pwd)
        return False
    return True


def check_names_syntax(name: str):
    """Se comprueba que el patron establecido por la expresion regular como correcto se mantiene al introducir
        el nombre y los apellidos:
            -Nombres y apellidos como cadena de caracteres de letras entre 1 y 20 de longitud, admitiendose nombres y/o
            apellidos compuestos
        """
    validation_pattern = r"^[A-Za-z\s]{1,20}$"
    my_regex = re.compile(validation_pattern)
    result = my_regex.fullmatch(name)
    if not result:
        print(name)
        return False
    return True


def check_email_syntax(email: str):
    """Se comprueba que el patron establecido por la expresion regular como correcto se mantiene al introducir
        el correo:
            1. Cadena alfanumerica que admite caracteres del tipo {._%+-}
            2. Simbolo @ para separar el nombre del dominio
            3. Dominio que responde a una cadena alfanumerica que incluye caracteres del tipo {.-}
            4. Simbolo . para separar el dominio de su extension asociada
            5. Extension del tipo .com o .es de minimo 2 caracteres de longitud
        """
    validation_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    my_regex = re.compile(validation_pattern)
    result = my_regex.fullmatch(email)
    if not result:
        print(email)
        return False
    return True


def check_money(money: str):
    """Se verifica que el dinero introducido en el registro responde a una cadena numerica y que no supere los 7 digitos"""
    validation_pattern = r"^[0-9]{1,7}(.[0-9]{2})?$"
    my_regex = re.compile(validation_pattern)
    result = my_regex.fullmatch(money)
    if not result:
        print(money)
        return False
    return True
