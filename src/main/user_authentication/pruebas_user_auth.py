import user_auth
import re
from database_management import db_management
from database_management import db_creations


import re

nombre_apellido = ""
if re.match(r'^[A-Z][a-zA-Z\s]*$', nombre_apellido):
    print("El nombre o apellido es válido.")
else:
    print("El nombre o apellido no es válido.")
