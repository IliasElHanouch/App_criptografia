from interface import Interface
from database_management import db_creations
import os
if __name__ == "__main__":
    master_key_bytes = b'=6\x90\x9e\x02#d\x8f\x02\xcd\x19|\xdd\x05Dj\x18\x8cG\xf5\x1fZ\x02\xc6\x0cLS\xd8\xa6;c\x8e'
    # Convertir los bytes a una cadena hexadecimal para almacenar en la variable de entorno
    master_key_hex = master_key_bytes.hex()
    # Almacenar en la variable de entorno
    os.environ["MASTER_KEY"] = master_key_hex
    db_creations.create()
    app = Interface()
    app.mainloop()
