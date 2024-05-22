from tkinter import END

import customtkinter
from cryptography.exceptions import InvalidSignature

from database_management import db_management
import cryptography
from user_authentication import user_auth
from database_management import assymetric_management

# Variable global utilizada para almacenar el usuario que ha iniciado sesión y poder mostrar sus datos
current_user = "a"


class Interface(customtkinter.CTk):
    """Clase que se encarga de crear la base de la interfaz, incluyendo los cambios entre frames"""
    def __init__(self):
        """Parámetros de configuración de la interfaz de la aplicación My Balance"""
        super().__init__()
        self.geometry("500x500")
        self.title("My Balance")
        self.frame = Login_frame(master=self, controller=self)
        self.frame.pack(padx=40, pady=20, fill="both", expand="true")
        self.resizable(width=False, height=False)

    def show_frame(self, page_name):
        """Función que controla el cambio de frame en la interfaz, de manera que la interfaz pueda cambiar
        de acuerdo a lo que se quiere mostrar por pantalla. Para ello cada vez que se quiera cambiar de frame
        el frame anterior se destruirá y se creará el nuevo"""
        self.frame.destroy()
        if page_name == "Login_frame":
            self.frame = Login_frame(master=self, controller=self)
        elif page_name == "Login_frame_error":
            self.frame = Login_frame_error(master=self, controller=self)
        elif page_name == "Register_frame":
            self.frame = Register_frame(master=self, controller=self)
        elif page_name == "Register_frame_ar":
            self.frame = Register_frame_ar(master=self, controller=self)
        elif page_name == "Register_frame_wrong":
            self.frame = Register_frame_wrong(master=self, controller=self)
        elif page_name == "Withdraw_money_frame":
            self.frame = Withdraw_money_frame(master=self, controller=self)
        elif page_name == "Withdraw_money_frame_error":
            self.frame = Withdraw_money_frame_error(master=self, controller=self)
        elif page_name == "Sum_money_frame":
            self.frame = Sum_money_frame(master=self, controller=self)
        elif page_name == "Sum_money_frame_error":
            self.frame = Sum_money_frame_error(master=self, controller=self)
        elif page_name == "Show_data_frame":
            global current_user
            money, email, name, surname = db_management.get_user_info(current_user)
            self.frame = Show_data_frame(master=self, controller=self, user=current_user, email=email, name=name,
                                         surname=surname, money=money)
        else:
            self.frame = Main_frame(master=self, controller=self)
        self.frame.pack(padx=40, pady=20, fill="both", expand="true")


class Login_frame(customtkinter.CTkFrame):
    """Frame de inicio de sesión, con el que arranca la aplicación"""
    def __init__(self, master, controller):
        super().__init__(master)
        self.controller = controller
        self.titulo = customtkinter.CTkLabel(master=self,
                                             text="Inicio de sesión",
                                             text_color="black",
                                             font=("Century Gothic", 40))
        self.titulo.pack(padx=10, pady=30)
        self.usuario = customtkinter.CTkEntry(master=self, placeholder_text="Usuario", font=("Roboto", 15),
                                              width=190, height=37)
        self.usuario.pack(padx=10, pady=30)
        self.usuario.place(relx=0.275, rely=0.25)
        self.pwd = customtkinter.CTkEntry(master=self, placeholder_text="Contraseña", show="*", font=("Roboto", 15),
                                          width=190, height=37)
        self.pwd.pack(padx=10, pady=30)
        self.pwd.place(relx=0.275, rely=0.375)
        # Este botón sirve para iniciar sesión
        self.login_button = customtkinter.CTkButton(master=self, text="Iniciar sesión", font=("Roboto", 15),
                                                    width=190, height=37,
                                                    command=lambda: login_user_gui(self.controller, self.usuario.get(),
                                                                                   self.pwd.get()))
        self.login_button.pack(padx=10, pady=30)
        self.login_button.place(relx=0.275, rely=0.55)
        self.new_user_button = customtkinter.CTkButton(master=self,
                                                       text="¿Eres un nuevo usuario? Registráte aquí",
                                                       font=("Roboto", 15),
                                                       width=200, height=30, fg_color="#5dade2",
                                                       command=lambda: controller.show_frame("Register_frame"))
        self.new_user_button.pack(padx=10, pady=30)
        self.new_user_button.place(relx=0.16, rely=0.675)


class Login_frame_error(Login_frame):
    """Frame de error en los datos introducidos durante el inicio de sesión"""
    def __init__(self, master, controller):
        super().__init__(master, controller)
        self.error = customtkinter.CTkLabel(master=self,
                                            text="Usuario o contraseña incorrecto",
                                            text_color="red",
                                            font=("Century Gothic", 15))
        self.error.pack(padx=10, pady=30)
        self.error.place(relx=0.225, rely=0.475)


class Register_frame(customtkinter.CTkFrame):
    """Frame que contiene la interfaz de registro de usuario"""
    def __init__(self, master, controller):
        super().__init__(master)
        self.controller = controller
        self.titulo = customtkinter.CTkLabel(master=self,
                                             text="Registro de usuario",
                                             text_color="black",
                                             font=("Century Gothic", 40))
        self.titulo.pack(padx=10, pady=30)
        self.titulo.place(relx=0.07, rely=0.02)

        self.usuario = customtkinter.CTkEntry(master=self, placeholder_text="Usuario",
                                              font=("Roboto", 15),
                                              width=190, height=37)
        self.usuario.pack(padx=10, pady=30)
        self.usuario.place(relx=0.275, rely=0.15)
        self.pwd = customtkinter.CTkEntry(master=self, placeholder_text="Contraseña", show="*",
                                          font=("Roboto", 15),
                                          width=190, height=37)
        self.pwd.pack(padx=10, pady=30)
        self.pwd.place(relx=0.275, rely=0.25)
        self.nombre = customtkinter.CTkEntry(master=self, placeholder_text="Nombre",
                                             font=("Roboto", 15),
                                             width=190, height=37)
        self.nombre.pack(padx=10, pady=30)
        self.nombre.place(relx=0.275, rely=0.35)
        self.apellido = customtkinter.CTkEntry(master=self, placeholder_text="Apellido",
                                               font=("Roboto", 15),
                                               width=190, height=37)
        self.apellido.pack(padx=10, pady=30)
        self.apellido.place(relx=0.275, rely=0.45)
        self.email = customtkinter.CTkEntry(master=self, placeholder_text="E-Mail",
                                            font=("Roboto", 15),
                                            width=190, height=37)
        self.email.pack(padx=10, pady=30)
        self.email.place(relx=0.275, rely=0.55)
        self.dinero = customtkinter.CTkEntry(master=self, placeholder_text="Dinero en la cuenta",
                                             font=("Roboto", 15),
                                             width=190, height=37)
        self.dinero.pack(padx=10, pady=30)
        self.dinero.place(relx=0.275, rely=0.65)
        # Con este botón se registra el usuario usando los datos introducidos
        self.register_button = customtkinter.CTkButton(master=self, text="Registrar usuario",
                                                       font=("Roboto", 15),
                                                       width=190, height=37,
                                                       command=lambda: register_user_gui(self.controller,
                                                                                         self.usuario.get(),
                                                                                         self.pwd.get(),
                                                                                         self.nombre.get(),
                                                                                         self.apellido.get(),
                                                                                         self.email.get(),
                                                                                         self.dinero.get()))
        self.register_button.pack(padx=10, pady=30)
        self.register_button.place(relx=0.275, rely=0.80)
        self.volver = customtkinter.CTkButton(master=self, text="Volver", font=("Roboto", 15),
                                              width=100, height=20,
                                              command=lambda: controller.show_frame("Login_frame"))
        self.volver.pack(padx=10, pady=30)
        self.volver.place(relx=0.05, rely=0.92)
        self.reglas = customtkinter.CTkButton(master=self, text="Reglas", font=("Roboto", 15),
                                              width=100, height=20)
        self.reglas.pack(padx=10, pady=30)
        self.reglas.place(relx=0.725, rely=0.92)


class Register_frame_ar(Register_frame):
    """Frame que muestra si el usuario a registrar ya ha sido registrado en la BBDD"""
    def __init__(self, master, controller):
        super().__init__(master, controller)
        self.already_registered = customtkinter.CTkLabel(master=self,
                                                         text="Usuario ya registrado",
                                                         text_color="red",
                                                         font=("Century Gothic", 15))
        self.already_registered.pack(padx=0, pady=0)
        self.already_registered.place(relx=0.32, rely=0.73)


class Register_frame_wrong(Register_frame):
    """Frame que muestra si ha habido algún error a la hora de introducir los datos del usuario a registrar"""
    def __init__(self, master, controller):
        super().__init__(master, controller)
        self.wrong = customtkinter.CTkLabel(master=self,
                                            text="Formato de los datos incorrecto",
                                            text_color="red",
                                            font=("Century Gothic", 15))
        self.wrong.pack(padx=0, pady=0)
        self.wrong.place(relx=0.225, rely=0.73)


class Main_frame(customtkinter.CTkFrame):
    """Frame principal de la aplicación, donde se encuentra la funcionalidad de la misma, con las opciones de ver
    los datos de la cuenta, realizar un ingreso y realizar un pago"""
    def __init__(self, master, controller):
        super().__init__(master)
        self.controller = controller
        self.check_dinero = customtkinter.CTkButton(master=self, text="Ver dinero", font=("Roboto", 25),
                                                    width=250, height=60,
                                                    command=lambda: controller.show_frame("Show_data_frame"))
        self.check_dinero.pack(padx=10, pady=30)
        self.check_dinero.place(relx=0.21, rely=0.15)
        # Boton para acceder al registro de un ingreso
        self.ingreso = customtkinter.CTkButton(master=self, text="Anotar ingreso", font=("Roboto", 25),
                                               width=250, height=60,
                                               command=lambda: controller.show_frame("Sum_money_frame"))
        self.ingreso.pack(padx=10, pady=30)
        self.ingreso.place(relx=0.21, rely=0.30)
        # Botón para acceder al registro de un pago
        self.pago = customtkinter.CTkButton(master=self, text="Anotar pago", font=("Roboto", 25),
                                            width=250, height=60,
                                            command=lambda: controller.show_frame("Withdraw_money_frame"))
        self.pago.pack(padx=10, pady=30)
        self.pago.place(relx=0.21, rely=0.45)
        # Botón para cerrar la sesión
        self.salir = customtkinter.CTkButton(master=self, text="Cerrar sesión", font=("Roboto", 25),
                                             width=250, height=60, fg_color="#e74c3c", hover_color="#b03a2e",
                                             command=lambda: controller.show_frame("Login_frame"))
        self.salir.pack(padx=10, pady=30)
        self.salir.place(relx=0.21, rely=0.65)
        # Botón para eliminar el usuario
        self.borrar_user = customtkinter.CTkButton(master=self, text="Borrar usuario", font=("Roboto", 25),
                                                   width=250, height=60, fg_color="black", hover_color="#202121",
                                                   command=lambda: borrar_usuario(self.controller))
        self.borrar_user.pack(padx=10, pady=30)
        self.borrar_user.place(relx=0.21, rely=0.80)


class Withdraw_money_frame(customtkinter.CTkFrame):
    """Frame utilizado para implementar la interfaz de pago"""
    def __init__(self, master, controller):
        super().__init__(master)
        self.controller = controller
        self.titulo = customtkinter.CTkLabel(master=self,
                                             text="Introduce el pago",
                                             text_color="black",
                                             font=("Century Gothic", 30))
        self.titulo.pack(padx=10, pady=30)
        self.titulo.place(relx=0.18, rely=0.20)
        self.entrada = customtkinter.CTkEntry(master=self, placeholder_text="Cantidad",
                                              font=("Roboto", 15),
                                              width=190, height=45)
        self.entrada.pack(padx=10, pady=30)
        self.entrada.place(relx=0.28, rely=0.32)
        self.confirmar = customtkinter.CTkButton(master=self, text="Confirmar", font=("Roboto", 25),
                                                 width=250, height=50, fg_color="#0dba2d", hover_color="#09731d",
                                                 command=lambda: modificar_dinero(self.controller, self.entrada.get(),
                                                                                  "retirada"))
        self.confirmar.pack(padx=10, pady=30)
        self.confirmar.place(relx=0.21, rely=0.50)
        self.volver = customtkinter.CTkButton(master=self, text="Volver", font=("Roboto", 15),
                                              width=100, height=30,
                                              command=lambda: controller.show_frame("Main_frame"))
        self.volver.pack(padx=10, pady=30)
        self.volver.place(relx=0.05, rely=0.90)


class Withdraw_money_frame_error(Withdraw_money_frame):
    """Frame utilizado para mostar si ha habido algún error en la cantidad introducida de pago"""
    def __init__(self, master, controller):
        super().__init__(master, controller)
        self.wrong = customtkinter.CTkLabel(master=self,
                                            text="Cantidad incorrecta",
                                            text_color="red",
                                            font=("Century Gothic", 15))
        self.wrong.pack(padx=0, pady=0)
        self.wrong.place(relx=0.325, rely=0.425)


class Sum_money_frame(customtkinter.CTkFrame):
    """Frame utilizado para implementar la interfaz de ingreso"""
    def __init__(self, master, controller):
        super().__init__(master)
        self.controller = controller
        self.titulo = customtkinter.CTkLabel(master=self,
                                             text="Introduce el ingreso",
                                             text_color="black",
                                             font=("Century Gothic", 30))
        self.titulo.pack(padx=10, pady=30)
        self.titulo.place(relx=0.15, rely=0.20)
        self.entrada = customtkinter.CTkEntry(master=self, placeholder_text="Cantidad",
                                              font=("Roboto", 15),
                                              width=190, height=45)
        self.entrada.pack(padx=10, pady=30)
        self.entrada.place(relx=0.28, rely=0.32)
        self.confirmar = customtkinter.CTkButton(master=self, text="Confirmar", font=("Roboto", 25),
                                                 width=250, height=50, fg_color="#0dba2d", hover_color="#09731d",
                                                 command=lambda: modificar_dinero(self.controller, self.entrada.get(),
                                                                                  "ingreso"))
        self.confirmar.pack(padx=10, pady=30)
        self.confirmar.place(relx=0.21, rely=0.50)
        self.volver = customtkinter.CTkButton(master=self, text="Volver", font=("Roboto", 15),
                                              width=100, height=30,
                                              command=lambda: controller.show_frame("Main_frame"))
        self.volver.pack(padx=10, pady=30)
        self.volver.place(relx=0.05, rely=0.90)


class Sum_money_frame_error(Sum_money_frame):
    """Frame utilizado para mostar si ha habido algún error en la cantidad introducida de ingreso"""
    def __init__(self, master, controller):
        super().__init__(master, controller)
        self.wrong = customtkinter.CTkLabel(master=self,
                                            text="Cantidad incorrecta",
                                            text_color="red",
                                            font=("Century Gothic", 15))
        self.wrong.pack(padx=0, pady=0)
        self.wrong.place(relx=0.325, rely=0.425)


class Show_data_frame(customtkinter.CTkFrame):
    """Frame que enseña los datos del usuario por pantalla, concretamente:
        - Nombre de usuario
        - Email
        - Nombre
        - Apellido
        - Dinero """
    def __init__(self, master, controller, user, email, name, surname, money):
        super().__init__(master)
        self.controller = controller
        self.user_titulo = customtkinter.CTkLabel(master=self,
                                                  text="Usuario:",
                                                  text_color="black",
                                                  font=("Century Gothic", 20))
        self.user_titulo.pack(padx=10, pady=30)
        self.user_titulo.place(relx=0.15, rely=0.20)
        self.user = customtkinter.CTkLabel(master=self,
                                           text=user,
                                           text_color="black",
                                           font=("Century Gothic", 20))
        self.user.pack(padx=10, pady=30)
        self.user.place(relx=0.35, rely=0.20)
        self.email_titulo = customtkinter.CTkLabel(master=self,
                                                   text="E-mail:",
                                                   text_color="black",
                                                   font=("Century Gothic", 20))
        self.email_titulo.pack(padx=10, pady=30)
        self.email_titulo.place(relx=0.15, rely=0.275)
        self.email = customtkinter.CTkLabel(master=self,
                                            text=email,
                                            text_color="black",
                                            font=("Century Gothic", 20))
        self.email.pack(padx=10, pady=30)
        self.email.place(relx=0.325, rely=0.275)
        self.name_titulo = customtkinter.CTkLabel(master=self,
                                                  text="Nombre:",
                                                  text_color="black",
                                                  font=("Century Gothic", 20))
        self.name_titulo.pack(padx=10, pady=30)
        self.name_titulo.place(relx=0.15, rely=0.35)
        self.name = customtkinter.CTkLabel(master=self,
                                           text=name,
                                           text_color="black",
                                           font=("Century Gothic", 20))
        self.name.pack(padx=10, pady=30)
        self.name.place(relx=0.375, rely=0.35)
        self.surname_titulo = customtkinter.CTkLabel(master=self,
                                                     text="Apellido:",
                                                     text_color="black",
                                                     font=("Century Gothic", 20))
        self.surname_titulo.pack(padx=10, pady=30)
        self.surname_titulo.place(relx=0.15, rely=0.425)
        self.surname = customtkinter.CTkLabel(master=self,
                                              text=surname,
                                              text_color="black",
                                              font=("Century Gothic", 20))
        self.surname.pack(padx=10, pady=30)
        self.surname.place(relx=0.385, rely=0.425)
        self.money_titulo = customtkinter.CTkLabel(master=self,
                                                   text="Dinero:",
                                                   text_color="black",
                                                   font=("Century Gothic", 20))
        self.money_titulo.pack(padx=10, pady=30)
        self.money_titulo.place(relx=0.15, rely=0.5)
        self.money = customtkinter.CTkLabel(master=self,
                                            text=str(money) + " €",
                                            text_color="black",
                                            font=("Century Gothic", 20))
        self.money.pack(padx=10, pady=30)
        self.money.place(relx=0.35, rely=0.5)
        self.volver = customtkinter.CTkButton(master=self, text="Volver atrás", font=("Roboto", 25),
                                              width=200, height=50,
                                              command=lambda: controller.show_frame("Main_frame"))
        self.volver.pack(padx=10, pady=30)
        self.volver.place(relx=0.26, rely=0.65)


def register_user_gui(controller, user, pwd, name, surname1, email, money):
    """Función que recibe una serie de datos de nuevo usuario e intenta su registro en la bbdd"""
    # Solo si no encontramos el usuario en la bbdd
    if not db_management.search_user(user):
        # Comprobamos que la sintaxis de todos los datos es correcta de acuerdo a las reglas implementadas
        syntax = user_auth.check_username_syntax(user) and user_auth.check_pwd_syntax(pwd) and \
                 user_auth.check_names_syntax(name) and user_auth.check_names_syntax(surname1) and \
                 user_auth.check_email_syntax(email) and user_auth.check_money(money)
        if syntax:
            # Si es correcta se inserta y pasamos de nuevo al frame de inicio de sesión
            db_management.insert_new_user(user, pwd)
            db_management.insert_new_user_details(user, money, email, name, surname1)
            key = assymetric_management.generate_key(user)
            assymetric_management.certificate_request(user, key)
            controller.show_frame("Login_frame")
        else:
            # Si no lo es enseñamos el frame de error
            controller.show_frame("Register_frame_wrong")
    else:
        # Si el usuario ya existe, mostramos el frame de que ya existe el usuario
        controller.show_frame("Register_frame_ar")


def login_user_gui(controller, user, pwd):
    """Función que controla si un usuario puede o no iniciar sesión"""
    # Si se encuentra el usuario en la bbdd
    if db_management.search_user(user):
        try:
            # Verificamos que la contraseña introducida es la misma que la que se usó en el registro
            # usando para ello la derivación de la contraseña
            db_management.verify_user_password(user, pwd)
            try:
                assymetric_management.verify_certificate(user)
            except InvalidSignature:
                print("No se ha podido verificar el certificado de usuario")
                return None
            # Marcamos el usuario como el usuario actual
            global current_user
            current_user = user
            print("Certificado de usuario verificado. Acceso concedido")
            controller.show_frame("Main_frame")
        # Si no se puede verificar que la contraseña es la misma, se captura la excepción lanzada por Cryptography
        # y se muestra el frame de error
        except cryptography.exceptions.InvalidKey:
            controller.show_frame("Login_frame_error")
    else:
        # Si no se encuentra el usuario mostramos el frame de error
        controller.show_frame("Login_frame_error")


def borrar_usuario(controller):
    """Función para borrar el usuario actual de la bbdd"""
    global current_user
    db_management.delete_user(current_user)
    print(current_user)
    controller.destroy()


def modificar_dinero(controller, cantidad, operation_type):
    """Función que modifica el registro money de la bbdd en función de la operación realizada (ingreso o pago) y su
       cantidad"""
    global current_user
    # siempre y cuando se pueda verificar que la cantidad introducida es correcta
    if user_auth.check_money(cantidad):
        if operation_type == "ingreso":
            mensaje = "Usuario: " + current_user + ". Ingreso de " + str(cantidad) + " euros."
        else:
            mensaje = "Usuario: " + current_user + ". Retiro de " + str(cantidad) + " euros."
        firma = assymetric_management.signing(mensaje, current_user)
        try:
            assymetric_management.verify_signature(current_user, firma, mensaje)
        except InvalidSignature:
            print("No se ha podido verificar la transacción")
            return None
        print(mensaje)
        db_management.modify_money(current_user, cantidad, operation_type)
        # Buscar al usuario en user_info usando el current_user y actualizar su dinero
        controller.show_frame("Main_frame")
    else:
        # Si hay algún error con la cantidad introducida cambiamos al frame de error correspondiente
        if operation_type == "ingreso":
            controller.show_frame("Sum_money_frame_error")
        else:
            controller.show_frame("Withdraw_money_frame_error")
