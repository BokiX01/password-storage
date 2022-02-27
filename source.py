from tkinter import *
from tkinter import messagebox
from json import load as j_load, dump as j_dump
from pickle import load as p_load, dump as p_dump
from hashlib import sha512
from os import getenv, mkdir
from cryptography.fernet import Fernet

root = Tk()
root.title('Password Storage')
root.iconbitmap('resources/icon.ico')

path = f'{getenv("APPDATA")}\\Password Storage\\security_key.txt'

try:
    mkdir(f'{getenv("APPDATA")}\\Password Storage')
    with open(path, 'wb') as f:
        p_dump(b'', f)
except FileExistsError:
    pass

try:
    open(path, 'r')
except FileNotFoundError:
    with open(path, 'wb') as f:
        p_dump(b'', f)

if p_load(open(path, 'rb')) == b'':
    with open(path, 'wb') as f:
        p_dump(Fernet.generate_key(), f)


class Security:
    @staticmethod
    def encrypt(password, key=b''):
        if key == b'':
            key = p_load(open(path, 'rb'))
        encrypted = Fernet(key).encrypt(password.encode())
        return encrypted

    @staticmethod
    def decrypt(password):
        key = p_load(open(path, 'rb'))
        decrypted = Fernet(key).decrypt(password.encode())
        return decrypted.decode()

    @staticmethod
    def hash(not_hashed):
        return sha512(not_hashed.encode()).hexdigest()


class ReadingAndWriting:
    passwords_to_read = j_load(open('resources/storage.json', 'r'))
    passwords = {'storage_login': {'username': passwords_to_read['storage_login']['username'],
                                   'password': passwords_to_read['storage_login']['password']},
                 'storage_passwords': {}}
    for application, info in passwords_to_read['storage_passwords'].items():
        for username, password in info.items():
            passwords['storage_passwords'][application] = {Security.decrypt(username): password}

    @staticmethod
    def writing(security_key=b''):
        with open('resources/storage.json', 'w') as f:
            passwords_to_write = {
                'storage_login': {'username': ReadingAndWriting.passwords['storage_login']['username'],
                                  'password': ReadingAndWriting.passwords['storage_login']['password']},
                'storage_passwords': {}}
            for application, info in ReadingAndWriting.passwords['storage_passwords'].items():
                for username, password in info.items():
                    passwords_to_write['storage_passwords'][application] = {
                        str(Security.encrypt(username, security_key))[1:]: password}
            j_dump(passwords_to_write, f, indent=2)


class Main:
    main_frame = Frame(root, padx=10, pady=10)
    main_frame.grid(row=0, column=0, padx=5, pady=5)

    options = [
        ('Generate new security key', 'generate'),
        ('Get password', 'get'),
        ('Add password', 'add'),
        ('Change password', 'change_password'),
        ('Change login info', 'change_login')
    ]
    defaultVar = StringVar()
    defaultVar.set('generate')

    class Login:
        @staticmethod
        def check_login():
            if ReadingAndWriting.passwords['storage_login']['username'] == '':
                Main.Login.register()
            else:
                Second.second_frame.grid_forget()
                Main.Login.login()

        @staticmethod
        def submit_register(username, password):
            if username != '' and password != '':
                ReadingAndWriting.passwords['storage_login']['username'] = Security.hash(username)
                ReadingAndWriting.passwords['storage_login']['password'] = Security.hash(password)
                ReadingAndWriting.writing()
                messagebox.showinfo('Info', 'Successfully saved.')
                Main.Login.check_login()
            else:
                messagebox.showerror('Error', 'You didn\'t fill all input fields!')

        @staticmethod
        def register():
            for widget in Main.main_frame.winfo_children():
                widget.grid_forget()
            Label(Main.main_frame, text='Register').grid(row=0, columnspan=2)

            Label(Main.main_frame, text='New username: ').grid(row=1, column=0)
            username_register = Entry(Main.main_frame, borderwidth=3)
            username_register.grid(row=1, column=1)

            Label(Main.main_frame, text='New password: ').grid(row=2, column=0)
            password_register = Entry(Main.main_frame, show='*', borderwidth=3)
            password_register.grid(row=2, column=1)

            Button(Main.main_frame, text='Submit',
                   command=lambda: Main.Login.submit_register(username_register.get(), password_register.get())).grid(
                row=3, columnspan=2)

        @staticmethod
        def login():
            def submit_login(username, password):
                if Security.hash(username) == ReadingAndWriting.passwords['storage_login']['username'] and \
                        Security.hash(password) == ReadingAndWriting.passwords['storage_login']['password']:
                    for widget in Main.main_frame.winfo_children():
                        widget.grid_forget()
                    widged_row = 1
                    for option_key, option_value in Main.options:
                        Radiobutton(Main.main_frame, text=option_key, variable=Main.defaultVar, value=option_value) \
                            .grid(row=widged_row, sticky=W)
                        widged_row += 1
                    Button(Main.main_frame, text='Confirm', command=lambda: Main.confirm(Main.defaultVar.get())) \
                        .grid(row=widged_row)
                else:
                    messagebox.showerror('Error', 'Wrong username or password!')

            for widget in Main.main_frame.winfo_children():
                widget.grid_forget()
            Label(Main.main_frame, text='Login').grid(row=0, columnspan=2)

            Label(Main.main_frame, text='Username: ').grid(row=1, column=0)
            username_login = Entry(Main.main_frame, borderwidth=3)
            username_login.grid(row=1, column=1)

            Label(Main.main_frame, text='Password: ').grid(row=2, column=0)
            password_login = Entry(Main.main_frame, show='*', borderwidth=3)
            password_login.grid(row=2, column=1)

            Button(Main.main_frame, text='Submit',
                   command=lambda: submit_login(username_login.get(), password_login.get())) \
                .grid(row=3, columnspan=2)

    @staticmethod
    def confirm(option_value):
        Second.second_frame.grid(row=0, column=1, padx=5, pady=5)
        for widget in Second.second_frame.winfo_children():
            widget.grid_forget()

        if option_value == 'generate':
            Label(Second.second_frame, text='Click "Refresh" to generate new security key.').grid(row=0)
            Button(Second.second_frame, text='Refresh', command=Second.generate).grid(row=1)

        elif option_value == 'get':
            menu_list = ['-- select application --']
            accounts_dict = {}
            default_var = StringVar()
            default_var.set(menu_list[0])

            for application, accounts in ReadingAndWriting.passwords['storage_passwords'].items():
                menu_list.append(application)
                for username, password in accounts.items():
                    accounts_dict[application] = {username: password}
            drop_menu = OptionMenu(Second.second_frame, default_var, *menu_list)
            drop_menu.grid(row=0, column=0)
            Button(Second.second_frame, text='Submit',
                   command=lambda: (Second.get(default_var.get(), accounts_dict), password_info.delete(0, END))) \
                .grid(row=0, column=1)

        elif option_value == 'add':
            Label(Second.second_frame, text='Application: ').grid(row=0, column=0)

            user_input_app_add = Entry(Second.second_frame, borderwidth=3)
            user_input_app_add.grid(row=0, column=1)
            Label(Second.second_frame, text='Username: ').grid(row=1, column=0)

            user_input_name_add = Entry(Second.second_frame, borderwidth=3)
            user_input_name_add.grid(row=1, column=1)
            Label(Second.second_frame, text='Password: ').grid(row=2, column=0)

            user_input_password_add = Entry(Second.second_frame, borderwidth=3)
            user_input_password_add.grid(row=2, column=1)
            Button(Second.second_frame, text='Submit',
                   command=lambda: Second.add(user_input_app_add.get(),
                                              user_input_name_add.get(),
                                              user_input_password_add.get())).grid(row=3, column=0)
            Button(Second.second_frame, text='Clear', command=lambda: Second.clear(option_value)).grid(row=3, column=1)

        elif option_value == 'change_password':
            menu_list = ['-- select application --']
            default_var = StringVar()
            default_var.set(menu_list[0])

            for application, accounts in ReadingAndWriting.passwords['storage_passwords'].items():
                menu_list.append(application)
            drop_menu = OptionMenu(Second.second_frame, default_var, *menu_list)
            drop_menu.grid(row=0, column=0)
            Button(Second.second_frame, text='Submit',
                   command=lambda: Second.change(default_var.get())).grid(row=0, column=1)

        elif option_value == 'change_login':
            Label(Second.second_frame, text='New username: ').grid(row=0, column=0)
            username_register = Entry(Second.second_frame, borderwidth=3)
            username_register.grid(row=0, column=1)

            Label(Second.second_frame, text='New password: ').grid(row=1, column=0)
            password_register = Entry(Second.second_frame, show='*', borderwidth=3)
            password_register.grid(row=1, column=1)
            Button(Second.second_frame, text='Change',
                   command=lambda: Main.Login.submit_register(username_register.get(), password_register.get())) \
                .grid(row=2, columnspan=2)

        else:
            messagebox.showerror('Error', 'You didn\'t select any option!')


class Second:
    second_frame = Frame(root, padx=10, pady=10)

    @staticmethod
    def generate():
        security_key = Fernet.generate_key()
        decrypted_passwords = {}

        if p_load(open(path, 'rb')) != b'':
            for application, accounts in ReadingAndWriting.passwords['storage_passwords'].items():
                for username, password in accounts.items():
                    decrypted_passwords[application] = {username: Security.decrypt(password)}

            for application, accounts in decrypted_passwords.items():
                for username, password in accounts.items():
                    ReadingAndWriting.passwords['storage_passwords'][application] = {
                        username: str(Security.encrypt(password, security_key))[1:]}
            ReadingAndWriting.writing(security_key)

        with open(path, 'wb') as key:
            p_dump(security_key, key)
        messagebox.showinfo('Info', 'You refreshed security key.')

    @staticmethod
    def get(menu_option, accounts_dict, username_info=''):
        def submit(menu_option, accounts_dict, username_info):
            if username_info != '':
                try:
                    Label(Second.second_frame, text='Password: ').grid(row=2, column=0)
                    global password_info
                    password_info = Entry(Second.second_frame, borderwidth=3)
                    password_info.grid(row=2, column=1)
                    password_info.insert(0, Security.decrypt(accounts_dict[menu_option].get(username_info, 'None')))
                    if password_info.get() == 'None':
                        messagebox.showerror('Error', 'Can\'t find the username!')
                except TypeError:
                    messagebox.showerror('Error', 'Can\'t find the username!')
            else:
                messagebox.showerror('Error', 'You didn\'t fill the username input field!')

        if menu_option != '-- select application --':
            Label(Second.second_frame, text='Username: ').grid(row=1, column=0)
            username_info = Entry(Second.second_frame, borderwidth=3)
            username_info.grid(row=1, column=1)
            Button(Second.second_frame, text='Search for password',
                   command=lambda: submit(menu_option, accounts_dict, username_info.get())).grid(row=3, columnspan=2)
        else:
            messagebox.showerror('Error', 'You didn\'t select any application!')

    @staticmethod
    def add(application, username, password):
        if application != '' and username != '' and password != '':
            if application in ReadingAndWriting.passwords:
                ReadingAndWriting.passwords['storage_passwords'][application.lower()] = {
                    username: str(Security.encrypt(password))[1:]}
            else:
                ReadingAndWriting.passwords['storage_passwords'][application.lower()] = {
                    username: str(Security.encrypt(password))[1:]}

            ReadingAndWriting.writing()
            messagebox.showinfo('Info', 'New password added successfully.')
        else:
            messagebox.showerror('Error', 'You didn\'t fill all input fields!')

    @staticmethod
    def change(application, username_info=''):
        def submit(application, username_info):
            def submit(application, username, password):
                ReadingAndWriting.passwords['storage_passwords'][application.lower()] = {
                    username: str(Security.encrypt(password))[1:]}
                ReadingAndWriting.writing()
                messagebox.showinfo('Info', 'Password changed successfully.')

            if username_info != '':
                Label(Second.second_frame, text='New password: ').grid(row=2, column=0)
                password_info_change = Entry(Second.second_frame, borderwidth=3)
                password_info_change.grid(row=2, column=1)
                Button(Second.second_frame, text='Change password',
                       command=lambda: submit(application, username_info, password_info_change.get())).grid(row=4,
                                                                                                            columnspan=2)
            else:
                messagebox.showerror('Error', 'You didn\'t fill the username input field!')

        Label(Second.second_frame, text='Username: ').grid(row=1, column=0)
        username_info = Entry(Second.second_frame, borderwidth=3)
        username_info.grid(row=1, column=1)
        confim_username = Button(Second.second_frame, text='Confirm username',
                                 command=lambda:
                                 (submit(application, username_info.get()),
                                  confim_username.grid_forget()))
        confim_username.grid(row=3, columnspan=2)

    @staticmethod
    def clear(option):
        for widget in Second.second_frame.winfo_children():
            widget.grid_forget()

        Main.confirm(option)


Main.Login.check_login()
mainloop()
