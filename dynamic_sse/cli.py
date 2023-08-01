import os
from db import db, User

class SSEFeatures:
    @staticmethod
    def innit():
        pass

    @staticmethod
    def search():
        pass

    @staticmethod
    def add():
        pass

    @staticmethod
    def delete():
        pass

class UserOptions:
    @staticmethod
    def change_username():
        pass

    @staticmethod
    def change_password():
        pass


def new_user_dashboard():
    print("1. innit")
    print("2. change username")
    print("3. change password")

    opt = int(input("option"))
    #switch case

    
def user_dashboard():
    print("1. search")
    print("2. add")
    print("3. delete")
    print("4. change username")
    print("5. change password")
    
    opt = int(input("option"))
    #switch case


def gateway():
    db.bind(provider='sqlite', filename='database.sqlite', create_db=True)
    db.generate_mapping(create_tables=True)

    print("Dynamic-SSE")
   
    username : str = os.getenv('USER')
    user : User = User.select(lambda u: u.username == username)

    if not user:
        password = input("enter your password")
        user = User(username=username, password=password)

