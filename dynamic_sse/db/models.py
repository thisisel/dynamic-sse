from pony import orm
import bcrypt

db =  orm.Database()


class User(db.Entity):
    username: str = orm.Required(str, max_len=15, unique=True)
    password_hash: str = orm.Required(str, min_len=10, max_len=15)

    files = set(lambda : Files)

    @property
    def password(self):
        raise AttributeError("Password is not a readable attribute")

    @password.setter
    def password(self, password: str):
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(
            password=password.encode(), salt=salt
        ).decode()

    def verify_password(self, password: str):
        return bcrypt.checkpw(
            password=password.encode(), hashed_password=self.password_hash.encode()
        )


class Files(db.Entity):
    file_id : bytes = orm.Required(bytes)
    enc_file_path: str = orm.Required(str)
    owner : User = orm.Required(User)
