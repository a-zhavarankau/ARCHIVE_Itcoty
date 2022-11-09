import mongoengine
from mongoengine import Document, StringField


class User(Document):
    email = StringField(required=True)
    login = StringField(required=True)
    password = StringField()
    registration_type = StringField(required=True)
    meta = {"collection": "userscollection"}

    def to_json(self):
        return {
            "email": self.email,
            "login": self.login,
            "id": str(self.pk)
        } 
