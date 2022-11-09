import os
import pathlib

import pymongo
from flask import Flask, redirect, url_for, session, abort, jsonify, request
# from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from flask_pymongo import PyMongo
from pymongo import MongoClient
# from flask_oauthlib.client import OAuth


from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests

from flask_jwt_extended import JWTManager
import datetime

from flask_jwt_extended import JWTManager

from flask_mongoengine import MongoEngine

# from userauth import routes


# import app


app = Flask(__name__)

# app = Flask("ITCOTY")

jwt = JWTManager(app)


app.config["JWT_SECRET_KEY"] = "super-secret"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = datetime.timedelta(minutes=False) # (minutes=1500)




app.secret_key = "test"

# os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1" # !

# GOOGLE_CLIENT_ID = "408766048734-i932kcpfrd56jrb0v6d1oias0c4u5q7j.apps.googleusercontent.com"  # !
#
# client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json") # !


# oauth = OAuth(app)

# client = pymongo.MongoClient("mongodb+srv://admin:192168011@cluster0.f8yiv.mongodb.net/myFirstDatabase?retryWrites=true&w=majority")

# app.config['MONGODB_HOST']="mongodb+srv://admin:192168011@itcoty2.fx5qv.mongodb.net/myFirstDatabase?retryWrites=true&w=majority"

app.config['MONGODB_HOST']="mongodb+srv://admin:192168011@cluster0.f8yiv.mongodb.net/ITCOTY?retryWrites=true&w=majority"

# app.config["MONGO_URI"] = "mongodb://localhost:27017/DataBaza"
# mongodb_client = PyMongo(app)
# db = mongodb_client.db

db = MongoEngine(app)




# db = client.get_database('ITCOTY')




if __name__ == '__main__':
    app.run(host="localhost", debug=True)