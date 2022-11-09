import os
import pathlib
from json import dumps

from flask_pymongo import PyMongo

from userauth.models import User


import pymongo
from flask import Flask, redirect, url_for, session, abort, jsonify, request
# from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from pymongo import MongoClient
# from flask_oauthlib.client import OAuth


from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests

from ITCOTY2 import app, jwt
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity

import requests


# app.config['MONGODB_URI']="mongodb+srv://admin:192168011@itcoty2.fx5qv.mongodb.net/myFirstDatabase?retryWrites=true&w=majority"

app.config["MONGO_URI"] = "mongodb+srv://admin:192168011@cluster0.f8yiv.mongodb.net/ITCOTY?retryWrites=true&w=majority"


mongodb_client = PyMongo(app)
db = mongodb_client.db



@jwt.user_identity_loader
def user_identity_lookup(id):
    return id


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.objects(id=identity).first()


@app.route("/register", methods=["POST"])
def register():
    record = request.get_json()
    email = record["email"]
    password = record["password"]

    if not (email and password):
        return jsonify("Please enter email and password")
    all_emails = [i['email'] for i in db.userscollection.find()]
    if email in all_emails:
        return jsonify("Email already in use")
    else:
        hashed_password = generate_password_hash(password)
        db.userscollection.insert({"email": email, "password": hashed_password, "cvs": []})
    return jsonify("User registered succesfully!"), 200


@app.route("/login", methods=["POST"])
def login():
    record = request.get_json()
    email = record["email"]
    password = record["password"]
    if not (email and password):
        return jsonify("Please enter email and password")
    current_user = db.userscollection.find_one({"email": email})
    if not current_user:
        return jsonify("User doesn't exists in database")
    elif not check_password_hash(current_user["password"], password):
        return jsonify("Incorrect password!"), 401
    # access_token = create_access_token(dumps(str(current_user["_id"])))
    access_token = create_access_token(identity=str(current_user["_id"]))

    # return jsonify(access_token=access_token.decode("utf-8"))
    return jsonify(message="Login success!", access_token=access_token)


@app.route('/')
def hello_world():
    str_name = session.get('name')
    if str_name is not None:
        return f"Hello, {str_name}, in ITCOTY <br><br><br> <a href='/user/logout'><button>Logout</button><br><br><br></a> "
    return f"ITCOTY! <br><br><br>" \
           "<a href='/user/login'><button>LOGIN WITH EMAIL </button></a><br><br><br>"\
           "<a href='/user/google_login'><button>LOGIN WITH GOOGLE</button></a><br><br><br>" \
           "<a href='/user/fb_login'><button>LOGIN WITH FACEBOOK</button></a><br><br><br>" \
           "<a href='/user/in_login'><button>LOGIN WITH LINKEDIN</button></a><br><br><br>"


"""ЛОГИН/ЛОГАУТ ЧЕРЕЗ ГУГЛ АККАУНТ"""


os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = "408766048734-i932kcpfrd56jrb0v6d1oias0c4u5q7j.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)
# redirect_uri - нужно заменить на "https://ITCOTY2.herokuapp.com/callback" или "http://127.0.0.1:5000/callback" для локал хост


@app.route("/user/google_login")
def login_google():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)



@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )
# в переменной id_info лежит все что может дать гугл аккаунт
#     session["google_id"] = id_info.get("sub")
#     session["name"] = id_info.get("name")
#     session["email"] = id_info.get("email")
    registration_type = 'google'
    user = User.objects(email=id_info.get("email"), registration_type=registration_type).first()
    if not user:
        save_user(id_info.get("name"), id_info.get("email"), registration_type)
    user = User.objects(email=id_info.get("email"), registration_type=registration_type).first()
    access_token = create_access_token(identity=str(user.id))
    session["access_token"] = access_token
    session["login"] = user.login + ' from Google Account'
    return f"""
    User information: <br>
    Name: {id_info.get("name")} <br>
    Email: {id_info.get("email")} <br>
    <a href="/"><button>HOME</button></a><br><br><br>
    <a href="/user/logout"><button>LOGOUT</button>
    """


# def save_user(email, registration_type, password=None):
def save_user(login, email, registration_type, password=None):
    if password is None:
        user = User(
            email=email,
            login=login,
            registration_type=registration_type
        )
    else:
        user = User(
            password=generate_password_hash(password),
            email=email,
            login=login,
            registration_type=registration_type
        )
    user.save()
    return jsonify(user.to_json())


# @app.route('/user/all', methods=['GET'])
# @jwt_required()
# def query_records():
#     print("Hello world!")

@app.route('/user/all', methods=['GET'])
@jwt_required()
def query_records():
    users = User.objects()
    # current_user = get_jwt_identity()
    # password = current_user.password
    if not users:
        return jsonify({'error': 'data not found'})
    return jsonify(list(map(lambda user: user.to_json(), users)))
