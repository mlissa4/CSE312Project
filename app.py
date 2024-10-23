from flask import Flask, render_template, jsonify, request
from flask_security import UserMixin, RoleMixin, Security, MongoEngineUserDatastore
from flask_pymongo import PyMongo
from mongoengine import connect, Document
from utils.auth import *
from flask_security.utils import hash_password, verify_password
import os
from mongoengine.fields import (
    BinaryField,
    BooleanField,
    DateTimeField,
    IntField,
    ListField,
    ReferenceField,
    StringField,
)

app = Flask(__name__)

connect('user_auth', host='mongo', port=27017) #path is user_auth
app.config['MONGO_URI'] = 'mongodb://localhost:27017/user_auth' #go into user_auth collection
app.config["SECRET_KEY"] = "TEMP_KEY" #scecret key 
app.config["SECURITY_PASSWORD_SALT"] = "THIS SALT IS REDUNDANe" #Salt here is a seond layer of protect along with the first layer of salt 

mongo = PyMongo(app)

class Role(Document, RoleMixin):
    name = StringField(max_length=80, unique=True)
    description = StringField()
class User(Document, UserMixin):
    email = StringField(max_length=255,required=True,unique=True)
    password=StringField(required=True)
    active=BooleanField(default=True)
    fs_uniquifier = StringField(max_length=64, unique=True)
    roles = ListField(ReferenceField(Role), default=[])

user_datastore= MongoEngineUserDatastore(mongo.db,User,Role)
@app.route('/login', methods=["POST"]) #THIS LOGIN NEEDS TO BE HERE SO IT CAN OVER WRITE THE DEFAULT LOGIN PAGE GIVEN BY FLASK SECURITY
def login():
   
    username = request.form.get("login_username")
    password = request.form.get("login_password")
    user = user_datastore.find_user(email=username)
    if(username == "" or user == None):
        return jsonify({"error": "Username and fuck"}),404
    # if not bcrpyt.check_password_hash(user.password, password):
    if not verify_password(password, user.password):
        return jsonify({"error": "Invalid username or password"}), 404

    return jsonify({"correct": "pass"}), 200

Security = Security(app,user_datastore)
@app.after_request
def headerSecurity(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

@app.route('/')
def home():

    return render_template('index.html'), 200

@app.route('/login_page')
def login_page():
   
    return render_template('login.html'), 200

# RICO AND ERIC PLEASE USE SEPPERATE FILES FOR LOGGING IN AND REGISTERING
# TRY TO USE SOME LIBARIES!!!
# Redirect User to home screen on sucessfull login

print('something', flush=True)
@app.route('/register', methods=["POST"])
def register():

    username = request.form["username"]      # For form data (if the request is from a form submission)
    password = request.form["password"] 
    if not(auth_password(password)):
        return jsonify({"error": "password invalid"}), 404
    password = hash_password(password) #generates hashpassword that is salted by default (flask_security doc)
    user_datastore.create_user(email=username, password=password)
    user_datastore.commit()

    return f"{password}" #for testing should be removed 


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
