from flask import Flask, render_template, jsonify, request, redirect, Response
from flask_security import UserMixin, RoleMixin, Security, MongoEngineUserDatastore
from flask_pymongo import PyMongo
from pymongo import MongoClient
from mongoengine import connect, Document
from utils.auth import *
from flask_security.utils import hash_password, verify_password
import os
import secrets
import hashlib
from mongoengine.fields import (
    BinaryField,
    BooleanField,
    DateTimeField,
    IntField,
    ListField,
    ReferenceField,
    StringField,
)


mongo_clinet = MongoClient('mongo')
db = mongo_clinet["user_auth"]
auth= db["auth"] #to access this database is the same way you do for the homework 

app = Flask(__name__)

connect('user_auth', host='mongo', port=27017) #path is user_auth
app.config['MONGO_URI'] = 'mongodb://localhost:27017/user_auth' #go into user_auth collection
app.config["SECRET_KEY"] = os.getenv("secret_key") #scecret key 
app.config["SECURITY_PASSWORD_SALT"] = os.getenv("salt") #Salt here is a seond layer of protect along with the first layer of salt 

UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

mongo = PyMongo(app)
#Don't worry about this part, is from a library documentation
#read more about it on flasksecurity website https://flask-security-too.readthedocs.io/en/stable/
class Role(Document, RoleMixin): 
    name = StringField(max_length=80, unique=True)
    description = StringField()
class User(Document, UserMixin):
    email = StringField(max_length=255,required=True,unique=True) #username
    password=StringField(required=True) #password
    active=BooleanField(default=True) #active
    fs_uniquifier = StringField(max_length=64, unique=True) #another check to see if the user is unique
    roles = ListField(ReferenceField(Role), default=[]) #roles user admin, etc(will not be used yet)

user_datastore= MongoEngineUserDatastore(mongo.db,User,Role)

@app.route('/login', methods=["POST"]) #THIS LOGIN NEEDS TO BE HERE SO IT CAN OVER WRITE THE DEFAULT LOGIN PAGE GIVEN BY FLASK SECURITY
def login():
   
    username = request.form.get("login_username")
    password = request.form.get("login_password")
    user = user_datastore.find_user(email=username)
    if(username == "" or user == None):
        return jsonify({"error": "Invalid Username"}),404
    # if not bcrpyt.check_password_hash(user.password, password):
    if not verify_password(password, user.password):
        return jsonify({"error": "Invalid username or password"}), 404
    auth_token = secrets.token_hex(32)
    hash_auth_token = hashlib.sha256(auth_token.encode()).hexdigest()
    auth.insert_one({"username": username, "auth_token": hash_auth_token})
    response = Response(status=302,headers={"Location":"/"})
    response.set_cookie("auth_token",auth_token,httponly=True, max_age=360000)
    return response
#logout
@app.route('/logout', methods=["POST"]) #this also must be before startup of security
def logout():
    
    cookie_auth = request.cookies.get("auth_token") #get auth_token
    if(cookie_auth != None):
        hash_cookie_auth = hashlib.sha256(cookie_auth.encode()).hexdigest() #hash to compare in database
    finding = auth.find_one({"auth_token":hash_cookie_auth})
    if(finding != None): #test to see if the auth_token is legit
        auth.delete_one({"auth_token":hash_cookie_auth}) #delete the auth_token by setting expires to 0
    response = Response(status=302,headers={"Location":"/"})
    response.set_cookie("auth_token","",httponly=True, expires=0) 
    return response
    
Security = Security(app,user_datastore) #start up flask security
@app.after_request
def headerSecurity(response): # make sure every response has nosniff (global)
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

@app.route('/')
def home():
    # List all files in the uploads folder
    files_in_upload_folder = os.listdir(app.config['UPLOAD_FOLDER'])
    
    # Filter only image files (e.g., .png, .jpg, .jpeg, .gif)
    image_files = [f for f in files_in_upload_folder if f.endswith(('.png', '.jpg', '.jpeg', '.gif'))]

    #Pass the image filenames to the template
    return render_template('index.html',images=image_files)
@app.route('/login_page')
def login_page():
    return render_template('login.html'), 200

# RICO AND ERIC PLEASE USE SEPPERATE FILES FOR LOGGING IN AND REGISTERING
# TRY TO USE SOME LIBARIES!!!
# Redirect User to home screen on sucessfull login

#register
@app.route('/register', methods=["POST"]) 
def register():

    username = request.form["username"]# For form data (if the request is from a form submission)
    password = request.form["password"] 
    if not(auth_password(password)):
        return jsonify({"error": "password invalid"}), 404
    password = hash_password(password) #generates hashpassword that is salted by default (flask_security doc)
    user_datastore.create_user(email=username, password=password) #create a user (syntax will be used once to make flask secuurity work)
    user_datastore.commit()
    return redirect("/login_page",code=302)




@app.route('/upload', methods=['POST'])
def upload_image():
    # Get the uploaded image file
    image = request.files['image']
    description = request.form['description']

    if image and description:
        # Save the image to the specified upload folder
        image_filename = image.filename
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))

        # Print the description
        print(f"Description: {description}")

        # List all files in the upload folder and print them to the console
        files_in_upload_folder = os.listdir(app.config['UPLOAD_FOLDER'])
        print("Files in the upload folder:")
        for file in files_in_upload_folder:
            print(file)

            #Redirect back to the homepage or another route
        return redirect("/", code=302)
    else:
        return 'Error: Image and description are required!'


#route to post
@app.route('/post_screen', methods=["GET"])
def post_redirect():
    #if auth_token valid, redirect to /post_screen
        #hash auth token and check if hashed token exists in db
    #if not, error 401 unauthorized
    return render_template('post_screen.html'), 200
    return redirect("/post_screen",code=302)

#need to build post_screen.html
@app.route('/post_screen')
def post_screen():

    return render_template('post_screen.html'), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
