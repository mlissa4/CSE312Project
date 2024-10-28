from flask import Flask, render_template, jsonify, request, redirect, Response, flash,send_file, abort
from flask_security import UserMixin, RoleMixin, Security, MongoEngineUserDatastore
from flask_pymongo import PyMongo
from pymongo import MongoClient
from mongoengine import connect, Document
from utils.auth import *
from flask_security.utils import hash_password, verify_password
import os
import secrets
import hashlib
import uuid
import html
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
posts_db = db["posts"]

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
    posts = list(posts_db.find())
    
    return render_template('index.html',posts=posts)


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

@app.route('/static/css/<filename>')
def serve_css(filename):
    return send_file(f'static/css/{filename}', mimetype=f'text/css')

@app.route('/static/js/<filename>')
def serve_js(filename):
    return send_file(f'static/js/{filename}', mimetype='text/javascript')

@app.route('/static/uploads/<filename>')
def serve_image(filename):
    file_extension = filename.split(".")[1]
    mime_types = {
        "jpg": "jpeg",
        "jpeg": "jpeg",
        "png": "png",
        "gif": "gif",
    }
    mimetype = mime_types[file_extension]
    if mimetype == None:
        abort(404)
    return send_file(f'static/uploads/{filename}', mimetype=f'image/{mimetype}')

@app.route('/static/images/<filename>')
def serve_image2(filename):
    file_extension = filename.split(".")[1]
    mime_types = {
        "jpg": "jpeg",
        "jpeg": "jpeg",
        "png": "png",
        "gif": "gif",
    }
    mimetype = mime_types[file_extension]
    if mimetype == None:
        abort(404)
    return send_file(f'static/images/{filename}', mimetype=f'image/{mimetype}')

@app.route('/upload', methods=['POST'])
def upload_image():

    cookie_auth = request.cookies.get("auth_token")
    if cookie_auth:
        hash_cookie_auth = hashlib.sha256(cookie_auth.encode()).hexdigest()
        User = auth.find_one({"auth_token": hash_cookie_auth})
    if not User:
        flash('Error: Not Logged In')
        return redirect("/", code=302)
    
    
    image = request.files['image']
    filetype = image.filename.split(".")[1]
    description = html.escape(request.form['description'])

    if not image.filename.endswith(('.png', '.jpg', '.jpeg', '.gif')):
        flash('Error: incorect image format')
        return redirect("/", code=302)

    if not image and not description:
        flash('Error: Image and description are required!')
        return redirect("/", code=302)
    image_filename = f"image_{uuid.uuid4()}.{filetype}"
    image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
    cookie_auth = request.cookies.get("auth_token")
    if cookie_auth:
        hash_cookie_auth = hashlib.sha256(cookie_auth.encode()).hexdigest()
        finding = auth.find_one({"auth_token": hash_cookie_auth})
    author = User["username"]
    print(f"AUTHOR === {author}")
    Reviewers = []
    Reviewers.append(author)
    data = {
        "file_name": image_filename,
        "Description": description,
        "Author": author,
        "Total_rating": 5,
        "reviews": 1,
        "Average_rating": 5,
        "Reviwers": Reviewers

    }
    posts_db.insert_one(data)
    files_in_upload_folder = os.listdir(app.config['UPLOAD_FOLDER'])
    print("Files in the upload folder:")
    for file in files_in_upload_folder:
        print(file)
    for thing in posts_db.find():
        print(thing)

        #Redirect back to the homepage or another route
    return redirect("/", code=302)
    



@app.route('/post_redirect', methods=["GET"])
def post_redirect():
    #if auth_token valid, redirect to /post_screen
        #hash auth token and check if hashed token exists in db
    #if not, error 401 unauthorized
    cookie_auth = request.cookies.get("auth_token")
    if cookie_auth:
        hash_cookie_auth = hashlib.sha256(cookie_auth.encode()).hexdigest()
        finding = auth.find_one({"auth_token": hash_cookie_auth})
        if finding:
            return redirect("/post_screen",code=302)

    return Response("Unauthorized", status=401)
 

#need to build post_screen.html
@app.route('/post_screen')
def post_screen():
    return render_template('post_screen.html'), 200

@app.route('/review/<file>', methods = {"GET","POST"})
def review_page(file):
    cookie_auth = request.cookies.get("auth_token")
    User = None
    if cookie_auth:
        hash_cookie_auth = hashlib.sha256(cookie_auth.encode()).hexdigest()
        User = auth.find_one({"auth_token": hash_cookie_auth})
    if not User:
        return Response("Not Logged in", status=401)
    post = posts_db.find_one({"file_name":file})
    Reviwers = post["Reviwers"]
    if User["username"] in Reviwers:
        return Response("Already Reviewed", status=401)
    if request.method == "GET":
        return render_template('review_page.html',post=post), 200
    if request.method == "POST":
        print("GETING REVIEW !!!!!!!!!!!!!!!!")
        print(f"Reviwers BEFORE {Reviwers}")
        print(f"USER THAT MADE REVIEW {User['username']}")
        rating = int(request.form.get('rating'))
        total_rating = post.get('Total_rating', 0) + rating
        review_count = post.get('reviews', 0) + 1
        average_rating = round(total_rating/review_count,1)
        Reviwers.append(User["username"])
        print(f"Reviwers AFTER {Reviwers}")
        posts_db.update_one({"file_name":file},{"$set": {"Total_rating": total_rating, "Average_rating": average_rating, "reviews": review_count, "Reviwers":Reviwers }})
        return redirect("/",code=302)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
