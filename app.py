from flask import Flask, render_template, jsonify, request, redirect, Response, flash,send_file, abort, make_response
from flask_security import UserMixin, RoleMixin, Security, MongoEngineUserDatastore
from flask_pymongo import PyMongo
from pymongo import MongoClient
from mongoengine import NotUniqueError
from mongoengine import connect, Document
from utils.auth import *
from html import escape
from flask_socketio import SocketIO, emit
from flask_security.utils import hash_password, verify_password
import os
import secrets
import hashlib
import uuid
import html
import pytz
import time
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
from PIL import Image, ImageSequence
from profilepage import serve_profile_page, profile_bp
from mongoengine.fields import (
    BinaryField,
    BooleanField,
    DateTimeField,
    IntField,
    ListField,
    ReferenceField,
    StringField,
)

# Set timezone to EST
est = pytz.timezone('America/New_York')
mongo_clinet = MongoClient('mongo')
db = mongo_clinet["user_auth"]
auth= db["auth"] #to access this database is the same way you do for the homework 
posts_db = db["posts"] #storage of image name 
name_counter = db["counter"] #might use but we keeping the image/gif uuid random
dm_message = db["dm"] #dm storage
app = Flask(__name__)
socketio = SocketIO(app, threaded=True) #sockets with multi threading
user_online = {} #storage of all the active members
blocked_list = {}
text_key_master = {}
connect('user_auth', host='mongo', port=27017) #path is user_auth
app.config['MONGO_URI'] = os.getenv("MONGO_URI", "mongodb://localhost:27017/user_auth")#go into user_auth collection
app.config["SECRET_KEY"] = os.getenv("secret_key") #scecret key is just a random hex can be changed to anything
app.config["SECURITY_PASSWORD_SALT"] = os.getenv("salt") #  seond layer of salt along with the first layer of salt using brcypt is just a random hex can be changed to anything
app.config['SECURITY_REGISTERABLE'] = False
app.config['SESSION_PROTECTION'] = None
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.register_blueprint(profile_bp)
limiter = Limiter( key_func=get_remote_address, app=app)

mongo = PyMongo(app)
#Don't worry about this part, is from a library documentation
#read more about it on flasksecurity website https://flask-security-too.readthedocs.io/en/stable/
class Role(Document, RoleMixin): 
    name = StringField(max_length=40, unique=True)
    description = StringField()
class User(Document, UserMixin):
    email = StringField(max_length=40,required=True,unique=True) #username
    password=StringField(required=True) #password
    pfp = StringField(default='static/images/default_pfp.jpg')
    active=BooleanField(default=True) #active
    fs_uniquifier = StringField(max_length=64, unique=True) #another check to see if the user is unique
    roles = ListField(ReferenceField(Role), default=[]) #roles user admin, etc(will not be used yet)

user_datastore = MongoEngineUserDatastore(mongo.db,User,Role)

@app.route('/login', methods=["GET","POST"]) #THIS LOGIN NEEDS TO BE HERE SO IT CAN OVER WRITE THE DEFAULT LOGIN PAGE GIVEN BY FLASK SECURITY
def login():
   
    username = request.form.get("login_username")
    # username = html.escape(username)
    password = request.form.get("login_password")
    user = user_datastore.find_user(email=username)
    if(username == "" or user == None):
        flash("incorrect password or username", "login")
        return redirect("/login_page",code=302)
    # if not bcrpyt.check_password_hash(user.password, password):
    if not verify_password(password, user.password):
        flash("incorrect password or username", "login")
        return redirect("/login_page",code=302)
    auth_token = secrets.token_hex(32)
    hash_auth_token = hashlib.sha256(auth_token.encode()).hexdigest()
    auth.insert_one({"username": username, "auth_token": hash_auth_token})
    response = Response(status=302,headers={"Location":"/"})
    response.set_cookie("auth_token",auth_token,httponly=True, max_age=360000, secure=True)
    return response
#logout
@app.route('/logout', methods=["GET","POST"]) #this also must be before startup of security
def logout():
    
    cookie_auth = request.cookies.get("auth_token") #get auth_token
    hash_cookie_auth =""
    if(cookie_auth != None):
        hash_cookie_auth = hashlib.sha256(cookie_auth.encode()).hexdigest() #hash to compare in database
    else:
        return Response(status=302,headers={"Location": "/"})
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
@limiter.limit("50 per 10 seconds")
def home():
    user_name = "Please Login"
    cookie_auth = request.cookies.get("auth_token") #get auth_token
    hash_cookie_auth = ""
    if(cookie_auth != None):
        hash_cookie_auth = hashlib.sha256(cookie_auth.encode()).hexdigest() #hash to compare in database
    finding = auth.find_one({"auth_token":hash_cookie_auth})
    if(finding != None): #test to see if the auth_token is legit
        user_name = finding["username"]
    posts_db.delete_many({"expiration_datetime": {"$lt": datetime.now(est)}})
    posts = list(posts_db.find())
    return render_template('index.html',posts=posts, username= user_name+"!")

@app.errorhandler(429)
def limited(error):
    ip = get_remote_address()
    if ip not in blocked_list:
        blocked_list[ip] = time.time()
    return "Uh Oh! Too Many Requests, Please wait 30 secs.", 429

@app.before_request
def blocking():
    ip = get_remote_address()
    time_now = time.time()
    if ip in blocked_list:
        ip_time = blocked_list[ip]
        if (30 > (time_now - ip_time)):
            return "Uh Oh! Too Many Requests, Please wait 30 secs.", 429
        else:
            blocked_list.pop(ip)
            



@app.route('/login_page')
def login_page():
    return render_template('login.html'), 200

# TRY TO USE SOME LIBARIES!!!
# Redirect User to home screen on sucessfull login

#register
@app.route('/register', methods=["POST"]) 
def register():
    username = request.form["username"]# For form data (if the request is from a form submission)
    # username = html.escape(username)
    password = request.form["password"]
    default_pfp = os.path.join('static', 'images', 'default_pfp.jpg') 
    confirm_password= request.form["confirm_password"]
    if len(username) >=16:
        flash("username too long, please try again", "register")
        return redirect("/login_page",code=302)
    if not(auth_password(password)):
        flash("password is not secure, please try again", "register")
        return redirect("/login_page",code=302)
    if (confirm_password != password):
        flash("password does not match, please try again", "register")
        return redirect("/login_page",code=302)
    password = hash_password(password) #generates hashpassword that is salted by default (flask_security doc)
    try:
        user_datastore.create_user(email=username, password=password, pfp=default_pfp) #create a user (syntax will be used once to make flask secuurity work)
        user_datastore.commit()
    except NotUniqueError:
        flash("username is already taken , please try again", "register")
        return redirect("/login_page",code=302)
    flash("Successful! Please login", "register")
    return redirect("/login_page",code=302)

@app.route('/static/css/<filename>')
def serve_css(filename):
    response = make_response(send_file(f'static/css/{filename}'))
    response.headers['Content-Type'] = 'text/css'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

@app.route('/static/js/<filename>')
def serve_js(filename):
    response = make_response(send_file(f'static/js/{filename}'))
    response.headers['Content-Type'] = 'text/javascript'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

@app.route('/static/images/<filename>')
def kitty_image(filename):
    file_path = os.path.join('static', 'images', filename)
    if not os.path.exists(file_path):
        abort(404, description="File not found")
    response = make_response(send_file(file_path))
    response.headers['Content-Type'] = 'image/jpeg'  # Adjust Content-Type if necessary
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

@app.route('/static/uploads/<filename>')
def serve_image(filename):
    print("file_extension", filename)
    file_extension = filename.split(".")[1]

    mime_types = {
        "jpg": "jpeg",
        "jpeg": "jpeg",
        "png": "png",
        "gif": "gif",
    }

    mimetype = mime_types.get(file_extension)
    if mimetype is None:
        abort(404)

    response = make_response(send_file(f'static/uploads/{filename}'))
    response.headers['Content-Type'] = f'image/{mimetype}'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

@app.route("/delete/<id>", methods=["POST"])
def delete(id):
    from bson.objectid import ObjectId
    posts_db.delete_one({"_id": ObjectId(id)})
    return redirect('/profile')



#uploading images/video to the site 
@app.route('/static/images/<filename>')
def serve_image2(filename):
    file_extension = filename.rsplit(".")[1].lower()

    mime_types = {
        "jpg": "jpeg",
        "jpeg": "jpeg",
        "png": "png",
        "gif": "gif",
    }

    mimetype = mime_types.get(file_extension)
    if mimetype is None:
        abort(404)

    response = make_response(send_file(f'static/images/{filename}'))
    response.headers['Content-Type'] = f'image/{mimetype}'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

#create custom name for each uploaded image/video
def custom_name():
    retur == None
    retur = name_counter.find_one({"counter": "counter"})
    if retur == None : 
        retur.insert_one({"counter": "counter", "number":"1"})
        name = "image_1"
    else:
        number = int(retur["number"])
        number += 1
        retur.replace_one({"counter":"counter", "number": str(number)})
        return "image_" + str(number)

#check the signature of the image/video
def sign_checker(img_sign):
    sign_dict = {
        "jpeg": ["FFD8FF", "FFD8FFE000104A46", "49460001", "FFD8FFEE", "FFD8FFE1????4578", "69660000", "FFD8FFE0"],
        "png" : ["89504E470D0A1A0A"],
        "gif" : ["474946383761", "474946383961"]

    }
    for sign in sign_dict:
        sign_list = sign_dict[sign]
        for signature in sign_list:
            if(img_sign.startswith(signature)):
                return sign
    return ""
@app.route('/upload', methods=['POST'])
def uploadimage():
    User = None
    cookie_auth = request.cookies.get("auth_token")
    if cookie_auth:
        hash_cookie_auth = hashlib.sha256(cookie_auth.encode()).hexdigest()
        User = auth.find_one({"auth_token": hash_cookie_auth})
    if User == None:
        flash('Error: Not Logged In')
        return redirect("/", code=302)


    image = request.files['image']
    print("image info", image)
    filetype = ""
    filetype = image.filename.split(".")[1]
    filetype = image.filename.split(".")[1]
    img_sign = image.stream.read(14)
    img_sign = img_sign.hex().upper()
    image.stream.seek(0)
    filetype = sign_checker(img_sign)

    description = request.form['description']
    print("filetype: ", filetype)
    if filetype == "":
            print("kicked out")
            return redirect("/", code=302)

    if not image and not description:
        flash('Error: Image and description are required!')
        return redirect("/", code=302)
    image_filename = f"image_{uuid.uuid4()}.{filetype}"
    
    with Image.open(image.stream) as img:
        width, height = img.size
        ratio = 0
        path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
        if (filetype != "gif"): #resize non gifs
            if(height < width):
                ratio = width/height
                width = 300
                height = round(300/ratio)
                resize = img.resize((width, height))
                resize.save(path)
            else:
                ratio = height/width
                height = 300
                width = round(300/ratio)
                resize = img.resize((width, height))
                resize.save(path)
        else: #resizing gifs
            frames = ImageSequence.Iterator(img)
            new_frames = []
            if(height < width):
                ratio = width/height
                height = round(300/ratio)
                width = 300
            else:
                ratio = height/width
                height = 300
                width = round(300/ratio)
            for frame in frames:
                resize = frame.resize((width, height))
                new_frames.append(resize)
            new_frames[0].save(path, save_all=True, append_images=new_frames[1:])
                



    cookie_auth = request.cookies.get("auth_token")
    if cookie_auth:
        hash_cookie_auth = hashlib.sha256(cookie_auth.encode()).hexdigest()
        finding = auth.find_one({"auth_token": hash_cookie_auth})
    author = User["username"]
    print(f"AUTHOR === {author}")
    Reviewers = []
    Reviewers.append(author)

    # Experation time
    expiration_time = float(request.form['expiration_time'])
    print(f"EXPERATION TIME = {expiration_time}")
    if expiration_time == 0:
        expiration_datetime = None  # Indicating a post that never expires
    else:
        expiration_datetime = datetime.now(est) + timedelta(hours=expiration_time)

    print(f"Current Time (EST): {datetime.now(est)}")
    print(f"Expiration Time (EST): {expiration_datetime}")

    user = user_datastore.find_user(email=author)
    data = {
        "file_name": image_filename,
        "Description": description,
        "Author": author,
        "Total_rating": 5,
        "reviews": 1,
        "Average_rating": 5,
        "Reviwers": Reviewers,
        "expiration_datetime": expiration_datetime,
        "Author_PFP": user["pfp"]

    }

    posts_db.insert_one(data)
    print("printing db entries")
    for entry in posts_db.find():
        print(entry)

    #Redirect back to the homepage or another route
    return redirect("/", code=302)
    

#user_list page
@app.route('/user_list', methods=["GET"]) 
def user_list():
    cookie_auth=request.cookies.get("auth_token")
    finding = None
    if cookie_auth: #check for if there is auth_cookies
        hash_cookie_auth = hashlib.sha256(cookie_auth.encode()).hexdigest()
        finding = auth.find_one({"auth_token": hash_cookie_auth})
        if finding: #if auth_cookie is valid 
            users = User.objects.all()
            all_users = [user.email for user in users] #all registered usernames
            for user in all_users:
                if(user != finding["username"]):
                    flash(f"{user}")
            return render_template("user_list.html")
        else: #if auth cookie is not valid
          flash("Please login to use DM feature", "post_permission") 
          return redirect("/", code=302)  
    else:
        flash("Please login to use DM feature", "post_permission") 
        return redirect("/", code=302)

@app.route('/direct_message/<username>', methods=["GET", "POST"])
def direct_message(username):
    cookie_auth = request.cookies.get("auth_token")
    finding = None
    if cookie_auth:
        hash_cookie_auth = hashlib.sha256(cookie_auth.encode()).hexdigest()
        finding = auth.find_one({"auth_token": hash_cookie_auth})
        if finding:
            sender_username = finding["username"]
            print("finding of reciever username: ", username)
            global_reciever = username
            key = message_finder(sender_username, username)
            if(key == None):
                text_key_master[sender_username+username] = [sender_username, username]
                dm_message.insert_one({"key":sender_username+username, "message_list": [[]]})
            return render_template('direct_message.html', username=username)

        else:
            flash("Please login to send a DM", "post_permission")
            return redirect("/", code=302)
    else:
        flash("Please login to send a DM", "post_permission")
        return redirect("/", code=302)


def message_finder(sender, reciever):
    messages_object = None
    key = sender+reciever
    messages_object = dm_message.find_one({"key":key})
    
    if(messages_object == None):
        key= reciever+sender
        messages_object = dm_message.find_one({"key":key})
    if(messages_object == None):
        return None
    text_key_master[key] = [sender,reciever]
    return key

#called when socket is established    
@socketio.on("connect")
def activity_adder():
    print("reached ")
    cookie_auth=request.cookies.get("auth_token")
    finding = None
    username = ""
    reciever_username = request.args.get("username")
    if cookie_auth:
        hash_cookie_auth = hashlib.sha256(cookie_auth.encode()).hexdigest()
        finding = auth.find_one({"auth_token": hash_cookie_auth})
        
        if finding: #if auth_cookie is valid 
            username = finding["username"]
            if (username not in user_online):
                user_online[username] = [request.sid]
            
            else:
                temp = user_online[username]
                temp.append(request.sid)
                user_online[username] = temp
            if(reciever_username != None):
                key = message_finder(reciever_username, username)
                message_object = dm_message.find_one({"key": key})
                print("message_oject type: ", message_object)
                for text in message_object["message_list"]:
                    if(len(text) != 0):
                        
                        socketio.emit("message", {"username":text[0], "message":text[1], "recipient":reciever_username, "key":key, "dict": text_key_master }, room=request.sid)
                
        else:
            return redirect("/", code=302)
    else:
        return redirect("/", code=302)

#called when socket is disconnected (will be deleted from active user)
@socketio.on('disconnect')
def websocket_disconnect():
    print("disconnect is triggered")
    cookie_auth=request.cookies.get("auth_token")
    finding = None
    username = ""
    if cookie_auth:
        hash_cookie_auth = hashlib.sha256(cookie_auth.encode()).hexdigest()
        finding = auth.find_one({"auth_token": hash_cookie_auth})
        if finding: #if auth_cookie is valid 
            username = finding["username"]
            sids = user_online[username]
            sids = sids.remove(request.sid)
            
        else: 
            return redirect("/", code=302)
    else: 
        return redirect("/", code=302)

@socketio.on("send_message")
def handle_messages(message_data):
    print("reached new_message")
    cookie_auth = request.cookies.get("auth_token")
    finding = None
    sender_username = ""
    if cookie_auth: 
        hash_cookie_auth = hashlib.sha256(cookie_auth.encode()).hexdigest()
        finding = auth.find_one({"auth_token": hash_cookie_auth})
        if finding:
            sender_username = finding["username"]
            reciever = message_data.get("username")
            print("activity in send_message: ", user_online)
            sender_lis = user_online[sender_username]
            key = message_finder(sender_username, reciever)
            message_object = dm_message.find_one({"key": key})
            message_list = message_object["message_list"]
            message_list.append([sender_username, message_data.get("message")])
            dm_message.replace_one({"key":key},{"key":key, "message_list": message_list})
            temp  = reciever
            for sender in sender_lis:
                socketio.emit("message", {"username":sender_username, "message":message_data.get("message"), "recipient":temp, "key": key, "dict": text_key_master}, room=sender)
            if reciever in user_online:
                reciever_lis = user_online[reciever]
                for i in reciever_lis:
                    print("temp: ",temp)
                    print("username in send_message: ",  i)
                    socketio.emit("message", {"username":sender_username, "message":message_data.get("message"), "recipient":temp, "key":key, "dict": text_key_master}, room=i)
            
            

@app.route('/post_redirect', methods=["GET"])
def post_redirect():
    #if auth_token valid, redirect to /post_screen
        #hash auth token and check if hashed token exists in db
    #if not, display please login
    cookie_auth = request.cookies.get("auth_token")
    if cookie_auth:
        hash_cookie_auth = hashlib.sha256(cookie_auth.encode()).hexdigest()
        finding = auth.find_one({"auth_token": hash_cookie_auth})
        if finding:
            return redirect("/post_screen",code=302)
        else:
            flash("To Post Please Login", "post_permission")
            return redirect("/", code=302)
    flash("To Post Please Login", "post_permission")
    return redirect("/", code=302)
 

#need to build post_screen.html
@app.route('/post_screen')
def post_screen():
    cookie_auth = request.cookies.get("auth_token")
    if cookie_auth:
        hash_cookie_auth = hashlib.sha256(cookie_auth.encode()).hexdigest()
        finding = auth.find_one({"auth_token": hash_cookie_auth})
        if finding:
            return render_template('post_screen.html'), 200
        else: 
            return redirect("/", code=302)
    else:
        return redirect("/", code=302)



@app.route('/review/<file>', methods = {"GET","POST"})
def review_page(file):
    User = None
    cookie_auth = request.cookies.get("auth_token")
    User = None
    if cookie_auth:
        hash_cookie_auth = hashlib.sha256(cookie_auth.encode()).hexdigest()
        User = auth.find_one({"auth_token": hash_cookie_auth})
    if not User:
        flash("To leave a review, Please Login", "post_permission")
        return redirect("/", code=302)
    post = posts_db.find_one({"file_name":file})
    Reviwers = post["Reviwers"]
    if User["username"] in Reviwers:
        flash("Already Reviewed or Is Your Own Post", "post_permission")
        return redirect("/", code=302)
    if request.method == "GET":
        return render_template('review_page.html',post=post), 200
    if request.method == "POST":
        print("GETING REVIEW !!!!!!!!!!!!!!!!")
        print(f"Reviwers BEFORE {Reviwers}")
        print(f"USER THAT MADE REVIEW {User['username']}")
        rating = int(float(request.form.get('rating')))
        total_rating = post.get('Total_rating', 0) + rating
        review_count = post.get('reviews', 0) + 1
        average_rating = round(total_rating/review_count,1)
        Reviwers.append(User["username"])
        print(f"Reviwers AFTER {Reviwers}")
        posts_db.update_one({"file_name":file},{"$set": {"Total_rating": total_rating, "Average_rating": average_rating, "reviews": review_count, "Reviwers":Reviwers }})
        return redirect("/",code=302)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
    posts_db.delete_many({})


