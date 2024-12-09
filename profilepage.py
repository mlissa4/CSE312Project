from flask import Blueprint, render_template, request, current_app, redirect
from PIL import Image, ImageSequence, UnidentifiedImageError
import os
from pymongo import MongoClient
import uuid
import hashlib

mongo_clinet = MongoClient('mongo')
db = mongo_clinet["user_auth"]
auth= db["auth"] #to access this database is the same way you do for the homework 
posts_db = db["posts"] #storage of image name 
# Create a Blueprint for profile-related routes
profile_bp = Blueprint('profile', __name__, template_folder='templates')

@profile_bp.route('/profile')
def serve_profile_page():
    from app import user_datastore, posts_db
    username = get_user(request)
    cookie_auth = request.cookies.get("auth_token")
    finding = None
    if cookie_auth:
        hash_cookie_auth = hashlib.sha256(cookie_auth.encode()).hexdigest()
        finding = auth.find_one({"auth_token": hash_cookie_auth})
        if finding:
            user = user_datastore.find_user(email=username)
            users_posts = list(posts_db.find({"Author": username}))
            return render_template('profile.html', pfp=user.pfp, posts=users_posts, stats=user_stats(users_posts),username=username)
        else:
            return redirect("/", code=302)
    
    else:
        return redirect("/", code=302)
    

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

@profile_bp.route('/profile/upload', methods=['POST'])
def upload_pfp():
    cookie_auth = request.cookies.get("auth_token")
    finding = None
    if cookie_auth:
        hash_cookie_auth = hashlib.sha256(cookie_auth.encode()).hexdigest()
        finding = auth.find_one({"auth_token": hash_cookie_auth})
        if finding:
            if 'image' not in request.files:
                return render_template('profile.html', error="No image uploaded.")
            username = get_user(request)
            if not username:
                return render_template('profile.html', error="Error")
            image = request.files['image']
            img_sign = image.stream.read(14)
            img_sign = img_sign.hex().upper()
            image.stream.seek(0)
            img_sign = sign_checker(img_sign)
            if(len(img_sign) != 0):
                image_path = save_image(image)
            else:
                return redirect("/profile", code=302)
            if not image_path:
                return render_template('profile.html', error="Bad file type")
            from app import user_datastore
            user = user_datastore.find_user(email=username)
            if user:
                user.pfp = image_path
                user.save()
                update_posts(user)

            return redirect('/profile')
        else:
            return redirect("/", code=302)
    else:
        return redirect("/", code=302)

def user_stats(posts):
    active_posts = len(posts)
    if active_posts == 0:
        return {
            "active_posts":0,
            "total_stars":0,
            "total_reviews":0,
            "average":0
        }
    total_stars = 0
    total_reviews = 0
    for post in posts:
        total_stars += post["Total_rating"] 
        total_reviews += post["reviews"]
    average = total_stars/total_reviews
    return {
        "active_posts":active_posts,
        "total_stars":total_stars,
        "total_reviews":total_reviews,
        "average":average
    }

def update_posts(user):
    from app import posts_db
    posts_db.update_many(
        {"Author": user.email}, 
        {"$set": {"Author_PFP": user.pfp}}
    )
# get the username
def get_user(request):
    from app import auth
    cookie_auth = request.cookies.get("auth_token")
    if cookie_auth != None:
        hash_cookie_auth = hashlib.sha256(cookie_auth.encode()).hexdigest()
        finding = auth.find_one({"auth_token":hash_cookie_auth})
        if finding != None:
            user_name = finding["username"]
            return user_name
    return None

# resizing images
def resize_image(image, size=300):
    width, height = image.size
    if width > height:
        ratio = width / height
        width = size
        height = round(size / ratio)
    else:
        ratio = height / width
        height = size
        width = round(size / ratio)
    return image.resize((width, height))


# takes image resizes it and saves it
def save_image(image):
    try:
        img = Image.open(image.stream)
    except UnidentifiedImageError as e:
        return render_template('profile.html', error="Bad file type")

    filetype = img.format.lower()  # Get the file format (e.g., 'jpeg', 'png', 'gif')filetype = imghdr.what(image.stream)
    if filetype not in ['jpeg', 'png', 'gif']:
        return None
    print("filetype profile: ", filetype)
    image_filename = f"image_{uuid.uuid4()}.{filetype}"
    path = os.path.join(current_app.config['UPLOAD_FOLDER'], image_filename)
    image.stream.seek(0)
    with Image.open(image.stream) as img:
        if filetype.lower() != 'gif':
            resized_image = resize_image(img)
            resized_image.save(path)
        else:
            frames = ImageSequence.Iterator(img)
            new_frames = []
            for frame in frames:
                resized_frame = resize_image(frame)
                new_frames.append(resized_frame)
            new_frames[0].save(path, save_all=True, append_images=new_frames[1:], loop=0, duration=img.info.get('duration', 100))
    print("image was SAVED sucessfully")
    return path
