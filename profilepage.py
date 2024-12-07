from flask import Blueprint, render_template, request, current_app, redirect
from PIL import Image, ImageSequence
import os
import uuid
import hashlib


# Create a Blueprint for profile-related routes
profile_bp = Blueprint('profile', __name__, template_folder='templates')

@profile_bp.route('/profile')
def serve_profile_page():
    from app import user_datastore, posts_db
    username = get_user(request)
    user = user_datastore.find_user(email=username)
    users_posts = list(posts_db.find({"Author": username}))
    return render_template('profile.html', pfp=user.pfp, posts=users_posts, stats=user_stats(users_posts),username=username)


@profile_bp.route('/profile/upload', methods=['POST'])
def upload_pfp():
    if 'image' not in request.files:
        return render_template('profile.html', error="No image uploaded.")
    username = get_user(request)
    if not username:
        return render_template('profile.html', error="Error")
    image = request.files['image']
    image_path = save_image(image)
    if not image_path:
        return render_template('profile.html', error="Bad file type")
    from app import user_datastore
    user = user_datastore.find_user(email=username)
    if user:
        user.pfp = image_path
        user.save()
        update_posts(user)

    return redirect('/profile')

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
    img = Image.open(image.stream)
    filetype = img.format.lower()  # Get the file format (e.g., 'jpeg', 'png', 'gif')filetype = imghdr.what(image.stream)
    if filetype not in ['jpeg', 'png', 'gif']:
        return None
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
