from flask import Blueprint, render_template, request, current_app
import imghdr
from PIL import Image, ImageSequence
import os
import uuid
import hashlib
from app import auth


# Create a Blueprint for profile-related routes
profile_bp = Blueprint('profile', __name__, template_folder='templates')

@profile_bp.route('/profile')
def serve_profile_page():
    return render_template('profile.html')

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
    
    auth.update_one({"username": username}, {"$set": {"pfp": image_path}})
    
    return render_template('profile.html')


# get the username
def get_user(request):
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
    filetype = imghdr.what(image.stream)
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
    return path
