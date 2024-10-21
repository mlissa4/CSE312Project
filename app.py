from flask import Flask, render_template, request

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login_page')
def login_page():
    return render_template('login.html')

# RICO AND ERIC PLEASE USE SEPPERATE FILES FOR LOGGING IN AND REGISTERING
# TRY TO USE SOME LIBARIES!!!
# Redirect User to home screen on sucessfull login

@app.route('/register', methods=["POST"])
def register():
    print("registering")
    print("Form Data:", request.form)      # For form data (if the request is from a form submission)
    
    return "Received!"

@app.route('/login', methods=["POST"])
def login():
    print("logging in")
    print("Form Data:", request.form)      # For form data (if the request is from a form submission)
    
    return "Received!"


if __name__ == '__main__':
    app.run(debug=True)
