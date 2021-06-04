from flask import Flask, render_template, jsonify, request, session, redirect
from passlib.hash import pbkdf2_sha256
from functools import wraps
import pymongo
import uuid

app = Flask(__name__)
#generate random secret key [(]python -c 'import os; print(os.urandom(16))']
app.secret_key = b"\x8e'j\xc1\xffv\xd9\xdc%x\xb1\xd5\xcf\xaf\x04\xa8"

#Database Connection
client = pymongo.MongoClient('localhost',27017)
db = client.user_login_system

#User Login Details
class User:

    def start_session(self, user):
        del user['password']
        session['logged_in'] = True
        session['user'] = user
        return jsonify(user), 200

    def signup(self):
        
        #output in console
        print(request.form)

        #Create User
        user = {
            "_id":uuid.uuid4().hex,
            "name":request.form.get('name'),
            "email":request.form.get('email'),
            "password":request.form.get('password')
        }

        #Encrypt the password
        user['password'] = pbkdf2_sha256.encrypt(user['password'])
        
        #Check for existing user
        if db.users.find_one({"email": user['email']}):
            return jsonify({"error": "Email address already exists"}), 400
        
        if db.users.insert_one(user):
            return self.start_session(user)

        return jsonify({"error": "Signup failed"}), 400

    def signout(self):
        session.clear()
        return redirect('/')

    def login(self):
        user = db.users.find_one({
            "email": request.form.get('email')
        })

        if user and pbkdf2_sha256.verify(request.form.get('password'), user['password']):
            return self.start_session(user)
        return jsonify({ "error": "Invalid login credentials" }), 401

#Login_Required
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            return redirect('/')
    return wrap

@app.route('/')
def Home():
    return render_template("home.html")

@app.route('/register')
def register():
    return render_template("register.html")

@app.route('/signin')
def signin():
    return render_template("signin.html")

@app.route('/dashboard/')
@login_required
def dashboard():
    return render_template("dashboard.html")

#User Authentication Routes
@app.route('/user/signup', methods=['POST'])
def signup():
    return User().signup()

@app.route('/user/signout')
def signout():
    return User().signout()

@app.route('/user/login', methods=['POST'])
def login():
    return User().login()

app.run(debug=True)