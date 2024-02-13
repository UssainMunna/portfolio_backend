
# MODULE IMPORTS

# Flask modules
from flask import Flask, render_template, request, url_for, request, redirect, abort, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_talisman import Talisman
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect

# Other modules
from urllib.parse import urlparse, urljoin
from datetime import datetime
import configparser
import json
import sys
import os


# Local imports
from user import User, Anonymous
from message import Message
from note import Note
from email_utility import send_email, send_registration_email, send_message_email
from verification import confirm_token
from flask_pymongo import pymongo
from flask_cors import CORS

# Create app
app = Flask(__name__)
CORS(app)

# Configuration
config = configparser.ConfigParser()
config.read('configuration.ini')
default = config['DEFAULT']
app.secret_key = 'hbh84ytvn4u5hb56un'
app.config['MONGO_DBNAME'] = 'user_data'
# app.config['MONGO_URI'] = os.environ.get('MONGODB_URI') #default['MONGO_URI']
app.config['MONGO_URI'] = 'mongodb+srv://ussain_munna:kzAkve4KARJmUTyr@cluster0.5el0g3u.mongodb.net/?retryWrites=true&w=majority'
app.config['PREFERRED_URL_SCHEME'] = "https"

# Create Pymongo
mongo = PyMongo(app)

# Create Bcrypt
bc = Bcrypt(app)

# Create Talisman
csp = {
    'default-src': [
        '\'self\'',
        'https://stackpath.bootstrapcdn.com',
        'https://pro.fontawesome.com',
        'https://code.jquery.com',
        'https://cdnjs.cloudflare.com'
    ]
}
talisman = Talisman(app, content_security_policy=csp)

# # Create CSRF protect
# csrf = CSRFProtect()
# csrf.init_app(app)

# Create login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.anonymous_user = Anonymous
login_manager.login_view = "login"




#connect to mongo atlas
def connect_to_mongo():
    client = pymongo.MongoClient(app.config["MONGO_URI"])
    return client['user_data']

# Index    
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/contacts',methods=['GET'])
def get_contacts():
    # Fetch contact details from MongoDB
    db = connect_to_mongo()
    collection = db["contacts_data"]
    contacts = list(collection.find({}, {'_id': 0, 'name': 1, 'email': 1, 'phone': 1}))

    return jsonify(contacts)

@app.route('/contacts', methods=['POST'])
def add_contact():
    db = connect_to_mongo()
    collection = db["contacts_data"]
    # Extract contact data from the POST request
    contact_data = request.json

    # Validate the required fields
    if 'name' not in contact_data or 'email' not in contact_data or 'phone' not in contact_data:
        return jsonify({'error': 'Missing required fields'}), 400

    # Insert the contact data into MongoDB
    collection.insert_one(contact_data)

    return jsonify({'message': 'Contact added successfully'}), 201

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        if current_user.is_authenticated:
            # Redirect to index if already authenticated
            return redirect(url_for('/index'))
        # Render login page
        return render_template('login.html', error=request.args.get("error"))
    # Retrieve user from database
    db = connect_to_mongo()
    collection = db["users"]
    user_data = collection.find_one({'email': request.form['email']}, {'_id': 0})
    if user_data:
        # Check password hash
        if bc.check_password_hash(user_data['password'], request.form['pass']):
            # Create user object to login (note password hash not stored in session)
            user = User.make_from_dict(user_data)
            login_user(user)

            # Check for next argument (direct user to protected page they wanted)
            next = request.args.get('next')
            if not is_safe_url(next):
                return abort(400)

            # Go to profile page after login
            return redirect(next or url_for('profile'))

    # Redirect to login page on error
    return redirect(url_for('login', error=1))


# Register
@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        # Trim input data
        email = request.form['email'].strip()
        title = request.form['title'].strip()
        first_name = request.form['first_name'].strip()
        last_name = request.form['last_name'].strip()
        password = request.form['pass'].strip()
        db = connect_to_mongo()
        collection = db["users"]
        # Check if email address already exists
        existing_user = collection.find_one(
            {'email': email}, {'_id': 0})

        if existing_user is None:
            logout_user()
            print("inside")
            # Hash password
            hashpass = bc.generate_password_hash(password).decode('utf-8')
            # Create user object (note password hash not stored in session)
            new_user = User(title, first_name, last_name, email)
            # Create dictionary data to save to database
            user_data_to_save = new_user.dict()
            user_data_to_save['password'] = hashpass

            # Insert user record to database
            if collection.insert_one(user_data_to_save):
                login_user(new_user)
                # send_registration_email(new_user)
                return redirect(url_for('profile'))
            else:
                # Handle database error
                return redirect(url_for('register', error=2))

        # Handle duplicate email
        return redirect(url_for('register', error=1))

    # Return template for registration page if GET request
    return render_template('register.html', error=request.args.get("error"))


# Confirm email
@app.route('/confirm/<token>', methods=['GET'])
def confirm_email(token):
    logout_user()
    try:
        email = confirm_token(token)
        if email:
            db = connect_to_mongo()
            users = db["users"]
            if users.update_one({"email": email}, {"$set": {"verified": True}}):
                return render_template('confirm.html', success=True)
    except:
        return render_template('confirm.html', success=False)
    else:
        return render_template('confirm.html', success=False)


# Verification email
@app.route('/verify', methods=['POST'])
@login_required
def send_verification_email():
    if current_user.verified == False:
        send_registration_email(current_user)
        return "Verification email sent"
    else:
        return "Your email address is already verified"


# Profile
@app.route('/profile', methods=['GET'])
@login_required
def profile():
    db = connect_to_mongo()
    notes = db["notes"]
    notes = notes.find(
        {"user_id": current_user.id, "deleted": False}).sort("timestamp", -1)
    return render_template('profile.html', notes=notes, title=current_user.title)


# Messages
@app.route('/messages', methods=['GET'])
@login_required
def messages():
    db = connect_to_mongo()
    users = db["users"]
    messages = db["messages"]
    all_users = users.find(
        {"id": {"$ne": current_user.id}}, {'_id': 0})
    inbox_messages = messages.find(
        {"to_id": current_user.id, "deleted": False}).sort("timestamp", -1)
    sent_messages = messages.find(
        {"from_id": current_user.id, "deleted": False, "hidden_for_sender": False}).sort("timestamp", -1)
    return render_template('messages.html', users=all_users, inbox_messages=inbox_messages, sent_messages=sent_messages)


# Logout
@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


# POST REQUEST ROUTES

# Add note
@app.route('/add_note', methods=['POST'])
@login_required
def add_note():
    db = connect_to_mongo()
    notes = db["notes"]
    title = request.form.get("title")
    body = request.form.get("body")
    user_id = current_user.id
    user_name = current_user.display_name()
    note = Note(title, body, user_id, user_name)
    if notes.insert_one(note.dict()):
        return "Success! Note added: " + title
    else:
        return "Error! Could not add note"


# Delete note
@app.route('/delete_note', methods=['POST'])
@login_required
def delete_note():
    db = connect_to_mongo()
    notes = db["notes"]
    note_id = request.form.get("note_id")
    if notes.update_one({"id": note_id}, {"$set": {"deleted": True}}):
        return "Success! Note deleted"
    else:
        return "Error! Could not delete note"


# Send message
@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    db = connect_to_mongo()
    users = db["users"]
    messages = db["messages"]
    title = request.form.get("title")
    body = request.form.get("body")
    from_id = current_user.id
    from_name = current_user.display_name()
    to_id = request.form.get("user")
    to_user_dict = users.find_one({"id": to_id})
    to_user = User.make_from_dict(to_user_dict)
    to_name = to_user.display_name()
    message = Message(title, body, from_id, from_name, to_id, to_name)
    if messages.insert_one(message.dict()):
        send_message_email(from_user=current_user,
                           to_user=to_user, message=message)
        return "Success! Message sent to " + to_name + ": " + title
    else:
        return "Error! Could not send message"


# Delete message
@app.route('/delete_message', methods=['POST'])
@login_required
def delete_message():
    message_id = request.form.get("message_id")
    db = connect_to_mongo()
    collection = db["messages"]
    if collection.update_one({"id": message_id}, {"$set": {"deleted": True}}):
        return "Success! Message deleted"
    else:
        return "Error! Could not delete message"


# Hide sent message
@app.route('/hide_sent_message', methods=['POST'])
@login_required
def hide_sent_message():
    message_id = request.form.get("message_id")
    db = connect_to_mongo()
    collection = db["messages"]
    if collection.update_one({"id": message_id}, {"$set": {"hidden_for_sender": True}}):
        return "Success! Message hidden from sender"
    else:
        return "Error! Could not hide message"


# Change Name
@app.route('/change_name', methods=['POST'])
@login_required
def change_name():
    title = request.form['title'].strip()
    first_name = request.form['first_name'].strip()
    last_name = request.form['last_name'].strip()
    db = connect_to_mongo()
    collection = db["users"]
    if collection.update_one({"email": current_user.email}, {"$set": {"title": title, "first_name": first_name, "last_name": last_name}}):
        return "User name updated successfully"
    else:
        return "Error! Could not update user name"


# Delete Account
@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    user_id = current_user.id
    db = connect_to_mongo()
    collection = db["users"]
    # Deletion flags
    user_deleted = False
    notes_deleted = False
    messages_deleted = False

    # Delete user details
    if collection.delete_one({"id": user_id}):
        user_deleted = True
        logout_user()

    # Delete notes
    if mongo.db.notes.delete_many({"user_id": user_id}):
        notes_deleted = True

    # Delete messages
    if mongo.db.messages.delete_many({"$or": [{"from_id": user_id}, {"to_id": user_id}]}):
        messages_deleted = True

    return {"user_deleted": user_deleted, "notes_deleted": notes_deleted, "messages_deleted": messages_deleted}


# LOGIN MANAGER REQUIREMENTS

# Load user from user ID
@login_manager.user_loader
def load_user(userid):
    # Return user object or none
    db = connect_to_mongo()
    collection = db["users"]
    user = collection.find_one({'id': userid}, {'_id': 0})
    if user:
        return User.make_from_dict(user)
    return None


# Safe URL
def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
        ref_url.netloc == test_url.netloc


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0")
