from flask import Flask, render_template, request, url_for, flash, redirect
import sqlite3, hashlib, datetime
from sqlite3 import Error
app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecretkey'
db = sqlite3.connect("debate.sqlite", check_same_thread=False)
cursor = db.cursor()

class User:
    def __init__(self, userID, userName, passwordHash, isAdmin, creationTime=None, lastVisit=None):
        self.userID = userID
        self.userName = userName
        self.passwordHash = passwordHash
        self.isAdmin = isAdmin
        self.creationTime = creationTime
        self.lastVisit = lastVisit
@app.route('/')
def home():
    return render_template('home.html')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Hash the password
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        user = User(None, username, password_hash, False, datetime.datetime.now(), lastVisit=datetime.datetime.now())
        try:
            cursor.execute("INSERT INTO user (userName, passwordHash, isAdmin, creationTime, lastVisit) VALUES (?, ?, ?, ?, ?)"
                           , (user.userName, user.passwordHash, user.isAdmin, user.creationTime, user.lastVisit))
            db.commit()
            flash('Registration successful! Please log in.')
            # Redirect to the login page after successful registration
            return redirect(url_for('login'))
        except Error as e:
            print(e)
            flash('An error occurred. Please try again.')

    return render_template('register.html')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        try:
            cursor.execute("SELECT * FROM user WHERE userName=? AND passwordHash=?",
                           (username, hashlib.sha256(password.encode()).hexdigest()))
            user = cursor.fetchone()
            if user:
                # Redirect to the home page if the username and password are correct
                return redirect(url_for('home'))
            else:
                # Display an error message if the username or password is incorrect
                flash('Invalid username or password.')
        except Error as e:
            print(e)
            flash('An Error occurred. Please try again.')

    return render_template('login.html')

@app.route("/topic")
def topic():
    return render_template('topic.html')

@app.route("/claim")
def claim():
    return render_template('claim.html')

if __name__ == "__main__":
    app.run(debug=True)