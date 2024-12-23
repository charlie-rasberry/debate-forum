from flask import Flask, render_template, request, url_for, flash, redirect, session
import sqlite3, hashlib, datetime
from sqlite3 import Error
app = Flask(__name__)
app.config['SECRET_KEY'] = 'cripple'
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

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        if 'username' not in session:
            flash('You must be logged in to create a topic.')
            return redirect(url_for('login'))

        # Get the topic name from the form
        topic_name = request.form.get('topic_name')
        current_time = int(datetime.datetime.now().timestamp())
        user_id = session['user_id']  # Logged-in user's ID

        try:
            # Insert the topic into the database
            cursor.execute("""
                INSERT INTO topic (topicName, postingUser, creationTime, updateTime)
                VALUES (?, ?, ?, ?)
            """, (topic_name, user_id, current_time, current_time))
            db.commit()
            flash('Topic created successfully!')
        except Error as e:
            print(f"Error creating topic: {e}")
            flash('An error occurred. Please try again.')

    # Fetch topics, sorted by creationTime in descending order
    topics = []
    try:
        cursor.execute("""
            SELECT topic.topicID, topic.topicName, user.userName, topic.creationTime
            FROM topic
            JOIN user ON topic.postingUser = user.userID
            ORDER BY topic.creationTime DESC
        """)
        topics_raw = cursor.fetchall()

        # Convert raw tuples to dictionaries
        for topic in topics_raw:
            topics.append({
                'topicID': topic[0],
                'topicName': topic[1],
                'userName': topic[2],
                'creationTime': datetime.datetime.fromtimestamp(topic[3]).strftime('%Y-%m-%d %H:%M:%S')
            })
    except Error as e:
        print(f"Error fetching topics: {e}")

    print("Fetched topics from database:", topics_raw)  # Raw data from the database
    print("Processed topics for template:", topics)  # Processed list of dictionaries
    return render_template('home.html', last_visit=session.get('last_visit'), topics=topics)

@app.route('/signout')
def signout():
    session.clear()
    flash('You have successfully signed out.')
    return redirect(url_for('login'))

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Hash the password
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        current_time = int(datetime.datetime.now().timestamp())  # Current Unix timestamp

        user = User(None, username, password_hash, False, current_time, current_time)  # Same timestamp for creation and last visit
        try:
            cursor.execute(
                "INSERT INTO user (userName, passwordHash, isAdmin, creationTime, lastVisit) VALUES (?, ?, ?, ?, ?)",
                (user.userName, user.passwordHash, user.isAdmin, user.creationTime, user.lastVisit)
            )
            db.commit()
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        except Error as e:
            print(e)
            flash('An error occurred. Please try again.')

    return render_template('register.html')


@app.before_request
def update_last_visit():
    if 'username' in session:
        try:
            # Update the lastVisit field in the database
            cursor.execute("UPDATE user SET lastVisit=? WHERE userID=?", (datetime.datetime.now().timestamp(), session['user_id']))
            db.commit()

            # Update the session's `last_visit` for display purposes
            session['last_visit'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        except Error as e:
            print(f"Error updating last visit: {e}")
@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        try:
            # Hash the provided password and verify against the database
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            cursor.execute("SELECT * FROM user WHERE userName=? AND passwordHash=?", (username, hashed_password))
            user = cursor.fetchone()

            if user:
                # Store username and last visit in session
                session['username'] = username
                session['user_id'] = user[0]  # Assuming userID is the first column in the `user` table
                session['last_visit'] = datetime.datetime.fromtimestamp(float(user[5])).strftime('%Y-%m-%d %H:%M:%S')  # Convert Unix timestamp to readable format

                # Update the lastVisit field in the database (ONLY ON LOGIN)
                cursor.execute("UPDATE user SET lastVisit=? WHERE userID=?", (datetime.datetime.now().timestamp(), user[0]))
                db.commit()

                return redirect(url_for('home'))
            else:
                flash('Invalid username or password.')
        except Error as e:
            print(e)
            flash('An error occurred. Please try again.')

    return render_template('login.html')




@app.route("/topic")
def topic():
    return render_template('topic.html')

@app.route("/claim")
def claim():
    return render_template('claim.html')

if __name__ == "__main__":
    app.run(debug=True)