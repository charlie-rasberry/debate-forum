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
    return render_template('home.html', last_visit=session.get('last_visit'), topics=topics)


@app.route('/topic/<int:topic_id>', methods=['GET', 'POST'])
def view_topic(topic_id):
    # Handle creating a claim (POST request)
    if request.method == 'POST':
        if 'username' not in session:
            flash('You must be logged in to add a claim.')
            return redirect(url_for('login'))

        # Get the claim text from the form
        claim_text = request.form.get('claim_text')
        current_time = int(datetime.datetime.now().timestamp())
        user_id = session['user_id']

        try:
            # Insert the claim into the database
            cursor.execute("""
                INSERT INTO claim (topic, postingUser, creationTime, updateTime, text)
                VALUES (?, ?, ?, ?, ?)
            """, (topic_id, user_id, current_time, current_time, claim_text))
            db.commit()
            flash('Claim added successfully!')
        except Error as e:
            print(f"Error adding claim: {e}")
            flash('An error occurred. Please try again.')

        return redirect(url_for('view_topic', topic_id=topic_id))

    # Fetch topic details (GET request)
    topic = None
    claims = []
    try:
        # Query the topic details
        cursor.execute("""
            SELECT topic.topicName, user.userName, topic.creationTime
            FROM topic
            JOIN user ON topic.postingUser = user.userID
            WHERE topic.topicID = ?
        """, (topic_id,))
        topic_data = cursor.fetchone()
        if topic_data:
            topic = {
                'topicName': topic_data[0],
                'userName': topic_data[1],
                'creationTime': datetime.datetime.fromtimestamp(topic_data[2]).strftime('%Y-%m-%d %H:%M:%S')
            }

        # Query the claims associated with the topic
        cursor.execute("""
            SELECT claim.claimID, claim.text, user.userName, claim.creationTime
            FROM claim
            JOIN user ON claim.postingUser = user.userID
            WHERE claim.topic = ?
            ORDER BY claim.creationTime DESC
        """, (topic_id,))
        claims_raw = cursor.fetchall()
        claims = [
            {
                'claimID': claim[0],
                'text': claim[1],
                'userName': claim[2],
                'creationTime': datetime.datetime.fromtimestamp(claim[3]).strftime('%Y-%m-%d %H:%M:%S')
            } for claim in claims_raw
        ]
    except Error as e:
        print(f"Error fetching topic or claims: {e}")
        flash('An error occurred. Please try again.')

    # Render the topic view template
    return render_template('view_topic.html', topic=topic, claims=claims, topic_id=topic_id)

@app.route('/claim/<int:claim_id>', methods=['GET', 'POST'])
def view_claim(claim_id):
    if request.method == 'POST':
        if 'username' not in session:
            flash('You must be logged in to post a reply.')
            return redirect(url_for('login'))

        reply_text = request.form.get('reply_text')
        reply_type = request.form.get('reply_type')  # Get the reply type
        current_time = int(datetime.datetime.now().timestamp())
        user_id = session['user_id']

        try:
            # Insert the reply into the `replyText` table
            cursor.execute("""
                INSERT INTO replyText (postingUser, creationTime, text)
                VALUES (?, ?, ?)
            """, (user_id, current_time, reply_text))
            db.commit()

            # Get the ID of the inserted reply
            reply_id = cursor.lastrowid

            # Insert the relationship into the `replyToClaim` table
            reply_type_map = {
                "clarify": 1,  # Assuming ID 1 is for "Clarify"
                "for": 2,      # Assuming ID 2 is for "For"
                "against": 3   # Assuming ID 3 is for "Against"
            }
            reply_type_id = reply_type_map.get(reply_type)

            cursor.execute("""
                INSERT INTO replyToClaim (reply, claim, replyToClaimRelType)
                VALUES (?, ?, ?)
            """, (reply_id, claim_id, reply_type_id))
            db.commit()

            flash('Reply posted successfully!')
        except Error as e:
            print(f"Error posting reply: {e}")
            flash('An error occurred. Please try again.')

        return redirect(url_for('view_claim', claim_id=claim_id))

    # Fetch claim and replies (existing code remains unchanged)
    claim = {}
    try:
        cursor.execute("""
            SELECT claim.claimID, claim.text, user.userName, claim.creationTime
            FROM claim
            JOIN user ON claim.postingUser = user.userID
            WHERE claim.claimID = ?
        """, (claim_id,))
        claim = cursor.fetchone()
    except Error as e:
        print(f"Error fetching claim: {e}")

    # Fetch replies and their nested replies
    replies = []
    try:
        # Fetch all replies directly linked to the claim
        cursor.execute("""
            SELECT replyText.replyTextID, replyText.text, user.userName, replyText.creationTime, replyToClaimType.claimReplyType
            FROM replyText
            JOIN user ON replyText.postingUser = user.userID
            JOIN replyToClaim ON replyText.replyTextID = replyToClaim.reply
            JOIN replyToClaimType ON replyToClaim.replyToClaimRelType = replyToClaimType.claimReplyTypeID
            WHERE replyToClaim.claim = ?
            ORDER BY replyText.creationTime ASC
        """, (claim_id,))
        replies_raw = cursor.fetchall()
        for reply in replies_raw:
            replies.append({
                'text': reply[1],
                'userName': reply[2],
                'creationTime': datetime.datetime.fromtimestamp(reply[3]).strftime('%Y-%m-%d %H:%M:%S'),
                'type': reply[4],
                'replyTextID': reply[0]
            })

            # Fetch nested replies for each reply
            cursor.execute("""
                SELECT replyText.text, user.userName, replyText.creationTime, replyToReplyType.replyReplyType
                FROM replyText
                JOIN user ON replyText.postingUser = user.userID
                JOIN replyToReply ON replyText.replyTextID = replyToReply.reply
                JOIN replyToReplyType ON replyToReply.replyToReplyRelType = replyToReplyType.replyReplyTypeID
                WHERE replyToReply.parent = ?
                ORDER BY replyText.creationTime ASC
            """, (reply[0],))
            nested_replies = cursor.fetchall()
            replies[-1]['nested_replies'] = [
                {
                    'text': nested[0],
                    'userName': nested[1],
                    'creationTime': datetime.datetime.fromtimestamp(nested[2]).strftime('%Y-%m-%d %H:%M:%S'),
                    'type': nested[3]
                } for nested in nested_replies
            ]
    except Error as e:
        print(f"Error fetching replies: {e}")

    return render_template('view_claim.html', claim=claim, replies=replies)

@app.route('/reply_to_reply/<int:reply_id>', methods=['POST'])
def reply_to_reply(reply_id):
    if 'username' not in session:
        flash('You must be logged in to post a reply.')
        return redirect(url_for('login'))

    reply_text = request.form.get('reply_text')
    reply_type = request.form.get('reply_type')  # Get the reply type
    current_time = int(datetime.datetime.now().timestamp())
    user_id = session['user_id']

    try:
        # Insert the new reply into `replyText` table
        cursor.execute("""
            INSERT INTO replyText (postingUser, creationTime, text)
            VALUES (?, ?, ?)
        """, (user_id, current_time, reply_text))
        db.commit()

        # Get the ID of the newly inserted reply
        new_reply_id = cursor.lastrowid

        # Map reply type to its ID
        reply_type_map = {
            "evidence": 1,  # Assuming ID 1 is for "Evidence"
            "support": 2,   # Assuming ID 2 is for "Support"
            "rebuttal": 3   # Assuming ID 3 is for "Rebuttal"
        }
        reply_type_id = reply_type_map.get(reply_type)

        # Insert the relationship into `replyToReply` table
        cursor.execute("""
            INSERT INTO replyToReply (reply, parent, replyToReplyRelType)
            VALUES (?, ?, ?)
        """, (new_reply_id, reply_id, reply_type_id))
        db.commit()

        flash('Reply posted successfully!')
    except Error as e:
        print(f"Error posting reply to reply: {e}")
        flash('An error occurred. Please try again.')

    # Redirect back to the claim page
    return redirect(request.referrer)


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
    return render_template('view_topic.html')

@app.route("/claim")
def claim():
    return render_template('view_claim.html')

if __name__ == "__main__":
    app.run(debug=True)