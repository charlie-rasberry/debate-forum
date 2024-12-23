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
            flash('you need to log in before you can create a topic.')
            return redirect(url_for('login'))

        # get the topic name from the form
        topic_name = request.form.get('topic_name')
        current_time = int(datetime.datetime.now().timestamp())
        user_id = session['user_id']  # the id of the logged-in user

        try:
            # add the topic to the database
            cursor.execute("""
                INSERT INTO topic (topicName, postingUser, creationTime, updateTime)
                VALUES (?, ?, ?, ?)
            """, (topic_name, user_id, current_time, current_time))
            db.commit()
            flash('topic created successfully!')
        except Error as e:
            print(f"error creating topic: {e}")
            flash('something went wrong. please try again.')

    # fetch topics and sort them by when they were created, newest first
    topics = []
    try:
        cursor.execute("""
            SELECT topic.topicID, topic.topicName, user.userName, topic.creationTime
            FROM topic
            JOIN user ON topic.postingUser = user.userID
            ORDER BY topic.creationTime DESC
        """)
        topics_raw = cursor.fetchall()

        # turn the database results into a more useful format
        for topic in topics_raw:
            topics.append({
                'topicID': topic[0],
                'topicName': topic[1],
                'userName': topic[2],
                'creationTime': datetime.datetime.fromtimestamp(topic[3]).strftime('%Y-%m-%d %H:%M:%S')
            })
    except Error as e:
        print(f"error fetching topics: {e}")
    return render_template('home.html', last_visit=session.get('last_visit'), topics=topics)

@app.route('/topic/<int:topic_id>', methods=['GET', 'POST'])
def view_topic(topic_id):
    # if it's a post request, we're adding a claim to the topic
    if request.method == 'POST':
        if 'username' not in session:
            flash('you need to log in to add a claim.')
            return redirect(url_for('login'))

        # grab the data from the form
        claim_text = request.form.get('claim_text')
        related_claim_id = request.form.get('related_claim')
        relation_type = request.form.get('relation_type')
        current_time = int(datetime.datetime.now().timestamp())
        user_id = session['user_id']

        try:
            # add the new claim to the database
            cursor.execute("""
                INSERT INTO claim (topic, postingUser, creationTime, updateTime, text)
                VALUES (?, ?, ?, ?, ?)
            """, (topic_id, user_id, current_time, current_time, claim_text))
            db.commit()

            # if there's a related claim, link it
            if related_claim_id and relation_type:
                relation_type_map = {
                    "opposed": 1,  # assume 1 means "opposed"
                    "equivalent": 2  # assume 2 means "equivalent"
                }
                relation_type_id = relation_type_map.get(relation_type)

                cursor.execute("""
                    INSERT INTO claimToClaim (first, second, claimRelType)
                    VALUES (?, ?, ?)
                """, (cursor.lastrowid, related_claim_id, relation_type_id))
                db.commit()

            flash('claim added successfully!')
        except Error as e:
            print(f"error adding claim: {e}")
            flash('something went wrong. please try again.')

        return redirect(url_for('view_topic', topic_id=topic_id))

    # if it's a get request, fetch and display the topic
    topic = None
    claims = []
    try:
        # get the topic details
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

        # get all the claims for the topic
        cursor.execute("""
            SELECT claim.claimID, claim.text, user.userName, claim.creationTime
            FROM claim
            JOIN user ON claim.postingUser = user.userID
            WHERE claim.topic = ?
            ORDER BY claim.creationTime DESC
        """, (topic_id,))
        claims_raw = cursor.fetchall()

        # format the claims into a list of dictionaries
        for claim in claims_raw:
            claims.append({
                'claimID': claim[0],
                'text': claim[1],
                'userName': claim[2],
                'creationTime': datetime.datetime.fromtimestamp(claim[3]).strftime('%Y-%m-%d %H:%M:%S'),
                'relatedClaims': []
            })

            # get the relationships for this claim
            cursor.execute("""
                SELECT ctc.second AS relatedClaimID, ctcType.claimRelType AS relationType
                FROM claimToClaim ctc
                JOIN claimToClaimType ctcType ON ctc.claimRelType = ctcType.claimRelTypeID
                WHERE ctc.first = ?
            """, (claim[-1]['claimID'],))
            related_raw = cursor.fetchall()
            claim['relatedClaims'] = [{'relatedClaimID': r[0], 'relationType': r[1]} for r in related_raw]
    except Error as e:
        print(f"error fetching topic or claims: {e}")
        flash('something went wrong. please try again.')

    return render_template('view_topic.html', topic=topic, claims=claims, topic_id=topic_id)

@app.route('/claim/<int:claim_id>', methods=['GET', 'POST'])
def view_claim(claim_id):
    # handle replies to claims if it's a post request
    if request.method == 'POST':
        if 'username' not in session:
            flash('you need to log in to post a reply.')
            return redirect(url_for('login'))

        reply_text = request.form.get('reply_text')
        reply_type = request.form.get('reply_type')  # get the type of reply (e.g., clarify, for, against)
        current_time = int(datetime.datetime.now().timestamp())
        user_id = session['user_id']

        try:
            # add the reply to the database
            cursor.execute("""
                INSERT INTO replyText (postingUser, creationTime, text)
                VALUES (?, ?, ?)
            """, (user_id, current_time, reply_text))
            db.commit()

            # get the id of the new reply
            reply_id = cursor.lastrowid

            # map reply type to its id and link the reply to the claim
            reply_type_map = {
                "clarify": 1,  # assume 1 means "clarify"
                "for": 2,      # assume 2 means "for"
                "against": 3   # assume 3 means "against"
            }
            reply_type_id = reply_type_map.get(reply_type)

            cursor.execute("""
                INSERT INTO replyToClaim (reply, claim, replyToClaimRelType)
                VALUES (?, ?, ?)
            """, (reply_id, claim_id, reply_type_id))
            db.commit()

            flash('reply posted successfully!')
        except Error as e:
            print(f"error posting reply: {e}")
            flash('something went wrong. please try again.')

        return redirect(url_for('view_claim', claim_id=claim_id))

    # if it's a get request, show the claim and any replies to it
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
        print(f"error fetching claim: {e}")

    # get replies and any nested replies for this claim
    replies = []
    try:
        # fetch replies directly related to the claim
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

            # fetch any replies to this reply
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
        print(f"error fetching replies: {e}")

    return render_template('view_claim.html', claim=claim, replies=replies)

@app.route('/reply_to_reply/<int:reply_id>', methods=['POST'])
def reply_to_reply(reply_id):
    # handle replies to replies
    if 'username' not in session:
        flash('you need to log in to post a reply.')
        return redirect(url_for('login'))

    reply_text = request.form.get('reply_text')
    reply_type = request.form.get('reply_type')  # get the reply type
    current_time = int(datetime.datetime.now().timestamp())
    user_id = session['user_id']

    try:
        # add the reply to the database
        cursor.execute("""
            INSERT INTO replyText (postingUser, creationTime, text)
            VALUES (?, ?, ?)
        """, (user_id, current_time, reply_text))
        db.commit()

        # get the id of the new reply
        new_reply_id = cursor.lastrowid

        # map the reply type to its id and link it to the parent reply
        reply_type_map = {
            "evidence": 1,  # assume 1 means "evidence"
            "support": 2,   # assume 2 means "support"
            "rebuttal": 3   # assume 3 means "rebuttal"
        }
        reply_type_id = reply_type_map.get(reply_type)

        cursor.execute("""
            INSERT INTO replyToReply (reply, parent, replyToReplyRelType)
            VALUES (?, ?, ?)
        """, (new_reply_id, reply_id, reply_type_id))
        db.commit()

        flash('reply posted successfully!')
    except Error as e:
        print(f"error posting reply to reply: {e}")
        flash('something went wrong. please try again.')

    return redirect(request.referrer)

@app.route('/signout')
def signout():
    # log out the user
    session.clear()
    flash('you have successfully signed out.')
    return redirect(url_for('login'))

@app.route("/register", methods=['GET', 'POST'])
def register():
    # handle user registration
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # hash the password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        current_time = int(datetime.datetime.now().timestamp())

        try:
            cursor.execute(
                "INSERT INTO user (userName, passwordHash, isAdmin, creationTime, lastVisit) VALUES (?, ?, ?, ?, ?)",
                (username, password_hash, False, current_time, current_time)
            )
            db.commit()
            flash('registration successful! please log in.')
            return redirect(url_for('login'))
        except Error as e:
            print(e)
            flash('something went wrong. please try again.')

    return render_template('register.html')

@app.before_request
def update_last_visit():
    # update the last visit time for logged-in users
    if 'username' in session:
        try:
            cursor.execute("UPDATE user SET lastVisit=? WHERE userID=?", (datetime.datetime.now().timestamp(), session['user_id']))
            db.commit()
            session['last_visit'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        except Error as e:
            print(f"error updating last visit: {e}")

@app.route("/login", methods=['GET', 'POST'])
def login():
    # handle user login
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        try:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            cursor.execute("SELECT * FROM user WHERE userName=? AND passwordHash=?", (username, hashed_password))
            user = cursor.fetchone()

            if user:
                session['username'] = username
                session['user_id'] = user[0]
                session['last_visit'] = datetime.datetime.fromtimestamp(float(user[5])).strftime('%Y-%m-%d %H:%M:%S')

                cursor.execute("UPDATE user SET lastVisit=? WHERE userID=?", (datetime.datetime.now().timestamp(), user[0]))
                db.commit()

                return redirect(url_for('home'))
            else:
                flash('invalid username or password.')
        except Error as e:
            print(e)
            flash('something went wrong. please try again.')

    return render_template('login.html')

@app.route("/topic")
def topic():
    return render_template('view_topic.html')

@app.route("/claim")
def claim():
    return render_template('view_claim.html')

if __name__ == "__main__":
    app.run(debug=True)
