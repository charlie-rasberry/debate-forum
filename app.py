from flask import Flask, render_template, request
app = Flask(__name__)

@app.route('/')
def home():
    return render_template('home.html')

@app.route("/register")
def register():
    return render_template('register.html')

@app.route("/login")
def login():
    return render_template('login.html')

@app.route("/topic")
def topic():
    return render_template('topic.html')

@app.route("/claim")
def claim():
    return render_template('claim.html')

app.run(debug=True)