import os
import pathlib

import cachecontrol as cachecontrol
import google as google
from flask_login import login_required, LoginManager, login_user, UserMixin, logout_user
from flask_sqlalchemy import SQLAlchemy
from google.oauth2 import id_token
import requests

from config import *
from flask import Flask, g, session, abort, redirect, request, render_template, url_for
from google_auth_oauthlib.flow import Flow

app = Flask(__name__)
app.config.from_pyfile('config.py')
db = SQLAlchemy(app)
login_manager = LoginManager(app)

client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")
flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email",
            "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"

)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    google_id = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    profile_pic = db.Column(db.String(500), unique=True, nullable=False)

    def is_active(self):
        return True


# Login is required decorator for protected area / pages.
def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()

    return wrapper


# Flask-Login helper to retrieve a user from our db
@login_manager.user_loader
def load_user(id):
    return User.query.get(id)


@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_infor = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )
    session["google_id"] = id_infor.get("sub")
    session["name"] = id_infor.get("name")
    session["email"] = id_infor.get("email")
    session["picture"] = id_infor.get("picture")

    # Create a user in our db with the information provided by Google
    # Doesn't exist? Add to database
    user = User.query.filter(User.google_id == session["google_id"]).first()

    if user:
        # g for globally accessing user session information
        g.user = user
        login_user(user)
        session['logged_in'] = True
        return redirect("/my-account")
    else:
        create_user = User(google_id=session["google_id"], name=session["name"], email=session["email"],
                           profile_pic=session["picture"])
        db.session.add(create_user)
        db.session.commit()

        # Begin user session by logging the user in
        user = User.query.filter(User.google_id == session["google_id"]).first()

        # g for globally accessing user session information
        g.user = user
        login_user(user)
        session['logged_in'] = True
        return redirect("/my-account")


@app.route("/logout")
def logout():
    logout_user()
    session.clear()
    return redirect("/")


@app.route("/")
def index():
    return render_template('sign-in.html')


@app.route("/my-account")
@login_required
@login_is_required
def my_account():
    return render_template('my-account.html')


if __name__ == "__main__":
    app.run(debug=True)
