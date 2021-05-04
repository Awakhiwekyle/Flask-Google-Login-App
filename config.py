import os

SQLALCHEMY_DATABASE_URI = 'mysql://root:malinga01@localhost/googleLogin'
SECRET_KEY = os.environ.get("SECRET_KEY") or os.urandom(24)
SQLALCHEMY_TRACK_MODIFICATIONS = False
OAUTHLIB_INSECURE_TRANSPORT = os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
GOOGLE_CLIENT_ID = "xxxx xxxx xxxx xxxx"
GOOGLE_CLIENT_SECRET = "xxxx xxxx xxxx xxxx"
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

