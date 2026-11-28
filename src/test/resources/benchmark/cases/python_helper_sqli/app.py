from flask import Flask, request
import sqlite3

app = Flask(__name__)

def load_user(name):
    connection = sqlite3.connect("app.db")
    cursor = connection.cursor()
    return cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")

@app.route("/user")
def user():
    name = request.args.get("name")
    return str(load_user(name).fetchall())
