from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/user")
def user():
    name = request.args.get("name")
    connection = sqlite3.connect("app.db")
    cursor = connection.cursor()
    rows = cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
    return str(rows.fetchall())
