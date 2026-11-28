from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/search")
def search():
    term = request.args.get("term")
    connection = sqlite3.connect("app.db")
    cursor = connection.cursor()
    rows = cursor.execute("SELECT * FROM products WHERE name = '" + term + "'")
    return str(rows.fetchall())
