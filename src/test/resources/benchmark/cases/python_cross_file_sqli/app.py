from flask import Flask, request
from user_repository import UserRepository

app = Flask(__name__)
repo = UserRepository()

@app.route("/user")
def get_user():
    # SOURCE: user-controlled query parameter
    username = request.args.get("name")

    # Passes to repository layer — no SQL visible in this file
    result = repo.find_by_name(username)
    return result or "not found"

if __name__ == "__main__":
    app.run()
