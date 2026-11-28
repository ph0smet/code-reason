from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/hello")
def hello():
    name = request.args.get("name")
    return render_template_string("<p>Hello " + name + "</p>")
