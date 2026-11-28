from flask import Flask, request
from job_runner import run_job

app = Flask(__name__)

@app.route("/job")
def job():
    job_name = request.args.get("name")
    return run_job(job_name)
