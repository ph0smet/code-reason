import os

def run_job(job_name):
    return str(os.system("/usr/local/bin/run-job " + job_name))
