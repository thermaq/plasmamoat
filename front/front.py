from flask import Flask
from flask_httpauth import HTTPBasicAuth
from flask import render_template
from flask import request
from werkzeug.security import generate_password_hash, check_password_hash
from db.models import LocalIP, IPCorrelation, TREATMENT_CHOICES, DEFAULT_TREATMENT_CHOICES
from db.session import create_session
import json
import subprocess

app = Flask(__name__)
auth = HTTPBasicAuth()

users = {
    "admin": generate_password_hash("P@ssw0rd"),
}

@auth.verify_password
def verify_password(username, password):
    if username in users:
        return check_password_hash(users.get(username), password)
    return False

@app.route('/')
@auth.login_required
def index():
    session = create_session()
    rulesets = []
    for policy_rule in session.query(LocalIP).order_by(LocalIP.id):
        rules = session.query(IPCorrelation).filter_by(local_ip=policy_rule.id).order_by(IPCorrelation.id)
        for rule in rules:
            if not rule.whois:
                p = subprocess.Popen(['whois', rule.remote_ip], stdout=subprocess.PIPE)
                rule.whois = ""
                with p.stdout:
                    for line in iter(p.stdout.readline, b''):
                        rule.whois += line.decode('utf-8')
                session.query(IPCorrelation).filter_by(id=rule.id).update({"whois": rule.whois})
                session.commit()
        rulesets.append({
            'local_ip': policy_rule,
            'rules': rules
        })
    return render_template(
        'index.html',
        rulesets=rulesets,
        treatment_choices=TREATMENT_CHOICES,
        default_treatment_choices=DEFAULT_TREATMENT_CHOICES
    )


@app.route('/set_treatment')
@auth.login_required
def set_treatment():
    session = create_session()
    id = request.args.get("id")
    treatment = request.args.get("treatment")
    ret=session.query(IPCorrelation).filter_by(id=id).update({"treatment": treatment})
    session.commit()
    return json.dumps({'updated': ret})


@app.route('/set_policy')
@auth.login_required
def set_policy():
    session = create_session()
    id = request.args.get("id")
    policy = request.args.get("policy")
    ret=session.query(LocalIP).filter_by(id=id).update({"policy": policy})
    session.commit()
    return json.dumps({'updated': ret})

@app.route('/add_local_ip')
@auth.login_required
def add_local_ip():
    session = create_session()
    ip = request.args.get("ip")
    policy = request.args.get("policy")
    ret=session.add(LocalIP(
        ip=ip,
        policy=policy
    ))
    session.commit()
    return json.dumps({'added': ret})

@app.route('/remove_local_ip')
@auth.login_required
def remove_local_ip():
    session = create_session()
    id = request.args.get("id")
    ret=session.query(LocalIP).filter_by(id=id).remove()
    session.commit()
    return json.dumps({'removed':ret})

if __name__ == '__main__':
    app.run()

