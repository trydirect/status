from flask import Flask, Response, redirect, url_for, request, session, abort, render_template
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user
import os
import secrets
from requests import get
import socket
import json
import docker
from shutil import copyfile
import logging
from collections import OrderedDict

log = logging.getLogger(__name__)

FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
log.setLevel(logging.DEBUG)

with open('config.json', 'r') as f:
    config = json.load(f, object_pairs_hook=OrderedDict)

app = Flask(__name__)
app.config.update(
    DEBUG=False,
    SECRET_KEY=secrets.token_urlsafe(64)
)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


class User(UserMixin):

    def __init__(self, id):
        self.id = id
        self.name = os.environ.get('STATUS_PANEL_USERNAME')
        self.password = os.environ.get('STATUS_PANEL_PASSWORD')

    def __repr__(self):
        return "%d/%s/%s" % (self.id, self.name, self.password)


@app.route('/')
@login_required
def home():
    if 'ssl_enabled' not in session:
        session['ssl_enabled'] = False
    client = docker.DockerClient(base_url='unix://var/run/docker.sock')
    container_list = []
    containers = client.containers.list()
    for container in containers:
        logs = ''.join([log for log in container.logs(tail=100, follow=False, stdout=True).decode('utf-8')])
        if container.name != 'try.direct.agent':
            container_list.append({"name": container.name, "status": container.status, "logs": logs})

    ip = get('https://api.ipify.org').text
    domainIp = ""
    try:
        domainIp = socket.gethostbyname(config.get('domain'))
    except Exception as e:
        print(e)
    if ip == domainIp:
        can_enable = True
    else:
        can_enable = False
    return render_template('index.html', ip=ip, domainIp=domainIp, can_enable=can_enable, container_list=container_list,
                           ssl_enabled=session['ssl_enabled'], domain=config.get('domain'))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        user = User(1)
        username = request.form['username']
        password = request.form['password']
        if password == user.password and username == user.name:
            login_user(user)
            return redirect("/")
        else:
            return render_template('login.html', error=True)
    else:
        return render_template('login.html')


@app.route('/enable_ssl')
@login_required
def enable_ssl():
    domain_list = config['subdomains']
    domains = '-w /tmp/letsencrypt {}'.format(' '.join(map(" -d {0} ".format, domain_list.values())))

    client = docker.DockerClient(base_url='unix://var/run/docker.sock')
    res = client.containers.get(os.environ.get('NGINX_CONTAINER')).exec_run("mkdir /tmp/letsencrypt")
    res = client.containers.get(os.environ.get('NGINX_CONTAINER')).exec_run("mkdir /tmp/letsencrypt/.well-known")
    res = client.containers.get(os.environ.get('NGINX_CONTAINER')).exec_run(
        "mkdir /tmp/letsencrypt/.well-known/acme-challenge"
    )

    if config['ssl'] == 'letsencrypt':
        try:
            log.debug('trying to letsencrypt')
            cmd = '/opt/letsencrypt/letsencrypt-auto certonly --email {admin_email} -a webroot {domains} --non-interactive --agree-tos --cert-path /etc/letsencrypt/live/{domain}/cert.pem --chain-path /etc/letsencrypt/live/{domain}/chain.pem --fullchain-path /etc/letsencrypt/live/{domain}/fullchain.pem --key-path /etc/letsencrypt/live/{domain}/privkey.pem'.format(
                http_service='nginx', admin_email=config['reqdata']['email'], domains=domains,
                domain=config.get('domain'))
            log.debug(cmd)
            res = client.containers.get(os.environ.get('NGINX_CONTAINER')).exec_run(cmd)
            log.debug(res)
            for fname in domain_list:
                copyfile("./origin_conf/letsencrypt-conf.d/{}.conf".format(fname),
                         "./destination_conf/conf.d/{}.conf".format(fname))
            client.containers.get(os.environ.get('NGINX_CONTAINER')).restart()
        except Exception as e:
            log.debug(e)
            return redirect("/")
    else:
        try:
            for fname in domain_list:
                copyfile("./origin_conf/ssl-conf.d/{}.conf".format(fname),
                         "./destination_conf/conf.d/{}.conf".format(fname))
            client.containers.get(os.environ.get('NGINX_CONTAINER')).restart()
            log.debug('Self sign SSL conf file was replaces')
        except Exception as e:
            log.debug(e)
            return redirect("/")
    session['ssl_enabled'] = True
    return redirect("/")


@app.route('/disable_ssl')
@login_required
def disable_ssl():
    domain_list = config['subdomains']
    client = docker.DockerClient(base_url='unix://var/run/docker.sock')

    try:
        log.debug('disable ssl')
        for fname in domain_list:
            copyfile("./origin_conf/conf.d/{}.conf".format(fname), "./destination_conf/conf.d/{}.conf".format(fname))
        client.containers.get(os.environ.get('NGINX_CONTAINER')).restart()
    except Exception as e:
        log.debug(e)
        return redirect("/")

    session['ssl_enabled'] = False
    return redirect("/")

@app.route('/restart/<container>')
@login_required
def restart(container):
    try:
        client = docker.DockerClient(base_url='unix://var/run/docker.sock')
        client.containers.get(container).restart()
    except Exception as e:
        log.debug(e)
    return redirect("/")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/login")


# handle login failed
@app.errorhandler(401)
def page_not_found(e):
    return Response('<p>Login failed</p>')


# callback to reload the user object
@login_manager.user_loader
def load_user(userid):
    return User(userid)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
