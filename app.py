import socket
import json
import os
import secrets
from typing import Union, Any
from werkzeug.exceptions import HTTPException
import docker
import logging
from collections import OrderedDict
from shutil import copyfile
from bs4 import BeautifulSoup
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from requests import get
from flask import jsonify
from flask import make_response, send_file
from flask import Flask, Response, redirect, request, session, render_template, abort
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user

log = logging.getLogger(__name__)

FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
BACKUP_FILE_NAME = 'backup.tar.gz.cpt'
BACKUP_DIR = '/data/encrypted'
logging.basicConfig(format=FORMAT)
log.setLevel(logging.ERROR)
client = docker.DockerClient(base_url=os.environ.get('DOCKER_SOCK'))

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


@app.errorhandler(HTTPException)
def handle_exception(e):
    return render_template('error.html', code=e.code, message=e.description, name=e.name)


def get_apps_name_version(apps_info: str) -> list:
    """
        Get apps_info string with format => appName-version
        And returns next data structure: [
            {
                'name':'appName',
                'version':'version'
            }
        ]
    """
    app_list = apps_info.split(',')
    result: list = []
    for i in range(len(app_list)):
        temp_list = app_list[i].split('-')
        result.append({
            'name': temp_list[0],
            'version': temp_list[1]
        })
    return result


config['apps_info'] = get_apps_name_version(config.get('apps_info', ''))


def check_hash(hash: str) -> dict:
    deployment_hash = os.environ.get('DEPLOYMENT_HASH')
    hash_to_verify = hash

    s = URLSafeTimedSerializer(deployment_hash)
    new_hash = s.dumps(deployment_hash)
    response = {
        'status': 'OK',
        'hash': new_hash
    }
    if not deployment_hash or not hash_to_verify or (hash_to_verify and not deployment_hash == hash_to_verify):
        response = {
            'status': "ERROR",
        }
    return response


class User(UserMixin):

    def __init__(self, id: int):
        self.id = id
        self.name = os.environ.get('STATUS_PANEL_USERNAME')
        self.password = os.environ.get('STATUS_PANEL_PASSWORD')

    def __repr__(self):
        return "%d/%s" % (self.id, self.name)


def get_self_hosted_services(port_bindings: dict, ip) -> list:
    """
    Check if port opened in container is for self-hosted service
    :param port_bindings:
    :return: list of ports for self-hosted services with their titles or empty list [{port:1234, title:Status Panel}]
    """
    service_ports: list = list()
    for key in port_bindings:
        for net in port_bindings[key]:
            try:
                r = get(f"http://{ip}:{net['HostPort']}")
                soup = BeautifulSoup(r.text)
                title = soup.find('title')
                if r.status_code == 200:
                    service_ports.append({
                        'port': net.get('HostPort'),
                        'title': title.string
                    })
            except Exception as e:
                log.debug(e)
    return service_ports


def get_ip_address():
    """
    Gets machines IP address
    :return: str
    """
    try:
        IP_API_MAP = [
            'https://api.ipify.org',
            'https://ipinfo.io/ip',
            'https://ifconfig.me/ip'
        ]
        for api in IP_API_MAP:
            ip = get(api)
            if ip.status_code == 200:
                return ip.text
    except Exception as e:
        log.exception(e)
    return 'undefined'


@app.route('/')
@login_required
def home():
    ip = get_ip_address()
    if 'ssl_enabled' not in session:
        session['ssl_enabled'] = False
    container_list = []
    containers = client.containers.list()
    for container in containers:
        logs = ''.join([lg for lg in container.logs(tail=100, follow=False, stdout=True).decode('utf-8')])
        ports = get_self_hosted_services(container.attrs['HostConfig']['PortBindings'], ip)
        log.debug(ports)
        if container.name != 'status':
            container_list.append({"name": container.name, "status": container.status, "logs": logs, "ports": ports})

    try:
        domain_ip = socket.gethostbyname(config.get('domain'))
    except Exception as e:
        domain_ip = ""
        log.exception(e)
    can_enable = ip == domain_ip
    return render_template('index.html', ip=ip, domainIp=domain_ip, can_enable=can_enable,
                           container_list=container_list, ssl_enabled=session['ssl_enabled'],
                           domain=config.get('domain'), apps_info=config.get('apps_info'),
                           panel_version='0.1.0', ip_help_link=os.environ.get('IP_HELP_LINK'))


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


def mk_cmd(_config: dict[str, Union[Any, Any]] = None):
    # a string of domains and subdomains is expected in the newer config.json format.
    # domains are separated by comma
    doms = _config or config['subdomains']
    # print(f"doms = {doms}")
    if isinstance(doms, dict):
        domains: str = '{}'.format(' '.join(map("-d {0} ".format, doms.values())))
    elif doms is not None and isinstance(doms, str):
        domains: str = '{}'.format(' '.join(map("-d {0} ".format, doms.split(','))))
    else:
        domains = ''
    # Run registration command (with client email)
    reg_cmd = f"certbot register --email {config['reqdata']['email']} --agree-tos -n"
    # Run command to generate certificates with redirect HTTP traffic to HTTPS, removing HTTP access
    crt_cmd = f"certbot --nginx --redirect {domains}"
    # Run command to generate certificates without redirect
    # certbot --nginx --no-redirect -d domain.com
    log.info(f"Executing command: {crt_cmd}")
    return reg_cmd, crt_cmd


@app.route('/enable_ssl')
@login_required
def enable_ssl():
    domain_list = config['subdomains']
    client.containers.get(os.environ.get('NGINX_CONTAINER')).exec_run(
        "mkdir -p /tmp/letsencrypt/.well-known/acme-challenge"
    )

    if config['ssl'] == 'letsencrypt':
        reg_cmd, crt_cmd = mk_cmd()
        try:
            log.info('Starting certbot..')
            res = client.containers.get(os.environ.get('NGINX_CONTAINER')).exec_run(reg_cmd)
            log.info(res)
            res = client.containers.get(os.environ.get('NGINX_CONTAINER')).exec_run(crt_cmd)
            log.info(res)
            client.containers.get(os.environ.get('NGINX_CONTAINER')).restart()
        except Exception as e:
            log.exception(e)
            return redirect("/")
    else:
        try:
            for fname in domain_list:
                copyfile("./origin_conf/ssl-conf.d/{}.conf".format(fname),
                         "./destination_conf/conf.d/{}.conf".format(fname))
            client.containers.get(os.environ.get('NGINX_CONTAINER')).restart()
            log.debug('Self signed SSL conf file was replaced')
        except Exception as e:
            log.debug(e)
            return redirect("/")
    session['ssl_enabled'] = True
    return redirect("/")


@app.route('/disable_ssl')
@login_required
def disable_ssl():
    domain_list = config['subdomains']
    try:
        log.debug('Disable SSL')
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
        client.containers.get(container).restart()
    except Exception as e:
        log.exception(e)
    return redirect("/")


@app.route('/stop/<container>')
@login_required
def stop(container):
    try:
        client.containers.get(container).stop()
    except Exception as e:
        log.exception(e)
    return redirect("/")


@app.route('/pause/<container>')
@login_required
def pause(container):
    try:
        client.containers.get(container).pause()
    except Exception as e:
        log.exception(e)
    return redirect("/")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/login")


# handle login failed
@app.errorhandler(401)
def page_not_found():
    return Response('<p>Login failed</p>')


# callback to reload the user object
@login_manager.user_loader
def load_user(userid):
    return User(userid)


@app.route("/backup/ping", methods=["POST"])
def backup_ping():
    # Check IP
    if request.environ['REMOTE_ADDR'] != os.environ.get('TRYDIRECT_IP'):
        return make_response(jsonify({"error": "Invalid IP"}), 400)

    try:
        args = json.loads(request.data.decode("utf-8"))
    except Exception:
        return make_response(jsonify({"error": "Invalid JSON"}), 400)

    response = check_hash(args.get('hash'))
    return make_response(jsonify(response), 200)


@app.route("/backup/<hash>/<target_ip>", methods=["GET"])
def return_backup(hash: str, target_ip: str):
    # Check hash
    deployment_hash = os.environ.get('DEPLOYMENT_HASH')
    s = URLSafeTimedSerializer(deployment_hash)
    try:
        s.loads(hash, max_age=1800)  # 30 mins in secs
    except (BadSignature, SignatureExpired) as ex:
        log.exception(ex)
        return make_response(jsonify({"error": "Invalid hash"}), 400)

    # Check IP
    if request.environ['REMOTE_ADDR'] != target_ip:
        return make_response(jsonify({"error": "Invalid IP"}), 400)

    # If back up file doesn't exist, issue an error
    backup_url = '{}/{}'.format(BACKUP_DIR, BACKUP_FILE_NAME)
    if os.path.isfile(backup_url):
        return send_file(backup_url, attachment_filename=BACKUP_FILE_NAME, as_attachment=True)
    else:
        return make_response(jsonify({"error": "Backup not found"}), 400)


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0')
