#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
import docker
import requests

client = docker.from_env()
time.sleep(10)  # we expect all containers are up and running in 20 secs

web = client.containers.get('status')
print(web.logs())
# assert 'spawned uWSGI master process' in web.logs()
# assert 'spawned uWSGI worker 1' in web.logs()
# assert 'spawned uWSGI worker 2' in web.logs()
# assert 'spawned uWSGI worker 3' in web.logs()
# assert 'spawned uWSGI worker 4' in web.logs()
assert web.status == 'running'
response = requests.get("http://localhost:5000")
assert response.status_code == 200
# assert "" in response.text
print(response.text)
