#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
import docker
import requests

client = docker.from_env()
time.sleep(10)  # we expect all containers are up and running in 20 secs

web = client.containers.get('status')
print(web.logs())
assert 'Running on http://0.0.0.0:5000' in web.logs()
assert web.status == 'running'
response = requests.get("http://localhost:5000")
print(response.text)
assert response.status_code == 200
assert "Status Panel" in response.text
