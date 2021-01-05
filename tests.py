#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Container services tests


import time
import docker
import requests
import unittest


class BaseTestCase(unittest.TestCase):

    def setUp(self):
        time.sleep(10)  # we expect all containers are up and running in 10-20 secs
        self.client = docker.from_env()
        pass

    def test_app_container_up(self):
        web = self.client.containers.get('status')
        print(web.logs())
        assert 'Running on http://0.0.0.0:5000' in web.logs()
        assert web.status == 'running'
        response = requests.get("http://localhost:5000")
        print(response.text)
        assert response.status_code == 200
        assert "Status Panel" in response.text

    def tearDown(self):
        pass


if __name__ == "__main__":
    unittest.main()
