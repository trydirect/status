#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest


class BaseTestCase(unittest.TestCase):

    def setUp(self):
        pass

    def test_enable_ssl(self):
        from app import app as _app
        config = {'reqdata': {'email': "admin@example1.com"}}
        config['subdomains'] = "sample1.com, sample2.com"
        from app import mk_cmd
        reg_cmd, crt_cmd = mk_cmd(config)
        assert(len(reg_cmd) > 0)
        assert(len(crt_cmd) > 0)
        # print(reg_cmd)
        # print(crt_cmd)

        config['subdomains'] = {"prod": "sample1.com", "dev": "sample2.com"}
        reg_cmd, crt_cmd = mk_cmd(config)
        assert(len(reg_cmd) > 0)
        assert(len(crt_cmd) > 0)
        # print(reg_cmd)
        # print(crt_cmd)

    def tearDown(self):
        pass


if __name__ == "__main__":
    unittest.main()
