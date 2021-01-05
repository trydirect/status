#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest


class BaseTestCase(unittest.TestCase):

    def setUp(self):
        pass

    def test_enable_ssl(self):
        from app import app as _app
        from app import mk_cmd
        reg_cmd, crt_cmd = mk_cmd()
        print(reg_cmd)
        print(crt_cmd)

    def tearDown(self):
        pass


if __name__ == "__main__":
    unittest.main()
