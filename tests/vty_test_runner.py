#!/usr/bin/env python3

# (C) 2013 by Katerina Barone-Adesi <kat.obsc@gmail.com>
# (C) 2013 by Holger Hans Peter Freyther
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os, sys
import time
import unittest
import socket
import subprocess

import osmopy.obscvty as obscvty
import osmopy.osmoutil as osmoutil
from osmopy.osmo_ipa import IPA

# to be able to find $top_srcdir/doc/...
confpath = os.path.join(sys.path[0], '..')

class TestVTYBase(unittest.TestCase):

    def checkForEndAndExit(self):
        res = self.vty.command("list")
        #print ('looking for "exit"\n')
        self.assertTrue(res.find('  exit\r') > 0)
        #print 'found "exit"\nlooking for "end"\n'
        self.assertTrue(res.find('  end\r') > 0)
        #print 'found "end"\n'

    def vty_command(self):
        raise Exception("Needs to be implemented by a subclass")

    def vty_app(self):
        raise Exception("Needs to be implemented by a subclass")

    def setUp(self):
        osmo_vty_cmd = self.vty_command()[:]
        config_index = osmo_vty_cmd.index('-c')
        if config_index:
            cfi = config_index + 1
            osmo_vty_cmd[cfi] = os.path.join(confpath, osmo_vty_cmd[cfi])

        try:
            self.proc = osmoutil.popen_devnull(osmo_vty_cmd)
        except OSError:
            print("Current directory: %s" % os.getcwd(), file=sys.stderr)
            print("Consider setting -b", file=sys.stderr)

        appstring = self.vty_app()[2]
        appport = self.vty_app()[0]
        self.vty = obscvty.VTYInteract(appstring, "127.0.0.1", appport)

    def tearDown(self):
        if self.vty:
            self.vty._close_socket()
        self.vty = None
        osmoutil.end_proc(self.proc)


class TestVTYGbproxy(TestVTYBase):

    def vty_command(self):
        return ["./src/osmo-gbproxy", "-c",
                "doc/examples/osmo-gbproxy/osmo-gbproxy.cfg"]

    def vty_app(self):
        return (4246, "./src/osmo-gbproxy", "OsmoGbProxy", "gbproxy")

    def testVtyTree(self):
        self.vty.enable()
        self.assertTrue(self.vty.verify('configure terminal', ['']))
        self.assertEqual(self.vty.node(), 'config')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify('ns', ['']))
        self.assertEqual(self.vty.node(), 'config-ns')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify('exit', ['']))
        self.assertEqual(self.vty.node(), 'config')
        self.assertTrue(self.vty.verify('gbproxy', ['']))
        self.assertEqual(self.vty.node(), 'config-gbproxy')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify('exit', ['']))
        self.assertEqual(self.vty.node(), 'config')

    def testVtyShow(self):
        res = self.vty.command("show ns")
        self.assertTrue(res.find('UDP bind') >= 0)

        res = self.vty.command("show gbproxy bvc bss stats")
        self.assertTrue(res.find('GBProxy Global Statistics') >= 0)

    def testVtyDeletePeer(self):
        self.vty.enable()
        self.assertTrue(self.vty.verify('delete-gbproxy-peer 9999 bvci 7777', ['NSE not found']))
        res = self.vty.command("delete-gbproxy-peer 9999 all dry-run")
        self.assertTrue(res.find('Not Deleted 0 BVC') >= 0)
        self.assertTrue(res.find('NSEI not found') >= 0)
        res = self.vty.command("delete-gbproxy-peer 9999 only-bvc dry-run")
        self.assertTrue(res.find('Not Deleted 0 BVC') >= 0)
        res = self.vty.command("delete-gbproxy-peer 9999 only-nsvc dry-run")
        self.assertTrue(res.find('NSEI not found') >= 0)
        res = self.vty.command("delete-gbproxy-peer 9999 all")
        self.assertTrue(res.find('Deleted 0 BVC') >= 0)
        self.assertTrue(res.find('NSEI not found') >= 0)

def add_gbproxy_test(suite, workdir):
    assert os.path.isfile(os.path.join(workdir, "src/osmo-gbproxy"))
    test = unittest.TestLoader().loadTestsFromTestCase(TestVTYGbproxy)
    suite.addTest(test)

if __name__ == '__main__':
    import argparse
    import sys

    workdir = '.'

    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", dest="verbose",
                        action="store_true", help="verbose mode")
    parser.add_argument("-p", "--pythonconfpath", dest="p",
                        help="searchpath for config")
    parser.add_argument("-w", "--workdir", dest="w",
                        help="Working directory")
    parser.add_argument("test_name", nargs="*", help="(parts of) test names to run, case-insensitive")
    args = parser.parse_args()

    verbose_level = 1
    if args.verbose:
        verbose_level = 2

    if args.w:
        workdir = args.w

    if args.p:
        confpath = args.p

    print("confpath %s, workdir %s" % (confpath, workdir))
    os.chdir(workdir)
    print("Running tests for specific VTY commands")
    suite = unittest.TestSuite()
    add_gbproxy_test(suite, workdir)

    if args.test_name:
        osmoutil.pick_tests(suite, *args.test_name)

    res = unittest.TextTestRunner(verbosity=verbose_level, stream=sys.stdout).run(suite)
    sys.exit(len(res.errors) + len(res.failures))

# vim: shiftwidth=4 expandtab nocin ai
