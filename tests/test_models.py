""" venv/bin/python probemanager/manage.py test checkcve.tests.test_models --settings=probemanager.settings.dev """
from django.test import TestCase

from checkcve.models import Checkcve, Cve, WhiteList, Software
from core.models import Probe, Server, OsSupported


class CveTest(TestCase):
    fixtures = ['init', 'crontab', 'init-checkcve', 'test-core-server', 'test-checkcve']

    def test_cve(self):
        all_cve = Cve.get_all()
        cve = Cve.get_by_id(1)
        self.assertEqual(len(all_cve), 5)
        self.assertEqual(cve.name, "CVE-2017-9798")
        self.assertEqual(str(cve), "CVE-2017-9798")
        self.assertEqual(Cve.get_by_name("CVE-2017-9798"), cve)
        with self.assertLogs(level='DEBUG'):
            Cve.get_by_name("TEST NOT EXIST")


class SoftwareTest(TestCase):
    fixtures = ['init', 'crontab', 'init-checkcve', 'test-core-secrets', 'test-checkcve']

    def test_software(self):
        all_software = Software.get_all()
        software = Software.get_by_id(1)
        self.assertEqual(len(all_software), 9)
        self.assertEqual(software.name, "dovecot-imapd")
        self.assertEqual(str(software), "dovecot-imapd - debian - apt")
        self.assertEqual(software.get_version(Probe.get_by_id(1)), "OK")
        software_brew = Software.objects.create(name='test',
                                                os=OsSupported.get_by_id(1),
                                                cpe='postfix:postfix',
                                                instaled_by='brew')
        self.assertEqual(software_brew.get_version(Checkcve.get_by_id(1)), 'OK')  # ????
        software_brew.delete()


class WhitelistTest(TestCase):
    fixtures = ['init', 'crontab', 'init-checkcve', 'test-core-server', 'test-checkcve']

    def test_whitelist(self):
        all_whitelist = WhiteList.get_all()
        whitelist = WhiteList.get_by_id(1)
        self.assertEqual(len(all_whitelist), 1)
        self.assertEqual(whitelist.name, "server")
        self.assertEqual(str(whitelist), "server")
        self.assertTrue(whitelist.check_if_exists("CVE-2017-9798"))
        self.assertEqual(WhiteList.get_by_name("server"), whitelist)
        with self.assertLogs(level='DEBUG'):
            WhiteList.get_by_name("TEST NOT EXIST")


class CheckcveTest(TestCase):
    fixtures = ['init', 'crontab', 'init-checkcve', 'test-core-secrets', 'test-checkcve']

    def test_cve(self):
        all_check_cve = Checkcve.get_all()
        check_cve = Checkcve.get_by_id(1)
        self.assertEqual(len(all_check_cve), 1)
        self.assertFalse(check_cve.vulnerability_found)
        self.assertEqual(str(check_cve), "checkcve1  test")
        self.assertEqual(check_cve.type, "Checkcve")
        self.assertIn("<h2>cpe:/a:openssl:openssl:1.1.0</h2>", check_cve.check_cve())
        checkcve_1 = Checkcve.objects.create(name='test 2',
                                             server=Server.get_by_id(1),
                                             whitelist=WhiteList.get_by_id(1),
                                             vulnerability_found=False,
                                             vulnerabilities=[])
        checkcve_1.softwares.add(Software.get_by_id(3))
        checkcve_1.save()
        self.assertIn("No CVE found !", checkcve_1.check_cve())
        checkcve_1.delete()
