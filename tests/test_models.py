""" venv/bin/python probemanager/manage.py test checkcve.tests.test_models --settings=probemanager.settings.dev """
from django.test import TestCase
from checkcve.models import Checkcve, Cve, WhiteList, Software


class CveTest(TestCase):
    fixtures = ['init', 'crontab', 'init-checkcve', 'test-core-server', 'test-core-probe', 'test-checkcve']

    def test_cve(self):
        all_cve = Cve.get_all()
        cve = Cve.get_by_id(1)
        self.assertEqual(len(all_cve), 5)
        self.assertEqual(cve.name, "CVE-2017-9798")
        self.assertEqual(str(cve), "CVE-2017-9798")
