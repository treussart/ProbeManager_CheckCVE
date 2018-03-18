""" venv/bin/python probemanager/manage.py test checkcve.tests.test_tasks --settings=probemanager.settings.dev """
from django.test import TestCase

from checkcve.models import Checkcve
from checkcve.tasks import check_cve


class TasksCheckCveTest(TestCase):
    fixtures = ['init', 'crontab', 'init-checkcve', 'test-core-secrets', 'test-checkcve']

    @classmethod
    def setUpTestData(cls):
        pass

    def test_check_cve(self):
        checkcve = Checkcve.get_by_id(1)
        self.assertIn("<h2>cpe:/a:openssl:openssl:1.1.0</h2>", check_cve(checkcve.name))
