""" venv/bin/python probemanager/manage.py test checkcve.tests.test_tasks --settings=probemanager.settings.dev """
from django.conf import settings
from django.test import TestCase

from checkcve.models import Checkcve
from checkcve.tasks import check_cve


class TasksCheckCveTest(TestCase):
    fixtures = ['init', 'crontab', 'init-checkcve', 'test-core-secrets', 'test-checkcve']

    @classmethod
    def setUpTestData(cls):
        settings.CELERY_TASK_ALWAYS_EAGER = True

    def test_check_cve(self):
        checkcve = Checkcve.get_by_id(1)
        response = check_cve.delay(checkcve.name)
        self.assertIn("<h2>cpe:/a:openssl:openssl:1.1.0</h2>", response.get())
        self.assertTrue(response.successful())
        self.assertEqual(check_cve.delay('name unknown').result,
                         {"message": "Error - probe is None - param id not set : name unknown"})
