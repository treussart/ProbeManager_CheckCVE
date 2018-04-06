""" venv/bin/python probemanager/manage.py test checkcve.tests.test_templatetags --settings=probemanager.settings.dev """
from django.test import TestCase

from checkcve.templatetags import status_cve

class TemplateTagsTest(TestCase):
    fixtures = ['init', 'crontab', 'init-checkcve', 'test-core-secrets', 'test-checkcve']

    def test_status_cve(self):
        self.assertEqual('success', status_cve.status_cve(1))
