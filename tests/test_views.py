""" venv/bin/python probemanager/manage.py test checkcve.tests.test_views --settings=probemanager.settings.dev """
from django.contrib.auth.models import User
from django.test import Client, TestCase


class ViewsCheckCveTest(TestCase):
    fixtures = ['init', 'crontab', 'init-checkcve', 'test-core-secrets', 'test-checkcve']

    def setUp(self):
        self.client = Client()
        User.objects.create_superuser(username='testuser', password='12345', email='testuser@test.com')
        if not self.client.login(username='testuser', password='12345'):
            self.assertRaises(Exception("Not logged"))

    def tearDown(self):
        self.client.logout()

    def test_home(self):
        """
        Home Page who list instances of Checkcve
        """
        response = self.client.get('/', follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('<title>Home</title>', str(response.content))
        self.assertEqual('core/index.html', response.templates[0].name)
        self.assertIn('core', response.resolver_match.app_names)
        self.assertIn('function index', str(response.resolver_match.func))
        with self.assertTemplateUsed('checkcve/home.html'):
            self.client.get('/', follow=True)

    def test_index(self):
        """
        Index Page for an instance of Checkcve
        """
        response = self.client.get('/checkcve/check/1', follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('<title>Checkcve</title>', str(response.content))
        self.assertEqual('checkcve/index.html', response.templates[0].name)
        self.assertIn('checkcve', response.resolver_match.app_names)
        self.assertIn('function check_cve', str(response.resolver_match.func))
        with self.assertTemplateUsed('checkcve/index.html'):
            self.client.get('/checkcve/check/1', follow=True)
