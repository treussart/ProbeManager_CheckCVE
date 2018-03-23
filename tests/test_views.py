""" venv/bin/python probemanager/manage.py test checkcve.tests.test_views --settings=probemanager.settings.dev """
from django.contrib.auth.models import User
from django.test import Client, TestCase

from checkcve.models import Checkcve


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
        checkcve = Checkcve.get_by_id(1)
        response = self.client.get('/checkcve/' + str(checkcve.id), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('<title>Checkcve</title>', str(response.content))
        self.assertEqual('checkcve/index.html', response.templates[0].name)
        self.assertIn('checkcve', response.resolver_match.app_names)
        self.assertIn('function probe_index', str(response.resolver_match.func))
        with self.assertTemplateUsed('checkcve/index.html'):
            self.client.get('/checkcve/' + str(checkcve.id), follow=True)

    def test_check(self):
        checkcve = Checkcve.get_by_id(1)
        response = self.client.get('/checkcve/check/' + str(checkcve.id), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Check CVE launched with succeed.', str(response.content))

    def test_admin(self):
        """
        Admin Pages
        """
        # index
        response = self.client.get('/admin/checkcve/', follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('<title>Checkcve administration', str(response.content))
        # checkcve
        response = self.client.get('/admin/checkcve/checkcve/', follow=True)
        self.assertEqual(response.status_code, 200)
        response = self.client.post('/admin/checkcve/checkcve/', {'action': 'check_cve', '_selected_action': '1'},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Check CVE OK', str(response.content))
        response = self.client.get('/admin/checkcve/checkcve/1/change/', follow=True)
        self.assertEqual(response.status_code, 200)
        response = self.client.post('/admin/checkcve/checkcve/1/change/', {'name': 'email',
                                                                           'server': 1,
                                                                           'softwares': '1, 2'}, follow=True)
        self.assertEqual(response.status_code, 200)
        response = self.client.get('/admin/checkcve/checkcve/add/', follow=True)
        self.assertEqual(response.status_code, 200)
        response = self.client.post('/admin/checkcve/checkcve/add/', {'name': 'test',
                                                                      'server': 1,
                                                                      'scheduled_check_crontab': 3,
                                                                      'softwares': '1, 2',
                                                                      'whitelist': 1}, follow=True)
        self.assertEqual(response.status_code, 200)
        response = self.client.post('/admin/checkcve/checkcve/', {'action': 'delete_selected', '_selected_action': '2'})
        self.assertEqual(response.status_code, 200)
        # cve
        response = self.client.get('/admin/checkcve/cve/', follow=True)
        self.assertEqual(response.status_code, 200)
        response = self.client.get('/admin/checkcve/cve/2/change/', follow=True)
        self.assertEqual(response.status_code, 200)
        response = self.client.post('/admin/checkcve/cve/2/change/', {'name': 'CVE-2017-7659'}, follow=True)
        self.assertEqual(response.status_code, 200)
        # software
        response = self.client.get('/admin/checkcve/software/', follow=True)
        self.assertEqual(response.status_code, 200)
        response = self.client.get('/admin/checkcve/software/2/change/', follow=True)
        self.assertEqual(response.status_code, 200)
        response = self.client.post('/admin/checkcve/software/2/change', {'name': 'postfix',
                                                                          'os': 1,
                                                                          'cpe': 'postfix:postfix',
                                                                          'instaled_by': 'apt'}, follow=True)
        self.assertEqual(response.status_code, 200)
        # whitelist
        response = self.client.get('/admin/checkcve/whitelist/', follow=True)
        self.assertEqual(response.status_code, 200)
        response = self.client.get('/admin/checkcve/whitelist/1/change/', follow=True)
        self.assertEqual(response.status_code, 200)
        response = self.client.post('/admin/checkcve/whitelist/1/change', {'name': 'reverse-proxy',
                                                                          'cves': "1,2,4,5"
                                                                           }, follow=True)
        self.assertEqual(response.status_code, 200)
