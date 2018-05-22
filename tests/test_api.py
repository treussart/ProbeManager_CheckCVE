""" venv/bin/python probemanager/manage.py test checkcve.tests.test_api --settings=probemanager.settings.dev """
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from django_celery_beat.models import PeriodicTask
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework.test import APITestCase

from checkcve.models import Checkcve


class APITest(APITestCase):
    fixtures = ['init', 'crontab', 'init-checkcve', 'test-core-secrets', 'test-checkcve']

    def setUp(self):
        self.client = APIClient()
        User.objects.create_superuser(username='testuser', password='12345', email='testuser@test.com')
        if not self.client.login(username='testuser', password='12345'):
            self.assertRaises(Exception("Not logged"))

    def tearDown(self):
        self.client.logout()

    def test_checkcve(self):
        response = self.client.get('/api/v1/checkcve/checkcve/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)

        data = {'name': 'test',
                'scheduled_check_crontab': 3,
                'server': 1,
                'softwares': [1, 2],
                'whitelist': 1}

        data_put = {'name': 'test',
                    'scheduled_check_crontab': 3,
                    'server': 1,
                    'softwares': [1, ],
                    'whitelist': 1}

        data_patch = {'softwares': [1, 2]}

        response = self.client.post('/api/v1/checkcve/checkcve/', data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(PeriodicTask.objects.get(name="test_check_cve"))

        response = self.client.post('/api/v1/checkcve/checkcve/', {'name': 'test'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        response = self.client.get('/api/v1/checkcve/checkcve/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 2)

        self.assertTrue(PeriodicTask.objects.get(name="test_check_cve"))

        self.assertEqual(len(Checkcve.get_by_name('test').softwares.all()), 2)
        response = self.client.put('/api/v1/checkcve/checkcve/' + str(Checkcve.get_by_name('test').id) + '/', data_put)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(Checkcve.get_by_name('test').softwares.all()), 1)

        response = self.client.get('/api/v1/checkcve/checkcve/' + str(Checkcve.get_by_name('test').id) + '/check_cve/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])

        response = self.client.put('/api/v1/checkcve/checkcve/' + str(Checkcve.get_by_name('test').id) + '/', {'name': 'test'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        response = self.client.patch('/api/v1/checkcve/checkcve/' + str(Checkcve.get_by_name('test').id) + '/', data_patch)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(Checkcve.get_by_name('test').softwares.all()), 2)

        response = self.client.patch('/api/v1/checkcve/checkcve/' + str(Checkcve.get_by_name('test').id) + '/',
                                     {'name': 'test2'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(Checkcve.get_by_name('test').name, 'test')

        response = self.client.delete('/api/v1/checkcve/checkcve/' + str(Checkcve.get_by_name('test').id) + '/')
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        response = self.client.get('/api/v1/checkcve/checkcve/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)

        with self.assertRaises(ObjectDoesNotExist):
            PeriodicTask.objects.get(name="test_check_cve")
