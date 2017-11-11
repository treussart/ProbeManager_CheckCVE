import requests
from urllib.parse import urljoin
from django_celery_beat.models import PeriodicTask, CrontabSchedule
import json
import subprocess
from django.conf import settings


def convert_to_cpe(name, version):
    prefix = "cpe:/a:"
    delimiter = ":"
    # print(name + delimiter + str(version))
    return prefix + name + delimiter + str(version)


class CVESearch():

    def __init__(self, base_url='https://cve.circl.lu', proxies=None):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.proxies = proxies
        self.session.headers.update({
            'content-type': 'application/json',
            'User-Agent': 'PyCVESearch - python wrapper'})

    def _http_get(self, api_call, query=None):
        if query is None:
            response = self.session.get(urljoin(self.base_url, 'api/{}'.format(api_call)))
        else:
            response = self.session.get(urljoin(self.base_url, 'api/{}/{}'.format(api_call, query)))
        return response

    def cvefor(self, param):
        """ cvefor() returns a dict containing the CVE's for a given CPE ID
        """
        data = self._http_get('cvefor', query=param)
        return data.json()


def create_check_cve_task(probe):
    if not probe.scheduled_crontab:
        probe.scheduled_crontab = CrontabSchedule.objects.create(minute="0", hour="17", day_of_week="0")
    try:
        PeriodicTask.objects.get(name=probe.name + "_check_cve")
    except PeriodicTask.DoesNotExist:
        PeriodicTask.objects.create(crontab=probe.scheduled_crontab,
                                    name=probe.name + "_check_cve",
                                    task='checkcve.tasks.check_cve',
                                    args=json.dumps([probe.name, ])
                                    )


def ssh_connection(probe, command):
    return subprocess.getoutput('ssh -o StrictHostKeyChecking=no -p ' + str(probe.server.ansible_remote_port) + ' -i ' + settings.MEDIA_ROOT + "/" + probe.server.ansible_ssh_private_key_file.file.name + ' ' + probe.server.ansible_remote_user + '@' + probe.server.host + ' "' + command + '"')
