import json
from urllib.parse import urljoin

import requests
from django_celery_beat.models import PeriodicTask


def convert_to_cpe(name, version):
    prefix = "cpe:/a:"
    delimiter = ":"
    return prefix + name + delimiter + str(version)


class CVESearch:

    def __init__(self, base_url='https://cve.circl.lu', proxies=None):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.proxies = proxies
        self.session.headers.update({
            'content-type': 'application/json',
            'User-Agent': 'PyCVESearch - python wrapper'})

    def _http_get(self, api_call, query=None):
        if query is None:  # pragma: no cover
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
    try:
        PeriodicTask.objects.get(name=probe.name + "_check_cve")
    except PeriodicTask.DoesNotExist:
        PeriodicTask.objects.create(crontab=probe.scheduled_check_crontab,
                                    name=probe.name + "_check_cve",
                                    task='checkcve.tasks.check_cve',
                                    args=json.dumps([probe.name, ])
                                    )
