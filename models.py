import logging

import select2.fields
from django.conf import settings
from django.contrib.postgres.fields import ArrayField
from django.db import models
from django.db.models import Q
from django.utils import timezone
from django_celery_beat.models import PeriodicTask

from checkcve.modelsmixins import NameMixin
from checkcve.utils import convert_to_cpe, CVESearch, create_check_cve_task
from core.models import Probe, OsSupported
from core.modelsmixins import CommonMixin
from core.notifications import send_notification
from core.ssh import execute

logger = logging.getLogger(__name__)


class Cve(NameMixin, CommonMixin, models.Model):
    name = models.CharField(max_length=100, unique=True, null=False, blank=False)

    def __str__(self):
        return self.name


class WhiteList(NameMixin, CommonMixin, models.Model):
    """
    The white list of CVE (Software not vulnerable).
    """
    name = models.CharField(max_length=100, unique=True, null=False, blank=False)
    cves = select2.fields.ManyToManyField(Cve,
                                          blank=True,
                                          ajax=True,
                                          search_field=lambda q: Q(name__icontains=q),
                                          sort_field='name',
                                          js_options={'quiet_millis': 200}
                                          )

    def __str__(self):
        return self.name

    def check_if_exists(self, cve_name):
        test = False
        for cve in self.cves.all():
            if cve.name == cve_name:
                test = True
                break
        return test


class Software(CommonMixin, models.Model):
    """
    The software to check the common vulnerabilities and exposures.
    """
    INSTALED_CHOICES = (
        ('apt', 'apt'),
        ('brew', 'brew'),
    )
    name = models.CharField(max_length=100, null=False, blank=False)
    os = models.ForeignKey(OsSupported, on_delete=models.CASCADE)
    command = models.CharField(max_length=700, null=True, blank=True, editable=False)
    cpe = models.CharField(max_length=100, null=False, blank=False)
    instaled_by = models.CharField(max_length=255, choices=INSTALED_CHOICES, null=False, blank=False)

    class Meta:
        unique_together = ('name', 'os', 'instaled_by')

    def __str__(self):
        return str(self.name) + " - " + str(self.os.name) + " - " + str(self.instaled_by)

    def get_version(self, probe):
        software_by_os = Software.objects.get(name=self.name, os=probe.server.os)
        command = {'get_version': software_by_os.command}
        if self.instaled_by == 'apt':
            command = {'get_version': "apt-cache policy " + str(
                self.name) + " | sed -n '2 p' | grep -Po '\d{1,2}\.\d{1,2}\.{0,1}\d{0,2}' | sed -n '1 p'"}
        elif self.instaled_by == 'brew':
            command = {'get_version': "brew list " + str(self.name) + " --versions | cut -d ' ' -f 2"}
        try:
            output = execute(probe.server, command)
        except Exception as e:  # pragma: no cover
            logger.exception('Error during get version')
            return str(e)
        logger.info("output : " + str(output))
        return output['get_version']


class Checkcve(Probe):
    """
    The software to check the common vulnerabilities and exposures.
    """
    softwares = models.ManyToManyField(Software, blank=True)
    whitelist = models.ForeignKey(WhiteList, on_delete=models.CASCADE)
    vulnerability_found = models.BooleanField(default=False, editable=False)
    vulnerabilities = ArrayField(models.CharField(max_length=100, blank=True), editable=False, blank=True, null=True,
                                 default=list())

    class Meta:
        verbose_name = 'Checkcve instance'
        verbose_name_plural = 'Checkcve instances'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.type = self.__class__.__name__

    def __str__(self):
        return str(self.name) + "  " + str(self.description)

    def save(self, **kwargs):
        super().save(**kwargs)
        create_check_cve_task(self)

    def delete(self, **kwargs):
        try:
            periodic_task = PeriodicTask.objects.get(
                name=self.name + "_check_cve")
            periodic_task.delete()
            logger.debug(str(periodic_task) + " deleted")
        except PeriodicTask.DoesNotExist:  # pragma: no cover
            pass
        return super().delete(**kwargs)

    def check_cve(self):
        cpe_list = list()
        vulnerabilities_list = list()
        list_new_cve = ""
        nbr = 0
        for software in self.softwares.all():
            version = software.get_version(self)
            logger.info(" software get version : " + str(version))
            cpe_list.append(convert_to_cpe(software.cpe, version))
        for cpe in cpe_list:
            logger.info("cpe: " + str(cpe))
            new = False
            list_new_cve_rows = ""
            cve = CVESearch()
            cves_json = cve.cvefor(cpe)
            for i, val in enumerate(cves_json):
                if not self.whitelist.check_if_exists(cves_json[i]['id']):
                    vulnerabilities_list.append(cves_json[i]['id'])
                    new = True
                    nbr += 1
                    logger.info("CVE not in Whitelist : " + str(val))
                    if self.server.os.name == 'debian':
                        title = "<h4><a href='https://security-tracker.debian.org/tracker/" + cves_json[i][
                            'id'] + "'>" + cves_json[i]['id'] + " :</a></h4>"
                    else:  # pragma: no cover
                        title = "<h4><a href='https://www.cvedetails.com/cve/" + cves_json[i]['id'] + "'>" + \
                                cves_json[i]['id'] + " :</a></h4>"
                    infos = "<b>Infos server :</b> " + str(self.server) + "<br/><br/>"
                    list_new_cve_rows = list_new_cve_rows + title + infos + cves_json[i]['summary'] + "<br/>"
            if new:
                list_new_cve += "<h2>" + cpe + "</h2><br/>" + list_new_cve_rows
        self.rules_updated_date = timezone.now()
        self.save()
        if list_new_cve:
            self.vulnerability_found = True
            self.vulnerabilities = vulnerabilities_list
            self.save()
            if hasattr(settings, 'HOST'):  # pragma: no cover
                link = "<br/><a href='https://" + settings.HOST + "'>Edit in ProbeManager</a>"
                list_new_cve = list_new_cve + link
            send_notification('%s new CVE' % nbr, list_new_cve, html=True)
            return list_new_cve
        else:
            self.vulnerability_found = False
            self.save()
            return "No CVE found ! for : " + str(cpe_list)
