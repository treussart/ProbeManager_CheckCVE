from django.db import models
from home.models import Probe, OsSupported
from home.notifications import send_notification
import logging
from home.ssh import execute
from checkcve.utils import convert_to_cpe, CVESearch
from django.utils import timezone
import select2.fields
from django.db.models import Q
from django.contrib.postgres.fields import ArrayField
from django.conf import settings


logger = logging.getLogger(__name__)


class Cve(models.Model):
    name = models.CharField(max_length=100, unique=True, null=False, blank=False)

    def __str__(self):
        return self.name

    @classmethod
    def get_all(cls):
        return cls.objects.all()

    @classmethod
    def get_by_id(cls, id):
        try:
            object = cls.objects.get(id=id)
        except cls.DoesNotExist as e:
            logger.debug('Tries to access an object that does not exist : ' + str(e))
            return None
        return object

    @classmethod
    def get_by_name(cls, name):
        try:
            object = cls.objects.get(name=name)
        except cls.DoesNotExist as e:
            logger.debug('Tries to access an object that does not exist : ' + str(e))
            return None
        return object


class WhiteList(models.Model):
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

    @classmethod
    def get_all(cls):
        return cls.objects.all()

    @classmethod
    def get_by_id(cls, id):
        try:
            object = cls.objects.get(id=id)
        except cls.DoesNotExist as e:
            logger.debug('Tries to access an object that does not exist : ' + str(e))
            return None
        return object

    @classmethod
    def get_by_name(cls, name):
        try:
            object = cls.objects.get(name=name)
        except cls.DoesNotExist as e:
            logger.debug('Tries to access an object that does not exist : ' + str(e))
            return None
        return object

    def check_if_exists(self, cve_name):
        test = False
        for cve in self.cves.all():
            if cve.name == cve_name:
                test = True
                break
        return test


class Software(models.Model):
    """
    The software to check the common vulnerabilities and exposures.
    """
    INSTALED_CHOICES = (
        ('manual', 'manual'),
        ('apt', 'apt'),
        ('brew', 'brew'),
    )
    name = models.CharField(max_length=100, null=False, blank=False)
    os = models.ForeignKey(OsSupported)
    command = models.CharField(max_length=700, null=True, blank=True)
    cpe = models.CharField(max_length=100, null=False, blank=False)
    instaled_by = models.CharField(max_length=255, choices=INSTALED_CHOICES, null=False, blank=False)

    class Meta:
        unique_together = ('name', 'os', 'instaled_by')

    def __str__(self):
        return self.name + " - " + self.os.name + " - " + self.instaled_by

    @classmethod
    def get_all(cls):
        return cls.objects.all()

    @classmethod
    def get_by_id(cls, id):
        try:
            object = cls.objects.get(id=id)
        except cls.DoesNotExist as e:
            logger.debug('Tries to access an object that does not exist : ' + str(e))
            return None
        return object

    def get_version(self, probe):
        software_by_os = Software.objects.get(name=self.name, os=probe.server.os)
        command = {'get_version': software_by_os.command}
        if self.instaled_by == 'apt':
            command = {'get_version': "apt-cache policy " + str(self.name) + " | sed -n '2 p' | grep -Po '\d{1,2}\.\d{1,2}\.{0,1}\d{0,2}' | sed -n '1 p'"}
        elif self.instaled_by == 'brew':
            command = {'get_version': "brew list " + str(self.name) + " --versions | cut -d ' ' -f 2"}
        try:
            output = execute(probe.server, command)
        except Exception as e:
            logger.error(e)
            return e.__str__()
        logger.info("output : " + str(output))
        return output['get_version']


class Checkcve(Probe):
    """
    The software to check the common vulnerabilities and exposures.
    """
    softwares = models.ManyToManyField(Software, blank=True)
    whitelist = models.ForeignKey(WhiteList)
    vulnerability_found = models.BooleanField(default=False, editable=False)
    vulnerabilities = ArrayField(models.CharField(max_length=100, blank=True), editable=False, blank=True, null=True, default=list())

    def __init__(self, *args, **kwargs):
        super(Probe, self).__init__(*args, **kwargs)
        self.type = self.__class__.__name__

    def __str__(self):
        return self.name + "  " + self.description

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
                    if self.server.os.name is 'debian':
                        title = "<h4><a href='https://security-tracker.debian.org/tracker/" + cves_json[i]['id'] + "'></a>" + cves_json[i]['id'] + " :</h4>"
                    else:
                        title = "<h4><a href='https://www.cvedetails.com/cve/" + cves_json[i]['id'] + "'></a>" + cves_json[i]['id'] + " :</h4>"
                    list_new_cve_rows = list_new_cve_rows + title + cves_json[i]['summary'] + "<br/>"
            if new:
                list_new_cve += "<h2>" + cpe + "</h2><br/>" + list_new_cve_rows
        self.rules_updated_date = timezone.now()
        self.save()
        if list_new_cve:
            self.vulnerability_found = True
            self.vulnerabilities = vulnerabilities_list
            self.save()
            if settings.HOST:
                link = "<br/><a href='https://" + settings.HOST + "'>Edit in ProbeManager</a>"
                list_new_cve = list_new_cve + link
            send_notification('%s new CVE' % nbr, list_new_cve, html=True)
            return list_new_cve
        else:
            self.vulnerability_found = False
            self.save()
            return "No CVE found ! for : " + str(cpe_list)
