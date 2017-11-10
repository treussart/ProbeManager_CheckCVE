from django.db import models
from home.models import Probe, OsSupported
from home.utils import send_notification
import logging
from checkcve.utils import convert_to_cpe, CVESearch, ssh_connection
from django.contrib.auth.models import User
from lxml import html
from django.utils import timezone
import select2.fields
from django.db.models import Q


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
    name = models.CharField(max_length=100, null=False, blank=False)
    os = models.ForeignKey(OsSupported)
    command = models.CharField(max_length=700, null=False, blank=False)
    cpe = models.CharField(max_length=100, null=False, blank=False)

    class Meta:
        unique_together = ('name', 'os',)

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

    def get_version(self, probe):
        software_by_os = Software.objects.get(name=self.name, os=probe.server.os)
        output = ssh_connection(probe, software_by_os.command)
        logger.debug("output : " + str(output))
        return output


class Checkcve(Probe):
    """
    The software to check the common vulnerabilities and exposures.
    """
    softwares = models.ManyToManyField(Software, blank=True)
    whitelist = models.ForeignKey(WhiteList)
    vulnerability_found = models.BooleanField(default=False, editable=False)

    def __init__(self, *args, **kwargs):
        super(Probe, self).__init__(*args, **kwargs)
        self.type = self.__class__.__name__

    def __str__(self):
        return self.name + "  " + self.description

    def check_cve(self):
        cpe_list = list()
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
                    new = True
                    nbr += 1
                    list_new_cve_rows = list_new_cve_rows + "<h4>" + cves_json[i]['id'] + " :</h4>" + cves_json[i][
                        'summary'] + "<br/>"
            if new:
                list_new_cve += "<h2>" + cpe + "</h2><br/>" + list_new_cve_rows
        self.rules_updated_date = timezone.now()
        self.save()
        if list_new_cve:
            self.vulnerability_found = True
            self.save()
            users = User.objects.all()
            try:
                for user in users:
                    if user.is_superuser:
                        user.email_user('%s new CVE' % nbr, list_new_cve, from_email="cve@treussart.com")
            except ConnectionRefusedError:
                pass
            send_notification('%s new CVE' % nbr, html.fromstring(list_new_cve).text_content())
            return list_new_cve
        else:
            self.vulnerability_found = False
            self.save()
            return "No CVE found !"
