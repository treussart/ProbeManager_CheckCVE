import logging

from django.contrib import admin
from django.contrib import messages
from django_celery_beat.models import PeriodicTask

from checkcve.forms import CheckCVEForm, CheckCVEChangeForm
from checkcve.models import Checkcve, Software, WhiteList, Cve
from checkcve.utils import create_check_cve_task

logger = logging.getLogger(__name__)


class CheckCVEAdmin(admin.ModelAdmin):
    form = CheckCVEForm

    def check_cve(self, request, obj):
        errors = list()
        test = True
        for probe in obj:
            try:
                probe.check_cve()
            except Exception as e:  # pragma: no cover
                test = False
                logger.exception('Error in check_cve ' + str(self.actions))
                errors.append(str(e))
        if test:
            messages.add_message(request, messages.SUCCESS, "Check CVE OK")
        else:  # pragma: no cover
            messages.add_message(request, messages.ERROR, "Check CVE failed ! " + str(errors))

    def save_model(self, request, obj, form, change):
        create_check_cve_task(obj)
        super().save_model(request, obj, form, change)

    def get_form(self, request, obj=None, **kwargs):
        """A ModelAdmin that uses a different form class when adding an object."""
        if obj is None:
            return super(CheckCVEAdmin, self).get_form(request, obj, **kwargs)
        else:
            return CheckCVEChangeForm

    actions = [check_cve]


admin.site.register(Checkcve, CheckCVEAdmin)
admin.site.register(Software)
admin.site.register(WhiteList)
admin.site.register(Cve)
