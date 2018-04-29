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

    def delete(self, request, obj, probe=None):
        if probe is None:
            probe = obj
        try:
            periodic_task = PeriodicTask.objects.get(
                name=probe.name + "_check_cve")
            periodic_task.delete()
            logger.debug(str(periodic_task) + " deleted")
        except PeriodicTask.DoesNotExist:  # pragma: no cover
            pass
        messages.add_message(request, messages.SUCCESS, "CheckCve instance " + probe.name + " deleted")
        super().delete_model(request, obj)

    def delete_model(self, request, obj):
        self.delete(request, obj)

    def delete_selected(self, request, obj):
        for probe in obj:
            self.delete(request, obj, probe=probe)

    actions = [check_cve, delete_selected]


admin.site.register(Checkcve, CheckCVEAdmin)
admin.site.register(Software)
admin.site.register(WhiteList)
admin.site.register(Cve)
