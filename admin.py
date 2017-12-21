from django.contrib import admin
from checkcve.models import Checkcve, Software, WhiteList, Cve
import logging
from django.contrib import messages
from checkcve.forms import CheckCVEForm, CheckCVEChangeForm
from checkcve.utils import create_check_cve_task


logger = logging.getLogger(__name__)


class CheckCVEAdmin(admin.ModelAdmin):
    form = CheckCVEForm

    def check_cve(self, request, obj):
        errors = list()
        test = True
        for probe in obj:
            try:
                response = probe.check_cve()
                print(response)
            except Exception as e:
                test = False
                errors.append(e.__str__())
        if test:
            messages.add_message(request, messages.SUCCESS, "Check CVE OK")
        else:
            messages.add_message(request, messages.ERROR, "Check CVE failed ! " + str(errors))

    actions = [check_cve]

    def save_model(self, request, obj, form, change):
        obj.scheduled_rules_deployment_enabled = True
        create_check_cve_task(obj)
        super().save_model(request, obj, form, change)

    """A ModelAdmin that uses a different form class when adding an object."""
    def get_form(self, request, obj=None, **kwargs):
        if obj is None:
            return super(CheckCVEAdmin, self).get_form(request, obj, **kwargs)
        else:
            return CheckCVEChangeForm


class SoftwareAdmin(admin.ModelAdmin):
    class Media:
        js = (
            'checkcve/js/mask-command-field.js',
        )


admin.site.register(Checkcve, CheckCVEAdmin)
admin.site.register(Software, SoftwareAdmin)
admin.site.register(WhiteList)
admin.site.register(Cve)
