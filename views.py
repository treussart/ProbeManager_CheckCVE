from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from home.models import Probe
import importlib
from django.http import HttpResponseNotFound
from django.contrib import messages
import logging
from checkcve.tasks import check_cve as task_cve
from django.utils.safestring import mark_safe


logger = logging.getLogger(__name__)


@login_required
def check_cve(request, id):
    """
    Check CVE for an instance.
    """
    probe = Probe.get_by_id(id)
    my_class = getattr(importlib.import_module(probe.type.lower() + ".models"), probe.type)
    probe = my_class.get_by_id(id)
    if probe is None:
        return HttpResponseNotFound
    else:
        try:
            task_cve.delay(probe.name)
            messages.add_message(request, messages.SUCCESS, mark_safe("Check CVE launched with succeed. <a href='/admin/home/job/'>View Job</a>"))
        except Exception as e:
            messages.add_message(request, messages.ERROR, "Check CVE failed ! " + e.__str__())
    return render(request, probe.type.lower() + '/index.html', {'probe': probe})
