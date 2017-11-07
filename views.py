from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from home.models import Probe
import importlib
from django.http import HttpResponseNotFound
from django.contrib import messages
import logging


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
            response = probe.check_cve()
            messages.add_message(request, messages.SUCCESS, response)
        except Exception as e:
            messages.add_message(request, messages.ERROR, "Check CVE failed ! " + e.__str__())
    return render(request, probe.type.lower() + '/index.html', {'probe': probe})
