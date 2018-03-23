import importlib

from celery import task
from celery.utils.log import get_task_logger

from core.models import Probe, Job
from core.notifications import send_notification

logger = get_task_logger(__name__)


@task
def check_cve(probe_name):
    job = Job.create_job('check_cve', probe_name)
    probe = Probe.get_by_name(probe_name)
    if probe is None:
        return {"message": "Error - probe is None - param id not set : " + str(probe_name)}
    my_class = getattr(importlib.import_module(probe.type.lower() + ".models"), probe.type)
    probe = my_class.get_by_name(probe_name)
    try:
        response = probe.check_cve()
        job.update_job(response, 'Completed')
        logger.info("task - check_cve : " + str(probe_name) + " - " + str(response))
    except Exception as e:  # pragma: no cover
        logger.exception(str(e))
        job.update_job(str(e), 'Error')
        send_notification("Error during Check CVE for " + str(probe.name), str(e))
        return {"message": "Error for probe " + str(probe.name) + " to check CVE", "exception": str(e)}
    return response
