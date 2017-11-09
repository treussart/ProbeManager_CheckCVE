from celery import task
from celery.utils.log import get_task_logger
from home.models import Probe, Job
import importlib
from home.utils import send_notification
import traceback


logger = get_task_logger('checkcve')


@task
def check_cve(probe_name):
    job = Job.create_job('check_cve', probe_name)
    probe = Probe.get_by_name(probe_name)
    if probe is None:
        return {"message": "Error - probe is None - param id not set : " + str(probe_name)}
    my_class = getattr(importlib.import_module(probe.type.lower() + ".models"), probe.type)
    probe = my_class.get_by_name(probe_name)
    if probe.scheduled_enabled:
        try:
            message = probe.check_cve()
            job.update_job(message, 'Completed')
            logger.info("task - check_cve : " + str(probe_name) + " - " + str(message))
        except Exception as e:
            logger.error(e.__str__())
            logger.error(traceback.print_exc())
            job.update_job(e.__str__(), 'Error')
            send_notification("Check CVE for " + str(probe.name), e.__str__())
            return {"message": "Error for probe " + str(probe.name) + " to check CVE", "exception": e.__str__()}
        return message
    else:
        job.update_job("Not enabled to check CVE", 'Error')
        send_notification("Probe " + str(probe.name), "Not enabled to check CVE")
        return {"message": probe.name + " not enabled to check CVE"}
