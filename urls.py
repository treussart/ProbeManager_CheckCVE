from django.conf.urls import url

from checkcve.views import check_cve
from core.views import probe_index

app_name = 'checkcve'

urlpatterns = [
    url(r'^(?P<id>\d+)$', probe_index, name='probe_index'),
    url(r'^check/(?P<id>\d+)$', check_cve, name='check'),
]
