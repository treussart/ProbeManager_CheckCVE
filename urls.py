from django.conf.urls import url
from home.views import probe_index
from checkcve.views import check_cve


app_name = 'checkcve'

urlpatterns = [
    url(r'^(?P<id>\d+)$', probe_index, name='probe_index'),
    url(r'^check/(?P<id>\d+)$', check_cve, name='check'),
]
