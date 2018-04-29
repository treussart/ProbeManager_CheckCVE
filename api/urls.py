from checkcve.api import views

urls_to_register = [
    (r'^checkcve/software', views.SoftwareViewSet),
    (r'^checkcve/whitelist', views.WhiteListViewSet),
    (r'^checkcve/cve', views.CveViewSet),
    (r'^checkcve/checkcve', views.CheckcveViewSet),
]
