from django.forms import ModelForm
from checkcve.models import Checkcve


class CheckCVEForm(ModelForm):
    class Meta:
        model = Checkcve
        fields = ('name', 'description', 'scheduled_check_crontab', 'server', 'softwares', 'whitelist')


class CheckCVEChangeForm(ModelForm):
    class Meta:
        model = Checkcve
        fields = ('name', 'description', 'server', 'softwares', 'whitelist')
