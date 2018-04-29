from rest_framework import serializers

from checkcve.models import Checkcve, WhiteList, Software, Cve


class CheckcveSerializer(serializers.ModelSerializer):
    class Meta:
        model = Checkcve
        fields = 'name', 'description', 'scheduled_check_crontab', 'server', 'softwares', 'whitelist'


class CheckcveUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Checkcve
        fields = 'description', 'server', 'softwares', 'whitelist'


class WhiteListSerializer(serializers.ModelSerializer):
    class Meta:
        model = WhiteList
        fields = "__all__"


class SoftwareSerializer(serializers.ModelSerializer):
    class Meta:
        model = Software
        fields = "__all__"


class CveSerializer(serializers.ModelSerializer):
    class Meta:
        model = Cve
        fields = "__all__"
