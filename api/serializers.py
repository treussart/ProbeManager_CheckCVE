from checkcve.models import Checkcve, WhiteList, Software, Cve
from rest_framework import serializers


class CheckcveSerializer(serializers.ModelSerializer):
    class Meta:
        model = Checkcve
        fields = "__all__"


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
