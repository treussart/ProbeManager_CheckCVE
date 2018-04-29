import logging

from rest_framework import status
from rest_framework import viewsets
from rest_framework.mixins import ListModelMixin, RetrieveModelMixin, UpdateModelMixin
from rest_framework.response import Response

from checkcve.api import serializers
from checkcve.models import Cve, Checkcve, WhiteList, Software
from checkcve.utils import create_check_cve_task

logger = logging.getLogger(__name__)


class CheckcveViewSet(ListModelMixin, RetrieveModelMixin, viewsets.GenericViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = Checkcve.objects.all()
    serializer_class = serializers.CheckcveSerializer

    def create(self, request):
        serializer = serializers.CheckcveSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            checkcve = Checkcve.get_by_name(request.data['name'])
            logger.debug("create scheduled task for " + str(checkcve))
            create_check_cve_task(checkcve)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        checkcve = self.get_object()
        serializer = serializers.CheckcveUpdateSerializer(checkcve, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        checkcve = self.get_object()
        serializer = serializers.CheckcveUpdateSerializer(checkcve, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CveViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = Cve.objects.all()
    serializer_class = serializers.CveSerializer


class WhiteListViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = WhiteList.objects.all()
    serializer_class = serializers.WhiteListSerializer


class SoftwareViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = Software.objects.all()
    serializer_class = serializers.SoftwareSerializer
