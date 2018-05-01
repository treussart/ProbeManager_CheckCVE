import logging

from rest_framework import mixins
from rest_framework import status
from rest_framework import viewsets
from rest_framework.response import Response

from checkcve.api import serializers
from checkcve.models import Cve, Checkcve, WhiteList, Software

logger = logging.getLogger(__name__)


class CheckcveViewSet(mixins.ListModelMixin, mixins.CreateModelMixin, mixins.RetrieveModelMixin,
                      mixins.DestroyModelMixin, viewsets.GenericViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = Checkcve.objects.all()
    serializer_class = serializers.CheckcveSerializer

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
