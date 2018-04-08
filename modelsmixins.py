import logging
import inspect
import os


class NameMixin:

    @classmethod
    def get_logger(cls):
        return logging.getLogger(__name__.split('.')[0] + '.' +
                                 os.path.basename(inspect.getsourcefile(cls)) + ':' + cls.__name__)

    @classmethod
    def get_by_name(cls, name):
        try:
            obj = cls.objects.get(name=name)
        except cls.DoesNotExist as e:
            cls.get_logger().warning('Tries to access an object that does not exist : ' + str(e))
            return None
        return obj
