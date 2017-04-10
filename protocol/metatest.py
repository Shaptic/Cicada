class Metaclass(type):
    def __new__(cls, clsname, bases, dct):
        dct["FMT"] = sum(dct["RAW"])
        dct["SIZ"] = len(dct["RAW"])
        return super(Metaclass, cls).__new__(cls, clsname, bases, dct)

class BaseClass(object):
    __metaclass__ = Metaclass
    RAW = [1, 2, 3]

class ChildClass(BaseClass):
    RAW = [4, 5, 6, 7]

print BaseClass().FMT
print ChildClass().FMT

print BaseClass().SIZ
print ChildClass().SIZ
