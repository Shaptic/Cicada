def rad(deg):
    """ Converts a value to radians. """
    return (deg * math.pi) / 180.0

def in_range(a, x, y):
    """ Determines if a in [x, y). """
    return a >= x and a < y

def mxrange(start, end, step):
    """ Creates an iterator in [start, end) multiplying by step each time.
    """
    i = start
    while i < end:
        yield i
        i *= step

def listify(fn):
    """ Turns a method that takes a single argument into one that takes lists.
    """
    def wrapper(self, single_arg, *args, **kwargs):
        if isinstance(single_arg, (list, tuple)):
            for item in single_arg:
                fn(self, item, *args, **kwargs)
        else:
            return fn(self, single_arg, *args, **kwargs)
    return wrapper
