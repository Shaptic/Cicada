""" Provides helpful packet-oriented utilities.
"""

def ip_to_int(addr):
    """ Converts a 4-octet IPv4 address string into an integer.
    """
    a, b, c, d = addr.split('.')
    return sum([
        int(a) << 24,
        int(b) << 16,
        int(c) << 8,
        int(d)
    ])


def int_to_ip(n):
    """ Converts a 32-bit integer into a 4-octet IPv4 address string.
    """
    return '.'.join([
        str((n & (0xFF << s)) >> s) for s in xrange(24, -1, -8)
    ])
