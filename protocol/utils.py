def ip_to_int(addr):
    a, b, c, d = addr.split('.')
    return sum([
        int(a) << 24,
        int(b) << 16,
        int(c) << 8,
        int(d)
    ])

def int_to_ip(n):
    return '.'.join([
        str((n & 0xFF000000) >> 24),
        str((n & 0x00FF0000) >> 16),
        str((n & 0x0000FF00) >> 8),
        str((n & 0x000000FF))
    ])

