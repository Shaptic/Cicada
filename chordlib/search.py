import enum


class BSearchMode(enum.Enum):
    EXACT = 1
    PREDECESSOR = 2
    SUCCESSOR = 3


def bsearch(array, target, func=lambda x: x, mode=BSearchMode.EXACT):
    """ Performs binary search on a sorted array.

    Based on the mode, this will return different things if the target value is
    not found.

    EXACT:          Returns -1.

    PREDECESSOR:    Returns the index of the first element that is _smaller_
                    than the provided target element. If there are no smaller
                    elements, returns 0.

    SUCCESSOR:      Returns the index of the first element that would be
                    _larger_ than the provided target element. If there are no
                    larger elements, returns the length of the array.

    >>> arr = [ 5 ]
    >>> bsearch(arr, 10, mode=BSearchMode.SUCCESSOR)
    1
    >>> bsearch(arr, 2, mode=BSearchMode.SUCCESSOR)
    0
    >>> bsearch(arr, 10, mode=BSearchMode.PREDECESSOR)
    0
    >>> bsearch(arr, 2, mode=BSearchMode.PREDECESSOR)
    0
    >>> arr = [ 2*i for i in xrange(6) ]
    >>> arr
    [0, 2, 4, 6, 8, 10]
    >>> bsearch(arr, 2)
    1
    >>> bsearch(arr, 2, mode=BSearchMode.PREDECESSOR)
    1
    >>> bsearch(arr, 3)
    -1
    >>> bsearch(arr, 3, mode=BSearchMode.PREDECESSOR)
    1
    >>> bsearch(arr, 3, mode=BSearchMode.SUCCESSOR)
    2
    >>> bsearch(arr, 12, mode=BSearchMode.SUCCESSOR)
    6
    >>> # Just make sure that the lambda approach works.
    >>> import collections
    >>> A = collections.namedtuple("A", "a")
    >>> arr = [ A(_) for _ in arr ]
    >>> bsearch(arr, 6, func=lambda x: x.a)
    3
    """
    left = 0
    rite = top = len(array) - 1

    while left <= rite:
        mid = (left + rite) / 2
        elem = func(array[mid])

        if elem < target:
            left = mid + 1
        elif elem > target:
            rite = mid - 1
        else:
            return mid

    if mode == BSearchMode.EXACT:
        return -1
    elif mode == BSearchMode.PREDECESSOR:
        return max(0, left - 1)

    # Successor mode, special case.
    if top == 0 and target > func(array[0]):
        return 1

    return min(top + 1, left)

def successor(key, nodes, packed=True):
    """ Returns the index of the node that next follows the hash of the key.

    The `nodes` array is assumed to be sorted (and rotated, if necessary). That
    is, explicitly compatible with `bsearch()`.
    """
    key_hash = pack_string(chord_hash(key)) if not packed else key
    index = bsearch(nodes, key_hash, func=lambda x: x.hash,
                    mode=BSearchMode.SUCCESSOR)
    return index

def predecessor(key, nodes, packed=True):
    """ Returns the index of the node that precedes the hash of the key.

    The `nodes` array is assumed to be sorted (and rotated, if necessary). That
    is, explicitly compatible with `bsearch()`.
    """
    key_hash = pack_string(chord_hash(key)) if not packed else key
    index = bsearch(nodes, key_hash, func=lambda x: x.hash,
                    mode=BSearchMode.PREDECESSOR)
    return index

def find_pivot(array, func=lambda x: x):
    """ Finds the pivot index of a rotated array.

    The pivot is the index of the array such that array[pivot] is the beginning
    of the sorted equivalent. Specifically,

        - Everything [0, pivot) is larger than anything after it
            elem > max(array[pivot:]) for elem in array[:pivot - 1]
          AND
        - Everything [pivot, length) is smaller than anything before it
            elem < min(array[:pivot]) for elem in array[pivot + 1:]

    See the test cases below for examples.

    >>> a = [ 1, 2, 3, 4 ]          # sorted
    >>> find_pivot(a)
    0
    >>> a = a[::-1]                 # reversed
    >>> find_pivot(a)
    3
    >>>
    >>> a = [ 5, 10, 15, 20, 0 ]    # odd array length with pivot
    >>> find_pivot(a)
    4
    >>> a = [ 10, 12, 4, 8, 9 ]
    >>> find_pivot(a)
    2
    >>> import random
    >>> def rotate(array, i):
    ...    return array[-i:] + array[:-i]
    >>>
    >>> for _ in xrange(10):        # random rotated lists
    ...    r = xrange(random.randint(10, 50))
    ...    tester = set([ random.choice(range(0, 100)) for x in r ])
    ...    tester = list(sorted(tester))
    ...    # Choose a random rotation size
    ...    rot = random.randint(0, len(tester) - 1)
    ...    tester = rotate(tester, rot)
    ...    assert find_pivot(tester) == rot, "Failed on %s: chose %d, not %d" % (
    ...         str(tester), find_pivot(tester), rot)
    """
    low = 0
    high = len(array) - 1
    mid = (high + low) / 2

    lowE  = func(array[low])
    highE = func(array[high])
    midE  = func(array[mid])

    if highE > lowE or len(array) <= 1:
        return 0

    elif len(array) == 2 and func(array[1]) < func(array[0]):
        return 1

    if midE > highE:    # rotated
        return mid + find_pivot(array[mid:], func)

    return find_pivot(array[:mid + 1], func)

def find_insertion_point(value, local, array, func=lambda x: x):
    """ Finds where `value` goes into `array`.

    The comparison value `local` specifies the number around which the array
    pivots. It should not be in the array. We find the index at which the
    given value fits into the array, ensuring that it does not violate the
    rotation.

    >>> hashes = [ 50, 68, 75, 99, 14, 28 ]
    >>> results = [
    ...     find_insertion_point(40,  45, hashes),
    ...     find_insertion_point(49,  45, hashes),
    ...     find_insertion_point(55,  45, hashes),
    ...     find_insertion_point(100, 45, hashes),
    ...     find_insertion_point(5,   45, hashes),
    ...     find_insertion_point(15,  45, hashes)
    ... ]
    >>> results
    [6, 0, 1, 4, 4, 5]
    >>> find_insertion_point(20, 40, [ 50 ])
    1
    >>> find_insertion_point(20, 40, [ 30 ])
    1
    >>> find_insertion_point(30, 40, [ 20 ])
    1
    """
    length = len(array)

    # Special case: len == 1. This is weird, because the "sorting order" depends
    # on the relationship to the `local` value.
    #
    # If the new value is between (local, first element), we need to insert at
    # the beginning. Contrarily, if it's outside of the range, we insert it at
    # the end
    if length == 1:
        begin = array[0]
        return 0 if value > local and value < begin else 1

    # Optimization: insertion value is at one end of the array.
    if   value > func(array[-1]) and value < local: return length
    elif value < func(array[0])  and value > local: return 0

    pivot = find_pivot(array, func)
    if pivot == 0: pivot = length

    # We know for a fact it doesn't need to be the first or the last
    # element. Thus, we can do an insertion without comparing to `local`, but
    # rather just by deciding whether it belongs on the right or left side of
    # the pivot index.
    if value > local:   # left side
        return bsearch(array[:pivot], value, func=func,
                       mode=BSearchMode.SUCCESSOR)

    return pivot + bsearch(array[pivot:], value, func=func,
                           mode=BSearchMode.SUCCESSOR)
