from . import node

class RemoteChordNode(node.ChordNode):
    """ Represents a remote Chord node in the hash ring.

    The primary purpose of this object is to handle communication from a local
    node to a remote node. It will cache properties within itself, but will
    perform a remote lookup otherwise.

    For example, accessing `RemoteChord.successor` MAY return a current value,
    but may require actual network communication to determine the successor,
    which is then cached.
    """

    def __init__(self, data):
        super(RemoteChordNode, self).__init__(data)
