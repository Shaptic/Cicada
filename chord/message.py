class BaseMessage(object):
    def __init__(self, response_handler=lambda x: None,
                       request_handler=lambda x: None):
        self.handlers = (request_handler, response_handler)
        self.msg_type = ""
        pass

    @classmethod
    def parse(cls, bytestream):
        msg = cls()
        if not msg.parse_request(bytestream):
            if not msg.parse_response(bytestream):
                return False
        return msg

    @property
    def handler(self):
        assert self.msg_type, "No handler for an unparsed message."
        return self.handlers[0] if self.msg_type == "REQUEST" \
                                else self.handlers[1]


class InfoMessage(BaseMessage):
    """ Handles all processing of an INFO message.

    An INFO request from a `Peer` N contains nothing but the command.

    An INFO response back _to_ `Peer` N _from_ `LocalChordNode` X contains the
    following data:
        - X's hash value.
        - A 2-tuple address of X's predecessor.
        - A 2-tuple address of X's successor.

    This object allows you to do the following operations:
        - Build an INFO request from scratch.
        - Parse an INFO request from a bytestream.
        - Call a particular handler on a successful parsing.
    """
    def parse_request(self, bytestream):
        if bytestream.startswith("INFO\r\n"):
            self.msg_type = "REQUEST"
            return self.handlers[0](self, bytestream)

        return False

    def parse_response(self, bytestream):
        if not bytestream.startswith("INFO-R:") or \
           not bytestream.endswith("\r\n"):
            return False

        b = bytestream[len("INFO-R:") - 1 : -2]
        parts = b.split('|')
        self.node_hash = int(parts[0])
        self.pred_addr = parts[1].split(':')
        self.pred_addr[1] = int(self.pred_addr[1])
        self.succ_addr = parts[2].split(':')
        self.succ_addr[1] = int(self.succ_addr[1])

        self.msg_type = "RESPONSE"
        return self.handler(self, bytestream)

    def build_request(self):
        return "INFO\r\n"

    def build_response(self, node_hash, predecessor_addr, successor_addr):
        return "INFO-R:%d|%s:%d|%s:%d\r\n" % (node_hash,
            predecessor_addr[0], predecessor_addr[1],
            successor_addr[0], successor_addr[1])


class JoinMessage(BaseMessage):
    def parse_request(self, bytestream):
        if bytestream.startswith("JOIN\r\n"):
            self.msg_type = "REQUEST"
            return self.handlers[0](self, bytestream)

        return False

    def parse_response(self, bytestream):
        if not bytestream.startswith("JOIN-R:") or \
           not bytestream.endswith("\r\n"):
            return False

        b = bytestream[len("JOIN-R:") - 1 : -2]
        if b == "NONE":
            self.succ_addr = "NONE"
        else:
            self.succ_addr = b.split(',')

        self.msg_type = "RESPONSE"
        return self.handler(self, bytestream)

    def build_request(self):
        return "JOIN\r\n"

    def build_response(self, succ_addr):
        return "JOIN-R:%s" % ("NONE" if succ_addr is None else (
            "%s,%d" % succ_addr))


class NotifyMessage(InfoMessage):
    def parse_request(self, bytestream):
        if bytestream.startswith("NOTIFY\r\n"):
            self.msg_type = "REQUEST"
            return self.handlers[0](self, bytestream)
        return False

    def parse_response(self, bytestream):
        bytestream.replace("NOTIFY-R:", "INFO-R:")
        return super(NotifyMessage, self).parse_response(bytestream)

    def build_request(self):
        return "NOTIFY\r\n"

    def build_response(self, node_hash, predecessor_addr, successor_addr):
        return super(NotifyMessage, self).build_response(node_hash, predecessor_addr, successor_addr).replace("INFO-R:", "NOTIFY-R:")
