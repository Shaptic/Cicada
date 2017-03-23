import uuid

class ChannelID(object):
    """ Every channel has a unique identifier. """
    def __init__(self, premade_id=None):
        if premade_id and len(premade_id) != CHANNEL_ID_LENGTH:
            raise TypeError("Invalid premade_id for channel:", premade_id)
        self.id = uuid.uuid4() if premade_id is None else premade_id

    def __eq__(self, o): return str(self) == str(self)
    def __ne__(self, o): return not (self == o)
    def __str__(self):   return str(self.id)
    def __repr__(self):  return str(self)

CHANNEL_ID_LENGTH = len(str(ChannelID()))
