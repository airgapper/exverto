

class BGPerror(Exception):
    def __init__(self, message, errno = None):
        self.message = message
        self.errno = errno


class BGPmessage(BGPerror)
    pass
