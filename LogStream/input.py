from LogStream import storage_engine
import uuid


class HttpSplunk (storage_engine.DatabaseFormat):
    def __init__(self, api_key, logger):
        super(HttpSplunk, self).__init__(logger)
        # Table
        self.type = 'http_splunk'
        # Primary key
        self.id = api_key
        # Attribute
        self.api_key = api_key
        self.events = []

    def generate_error(self, r):
        if self.logger:
            self.logger.error('%s::%s: code %s; %s' %
                              (__class__.__name__, __name__, r.status_code, r.text))
        raise ConnectionError('%s::%s: code %s; %s' %
                              (__class__.__name__, __name__, r.status_code, r.text))

    def get_json(self):
        return {
            'api_key': self.api_key
        }

    def pop_event(self):
        if len(self.events) == 0:
            return None
        else:
            return self.events.pop(0)

    def append_events(self, events):
        self.events += events



