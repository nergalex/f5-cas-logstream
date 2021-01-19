class CAS:
    @staticmethod
    def get_security_event(event):
        data = []
        if event['event']['type'] == 'security violation':
            data.append(event)
        return data
