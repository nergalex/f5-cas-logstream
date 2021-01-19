import logging
import socket
from datetime import datetime
from logging.handlers import SysLogHandler
from LogStream import storage_engine


class RemoteSyslog(storage_engine.DatabaseFormat):
    def __init__(self, ip_address, logger, port=514):
        super(RemoteSyslog, self).__init__(logger)
        # Table
        self.type = 'syslog'
        # Primary key
        self.id = ip_address + ':' + str(port)
        self.ip_address = ip_address
        self.port = port
        self.handler = logging.handlers.SysLogHandler(address=(ip_address, port), socktype=socket.SOCK_STREAM)
        self.handler.append_nul = False

    def emit(self, messages):
        for message in messages:
            event = message['event']
            struct_message = [
                'app=' + str(event['app']),
                'attack_types=' + str(event['attack_types']),
                'component=' + str(event['component']),
                'correlation_id=' + str(event['correlation_id']),
                'description=' + str(event['description']),
                'environment=' + str(event['environment']),
                'gateway=' + str(event['gateway']),
                'http.hostname=' + str(event['http.hostname']),
                'http.remote_addr=' + str(event['http.remote_addr']),
                'http.remote_port=' + str(event['http.remote_port']),
                'http.request_method=' + str(event['http.request_method']),
                'http.response_code=' + str(event['http.response_code']),
                'http.server_addr=' + str(event['http.server_addr']),
                'http.server_port=' + str(event['http.server_port']),
                'http.uri=' + str(event['http.uri']),
                'is_truncated=' + str(event['is_truncated']),
                'level=' + str(event['level']),
                'policy_name=' + str(event['policy_name']),
                'request=' + str(event['request']),
                'request_outcome=' + str(event['request_outcome']),
                'request_outcome_reason=' + str(event['request_outcome_reason']),
                'signature_cves=' + str(event['signature_cves']),
                'signature_ids=' + str(event['signature_ids']),
                'signature_names=' + str(event['signature_names']),
                'sub_violations=' + str(event['sub_violations']),
                'support_id=' + str(event['support_id']),
                'type=' + str(event['type']),
                'version=' + str(event['version']),
                'violation_rating=' + str(event['violation_rating']),
                'violations=' + str(event['violations']),
                'x_forwarded_for_header_value=' + str(event['x_forwarded_for_header_value']),
                'event_host=' + str(message['host']),
                'event_source=' + str(message['source']),
                'event_sourcetype=' + str(message['sourcetype']),
                'event_time=' + str(message['time']),
            ]
            now = datetime.now()
            struct_message = now.strftime("%B %d %H:%M:%S") + " logstream logger: " + ';'.join(struct_message) + '\n'
            self.logger.debug("%s::%s: SEND LOG: %s" %
                              (__class__.__name__, __name__, struct_message))
            record = logging.makeLogRecord({
                'msg': struct_message,
            })
            self.handler.emit(record)

    def get_json(self):
        return {
            'ip_address': self.ip_address,
            'port': self.port
        }

class LogCollectorDB(storage_engine.DatabaseFormat):
    def __init__(self, logger):
        super(LogCollectorDB, self).__init__(logger)
        self.handlers = {}
        # Relationship with other tables
        self.children['syslog'] = {}

    def add(self, log_instance):
        if log_instance.id not in self.children[log_instance.type].keys():
            self.create_child(log_instance)

    def remove(self, log_instance):
        if log_instance.id in self.children[log_instance.type].keys():
            log_instance.delete()

    def get(self):
        data_all_types = {}

        # syslog
        type = 'syslog'
        data = []
        for log_instance in self.children[type].values():
            data.append(log_instance.get_json())
        data_all_types[type] = data

        return data_all_types

    def emit(self, messages):
        # syslog
        type = 'syslog'
        for log_instance in self.children[type].values():
            log_instance.emit(messages)



