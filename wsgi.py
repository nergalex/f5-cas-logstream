from flask import (Flask, request)
from flask_restful import (Api, Resource)
from flasgger import Swagger
from LogStream import input, filter, output, local_file_manager
import logging
import threading
import uuid
import time
import json

application = Flask(__name__)
api = Api(application)
swagger = Swagger(application)


def setup_logging(log_level, log_file):
    if log_level == 'debug':
        log_level = logging.DEBUG
    elif log_level == 'verbose':
        log_level = logging.INFO
    else:
        log_level = logging.WARNING

    logging.basicConfig(filename=log_file, format='%(asctime)s %(levelname)s %(message)s', level=log_level)
    return logging.getLogger(__name__)


@swagger.definition('cas', tags=['v2_model'])
class ConfigCAS:
    """
    Integration of NGINX Controller
    ---
    required:
      - api_key
    properties:
      api_key:
        type: string
        description: API KEY set as a Credential for Integration object
    """

    @staticmethod
    def prepare(data_json):
        if 'api_key' in data_json:
            result = {
                'code': 200,
                'object': data_json
            }
        else:
            result = {
                'code': 400,
                'msg': 'parameters: api_key must be set'
            }
        return result

    @staticmethod
    def set(data_json):
        cas.api_key = data_json['object']['api_key']

    @staticmethod
    def get():
        if cas is not None:
            return cas.get_json()
        else:
            return None


@swagger.definition('logcollector', tags=['v2_model'])
class ConfigLogCollector:
    """
    Configure remote logging servers
    ---
    required:
      - syslog
    properties:
        syslog:
          type: array
          items:
            type: object
            schema:
            $ref: '#/definitions/syslog_server'
    """

    @staticmethod
    def prepare(data_json):
        if 'syslog' in data_json.keys():
            result = []
            code = 0
            for instance in data_json['syslog']:
                data = ConfigSyslogServer.prepare(instance)
                result.append(data)
                code = max(code, data['code'])
            result = {
                'code': code,
                'syslog': result
            }
        else:
            result = {
                'code': 400,
                'msg': 'parameters: syslog must be set'
            }
        return result

    @staticmethod
    def set(data_json):
        for instance in data_json['syslog']:
            ConfigSyslogServer.set(instance)

    @staticmethod
    def get():
        return logcol_db.get()


@swagger.definition('syslog_server', tags=['v2_model'])
class ConfigSyslogServer:
    """
    Configure a syslog server
    ---
    required:
      - ip_address
      - port
    properties:
      ip_address:
        type: string
        pattern: '^\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}$'
        description: ipv4 address
        example:
          1.1.1.1
      port:
        type: integer
        description: port listener
        default: 514
    """

    @staticmethod
    def prepare(data_json):
        if 'ip_address' in data_json.keys():
            result = {
                'code': 200,
                'object': {
                    'ip_address': data_json['ip_address']
                }
            }
            if 'port' in data_json.keys():
                result['object']['port'] = data_json['port']
            else:
                result['object']['port'] = 514
        else:
            result = {
                'code': 400,
                'msg': 'parameters: log_level, log_file must be set'
            }
        return result

    @staticmethod
    def set(data_json):
        logcol_db.add(output.RemoteSyslog(
            ip_address=data_json['object']['ip_address'],
            port=data_json['object']['port'],
            logger=logger)
        )


class Declare(Resource):
    def get(self):
        """
        Get LogStream current declaration
        ---
        tags:
          - LogStream
        responses:
          200:
            schema:
              required:
                - cas
                - logcollector
              properties:
                cas:
                  type: object
                  schema:
                  $ref: '#/definitions/cas'
                logcollector:
                  type: object
                  schema:
                  $ref: '#/definitions/logcollector'
        """
        return {
            'cas': ConfigCAS.get(),
            'logcollector': ConfigLogCollector.get(),
        }, 200

    def post(self):
        """
        Configure LogStream in one declaration
        ---
        tags:
          - LogStream
        consumes:
          - application/json
        parameters:
          - in: body
            name: body
            schema:
              required:
                - cas
                - logcollector
              properties:
                cas:
                  type: object
                  schema:
                  $ref: '#/definitions/cas'
                logcollector:
                  type: object
                  schema:
                  $ref: '#/definitions/logcollector'
        responses:
          200:
            description: Deployment done
         """
        data_json = request.get_json()
        clean_data = Declare.clean(declaration=data_json)

        # data malformated
        if 'code' in clean_data.keys():
            return clean_data

        # clean data
        else:
            Declare.deploy(declaration=clean_data)
            Declare.save(declaration=data_json)

        return "Configuration done", 200

    @staticmethod
    def clean(declaration):
        result = {}
        cur_class = 'cas'
        if cur_class in declaration.keys():
            result[cur_class] = ConfigCAS.prepare(declaration[cur_class])
            if result[cur_class]['code'] not in (200, 201, 202):
                return result, result[cur_class]['code']
        else:
            return {
                'code': 400,
                'msg': 'parameters: ' + cur_class + ' must be set'
            }

        cur_class = 'logcollector'
        if cur_class in declaration.keys():
            result[cur_class] = ConfigLogCollector.prepare(declaration[cur_class])
            if result[cur_class]['code'] not in (200, 201, 202):
                return result, result[cur_class]['code']
        else:
            return {
                'code': 400,
                'msg': 'parameters: ' + cur_class + ' must be set'
            }

        return result

    @staticmethod
    def deploy(declaration):
        cur_class = 'cas'
        if cur_class in declaration.keys():
            ConfigCAS.set(declaration[cur_class])

        cur_class = 'logcollector'
        if cur_class in declaration.keys():
            ConfigLogCollector.set(declaration[cur_class])

    @staticmethod
    def save(declaration):
        local_config.set_json(declaration)
        local_config.save()


class EngineThreading(Resource):
    @staticmethod
    def start_main(thread_number=1):
        """
        Start threads.
        :return:
        """
        if len(thread_manager['thread_queue'].keys()) == 0 and \
                thread_manager['event'].is_set():
            thread_manager['event'].clear()
            for cur_index in (1, thread_number):
                thread_name = str(uuid.uuid4())
                t = threading.Thread(
                    target=EngineThreading.task_producer_consumer,
                    name=thread_name,
                    args=(thread_manager['event'], thread_name, cur_index)
                )
                thread_manager['thread_queue'][thread_name] = t
                logger.debug("%s::%s: NEW THREAD: id=%s;index:%s" %
                            (__class__.__name__, __name__, t.name, cur_index))
                t.start()
            return "Engine started", 200
        else:
            return "Engine already started", 202

    @staticmethod
    def stop_main():
        """
        Stop gracefully threads
        :return:
        """
        if not thread_manager['event'].is_set():
            # set flag as a signal to threads for stop processing their next fetch logs iteration
            thread_manager['event'].set()
            logger.debug("%s::%s: Main - event set" %
                         (__class__.__name__, __name__))

            # wait for threads to stop processing their current fetch logs iteration
            while len(thread_manager['thread_queue'].keys()) > 0:
                logger.debug("%s::%s: Main - wait for dying thread" %
                             (__class__.__name__, __name__))
                time.sleep(thread_manager['update_interval'])

            logger.debug("%s::%s: Main - all thread died" %
                         (__class__.__name__, __name__))
            return "Engine stopped", 200
        else:
            return "Engine already stopped", 202

    @staticmethod
    def restart_main(thread_number=1):
        EngineThreading.stop_main()
        return EngineThreading.start_main(thread_number)

    @staticmethod
    def task_producer_consumer(thread_flag, thread_name, cur_index):
        """
        fetch events and send them on remote logging servers
        :param thread_flag:
        :param thread_name:
        :param cur_index: thread ID in pool
        :return:
        """
        while not thread_flag.is_set():
            events = cas.pop_event()
            if events is None:
                logger.debug("%s::%s: THREAD is sleeping: name=%s;index:%s" %
                             (__class__.__name__, __name__, thread_name, cur_index))
                time.sleep(thread_manager['update_interval'])
                logger.debug("%s::%s: THREAD is awake: name=%s;index:%s" %
                             (__class__.__name__, __name__, thread_name, cur_index))
            else:
                logcol_db.emit(filter.CAS.get_security_event(events))
                logger.debug("%s::%s: THREAD sent events: name=%s;index:%s" %
                             (__class__.__name__, __name__, thread_name, cur_index))

        logger.debug("%s::%s: THREAD exited his work: name=%s;index:%s" %
                     (__class__.__name__, __name__, thread_name, cur_index))
        thread_manager['thread_queue'].pop(thread_name, None)


class Engine(Resource):
    def get(self):
        """
        Get engine status
        ---
        tags:
          - LogStream
        responses:
          200:
            schema:
              required:
                - status
              properties:
                status:
                  type: string
                  description: status
                threads:
                  type: integer
                  description: number of running threads
        """
        data = {}
        if len(thread_manager['thread_queue'].keys()) > 0:
            data['status'] = 'sync processing'
            data['threads'] = len(thread_manager['thread_queue'].keys())
        else:
            data['status'] = 'no sync process'
        return data

    def post(self):
        """
            Start/Stop engine
            ---
            tags:
              - LogStream
            consumes:
              - application/json
            parameters:
              - in: body
                name: body
                schema:
                  required:
                    - action
                    - thread_number
                  properties:
                    action:
                      type: string
                      description : Start/Stop engine
                      enum: ['start', 'stop', 'restart']
                    thread_number:
                      type: integer
                      description : number of thread to start
                      default: 1
            responses:
              200:
                description: Action done
        """
        data_json = request.get_json()

        # Sanity check
        cur_class = 'action'
        if cur_class not in data_json.keys() or \
                data_json[cur_class] not in ('start', 'stop', 'restart') or \
                (data_json[cur_class] == 'start' and 'thread_number' not in data_json.keys()):
            return {
                'code': 400,
                'msg': 'parameters: ' + cur_class + ', thread_number must be set'
            }
        else:
            # Sanity check
            if 'thread_number' in data_json.keys():
                thread_number = data_json['thread_number']
            else:
                thread_number = 1
            if data_json[cur_class].lower() == 'start':
                return EngineThreading.start_main(thread_number)
            elif data_json[cur_class].lower() == 'stop':
                return EngineThreading.stop_main()
            elif data_json[cur_class].lower() == 'restart':
                return EngineThreading.restart_main(thread_number)
            else:
                return "Unknown action", 400


class Forward(Resource):
    def post(self):
        """
            Forward event
            ---
            tags:
              - LogStream
            consumes:
              - application/json
            parameters:
              - in: body
                name: security_events
                description: List of security events
                schema: {}
            responses:
              200:
                description: Event received
        """
        # Sanity Check
        if request.headers['Authorization'].split(' ')[1] != cas.api_key:
            return {
                'code': 401,
                'msg': 'Unauthorized'
            }

        # Authorization request
        elif request.headers['Content-Length'] == '0':
            return {'msg': 'heartbeat OK'}

        # Events
        else:
            # WORKAROUND ISSUE - header application/x-www-form-urlencoded generates an empty request.data value in Flask via NGINX UNIT #
            if request.content_type == 'application/x-www-form-urlencoded':
                data_form = ''
                for key, value in request.form.items():
                    data_form = key + value
                data_json = json.loads(data_form)
            else:
                data_json = request.get_json(force=True, silent=True)

            # JSON format sanity check
            if data_json is None:
                return {
                    'code': 400,
                    'msg': 'Bad request'
                }
            cas.append_events(data_json)
            return {'msg': 'security event OK'}


# Global var
logger = setup_logging(
    log_level='warning',
    log_file='logstream.log'
)
logcol_db = output.LogCollectorDB(logger)
thread_manager = {
    'event': threading.Event(),
    'thread_queue': {},
    'update_interval': 10,
}

# event = True == engine stopped
thread_manager['event'].set()

cas = input.HttpSplunk(
    api_key=None,
    logger=logger
)

# load local configuration
local_config = local_file_manager.Configuration(backup_file='declaration.json')
if local_config.get_json() is not None:
    clean_data = Declare.clean(declaration=local_config.get_json())
    # malformed declaration
    if 'code' in clean_data.keys():
        raise Exception('Local configuration file is malformated', clean_data)

    # deploy
    Declare.deploy(declaration=clean_data)

# API
api.add_resource(Declare, '/declare')
api.add_resource(Engine, '/engine')
api.add_resource(Forward, '/forward')

# Start program in developer mode
if __name__ == '__main__':
    print("Dev Portal: http://127.0.0.1:5000/apidocs/")
    application.run(
        host="0.0.0.0",
        debug=True,
        use_reloader=True,
        port=3001
    )

