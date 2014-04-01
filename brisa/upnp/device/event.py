# Licensed under the MIT license
# http://opensource.org/licenses/mit-license.php or see LICENSE file.
#
# Copyright 2007-2008, Brisa Team <brisa-develop@garage.maemo.org>

""" Device-side event related classes.
"""
import uuid

from xml.etree import ElementTree
from datetime import datetime

from brisa.core import log, reactor, webserver
log = log.getLogger('device-events')

from brisa.core.network import http_call
from brisa.core.network_senders import UDPTransport
from brisa.core.threaded_call import run_async_call, ThreadedCall
from brisa.utils.looping_call import LoopingCall
from brisa.upnp import soap
from brisa.upnp.upnp_defaults import map_upnp_value, UPnPDefaults

import brisa
if not brisa.__enable_events_logging__:
    log.disabled = 0


class EventController(webserver.CustomResource):
    """ Listen for event subscribe and unsubscribe at device services.
    It also manager the list of the control points interested at service
    eventing.
    """

    def __init__(self, service, event_reload_time, force_event_reload):
        webserver.CustomResource.__init__(self, 'eventSub')
        #FIXME - This list is not thread safe
        self.subscribers = []
        self.service = service
        self.event_reload_time = event_reload_time
        self.force_event_reload = force_event_reload

    def render(self, uri, request, response):
        """ Event renderer method.

        @param uri: URI of the request
        @param request: request object
        @param response: response object

        @type uri: string

        """
        compressed_headers = {}
        for k, v in list(request.headers.items()):
            if not v:
                v = ""
            compressed_headers[k.lower()] = v.strip()

        if request.method.lower() == "subscribe":
            if not 'sid' in compressed_headers:
                return self.render_subscriber(request,
                            response, compressed_headers)
            else:
                return self.render_renew(request, response, compressed_headers)
        elif request.method.lower() == "unsubscribe":
            return self.render_unsubscribe(request,
                            response, compressed_headers)

        return response.body

    def render_subscriber(self, request, response, compressed_headers):
        """ Renders the subscribe message for an event.

        @param request: request object
        @param response: response object
        """
        log.debug('Receiving subscribe request')
        request_status = self._validate_subscribe_request(request,
                                                          compressed_headers)

        if request_status == 200:
            timeout = int(compressed_headers['timeout'].split("-")[-1])
            callback = compressed_headers['callback'][1:-1]
            log.debug('Subscriber callback: %s' % callback)
            subscriber = Subscriber(self.service, timeout,
                                callback, request.server_protocol,
                                self.event_reload_time,
                                self.force_event_reload)
            response_body = self._get_subscribe_response(request,
                                                         response, subscriber)
            self.subscribers.append(subscriber)

            eventing_variables = {}
            for var_name, state_var in list(self.service.get_variables().items()):
                eventing_variables[var_name] = state_var.get_value()
            EventMessage(subscriber, eventing_variables, 1, "")

            # Try to unsubscribe after the timeout
            t_call = ThreadedCall(self._auto_remove_subscriber, None, None,
                                  None, None, timeout * 1.1,
                                  "uuid:" + str(subscriber.subscription_id))
            reactor.add_after_stop_func(t_call.stop)
            t_call.start()

            log.debug('Subscribe success')
            return response_body
        else:
            return self._build_error(request_status, request, response)

    def _validate_subscribe_request(self, request, compressed_headers):
        log.debug('Validating subscribe request')
        #TODO: verify if the callback url is a valid one
        if not 'callback' in compressed_headers:
            log.error('There is not a callback at the request')
            return 412

        if (not 'nt' in compressed_headers) or \
           (compressed_headers['nt'] != "upnp:event"):
            return 412

        #TODO: Put the verification of error 5xx

        # No errors
        return 200

    def _get_subscribe_response(self, request, response_obj, subscriber):
        log.debug('Building subscribe response')
        response_obj.status = 200

        #TODO: date
        response_obj.headers["DATE"] = ''
        response_obj.headers["SERVER"] = 'BRisa UPnP Framework'
        response_obj.headers["SID"] = 'uuid:' + str(subscriber.subscription_id)
        response_obj.headers["CONTENT-LENGTH"] = '0'
        response_obj.headers["TIMEOUT"] = 'Second-' \
                        + str(subscriber.subscription_duration)
        response_obj.body = ['\n']

        return response_obj.body

    def render_renew(self, request, response, compressed_headers):
        """ Renders the subscribe renew message for an event.

        @param request: request object
        @param response: response object

        """
        log.debug('Receiving renew request')
        request_status, subs = self._validate_renew_request(request,
                                                      compressed_headers)

        if request_status == 200:
            timeout = compressed_headers['timeout']
            subs.subscription_duration = int(timeout.split("-")[-1])
            subs.timestamp = datetime.now()

            return self._get_subscribe_response(request, response, subs)
        else:
            return self._build_error(request_status, request, response)

    def _validate_renew_request(self, request, compressed_headers):
        if 'callback' in compressed_headers or 'nt' in compressed_headers:
            log.error('Missing callback or nt')
            return 400, None

        subs = self._find_subscriber(compressed_headers['sid'])
        if not subs:
            log.error('Subscriber does not exist')
            return 412, None

        #TODO: Put the verification of error 5xx

        # No errors
        return 200, subs

    def _auto_remove_subscriber(self, sid):
        subscriber = self._find_subscriber(sid)
        if not subscriber:
            #Already unsubscribe
            return

        time_delta = datetime.now() - subscriber.timestamp
        if time_delta.seconds > subscriber.subscription_duration:
            log.debug('Subscriber sid:%s timeout'
                      % str(subscriber.subscription_id))
            self._remove_subscriber(subscriber)
        else:
            subscriber.timestamp = datetime.now()

            # Try to unsubscribe after the timeout
            t_call = ThreadedCall(self._auto_remove_subscriber, None, None,
                 None, None, subscriber.subscription_duration * 1.1,
                 sid)
            reactor.add_after_stop_func(t_call.stop)
            t_call.start()

    def render_unsubscribe(self, request, response, compressed_headers):
        """ Renders the unsubscribe message for an event.

        @param request: request object
        @param response: response object

        """
        log.debug('Receiving unsubscribe request')
        request_status, subs = self._validate_unsubscribe_request(request,
                                                            compressed_headers)

        if request_status == 200:
            self._remove_subscriber(subs)

            response.status = 200
            response.body = [""]
            return response.body
        else:
            return self._build_error(request_status, request, response)

    def _validate_unsubscribe_request(self, request, compressed_headers):

        if not 'sid' in compressed_headers:
            log.error('Missing sid')
            return 412, None

        if 'callback' in compressed_headers or 'nt' in compressed_headers:
            log.error('Missing callback or nt')
            return 400, None

        subs = self._find_subscriber(compressed_headers['sid'])
        if not subs:
            log.error('Subscriber does not exist')
            return 412, None

        # No errors
        return 200, subs

    def _build_error(self, request, response_obj, status):
        log.error('Building error response')
        response = soap.build_soap_error(status)

        response_obj.status = 500

        if self.encoding is not None:
            mime_type = 'text/xml; charset="%s"' % self.encoding
        else:
            mime_type = "text/xml"
        response_obj.headers["Content-type"] = mime_type
        response_obj.headers["Content-length"] = str(len(response))
        response_obj.headers["EXT"] = ''
        response_obj.body = response
        return response

    def _find_subscriber(self, sid):
        for subscribe in self.subscribers:
            if str(subscribe.subscription_id) == sid[5:]:
                return subscribe
        return None

    def _remove_subscriber(self, subscriber):
        subscriber.stop()
        self.subscribers.remove(subscriber)


class Subscriber:

    def __init__(self, service, subscription_duration, delivery_url, http_version,
                 event_reload_time, force_event_reload):

        self.service = service
        self.subscription_id = uuid.uuid4()
        self.delivery_url = delivery_url
        self.event_key = 0
        self.subscription_duration = subscription_duration
        self.http_version = http_version
        self.timestamp = datetime.now()

        self.eventing_variables = {}
        for name, state_var in list(self.service.get_variables().items()):
            state_var.subscribe_for_update(self._update_variable)

        self.force_event_reload = force_event_reload
        if not force_event_reload:
            self.looping_call = LoopingCall(self._send_variables)
            reactor.add_after_stop_func(self.looping_call.stop)
            self.looping_call.start(event_reload_time, False)

        sid = str(self.subscription_id)
        log.debug('Creating subscriber with subscription id: %s' % sid)

    def event_key_increment(self):
        self.event_key += 1
        if self.event_key > 4294967295:
            self.event_key = 1

    def _update_variable(self, name, value):
        if self.force_event_reload:
            self.eventing_variables[name] = value
            self._send_variables()
            return

        if name in list(self.eventing_variables.keys()) and \
            self.eventing_variables[name] != value:
            self._send_variables()

        self.eventing_variables[name] = value

    def _send_variables(self):
        if self.eventing_variables:
            EventMessage(self, self.eventing_variables, 0, "")
            self.eventing_variables = {}

    def stop(self):
        for name, state_var in list(self.service.get_variables().items()):
            state_var.unsubscribe_for_update(self._update_variable)

        # When called stop() manually, remove the before stop callback
        if not self.force_event_reload:
            reactor.rem_after_stop_func(self.looping_call.stop)
            self.looping_call.stop()


def build_notify_message_body(variables):
    log.debug("Building event message body")
    property_set = ElementTree.Element("e:propertyset")
    property_set.attrib.update({'xmlns:e':
                                "urn:schemas-upnp-org:event-1-0"})

    for var_name, var_value in list(variables.items()):
        property = ElementTree.SubElement(property_set, "e:property")

        try:
            var_val = map_upnp_value(var_value)
        except:
            #TODO - raise an error?
            log.error("Unknown state variable type")
            pass
                
        if var_val == None:
            var_val = ''

        e = ElementTree.SubElement(property, var_name)
        e.text = var_val

    return ElementTree.tostring(property_set, 'utf-8')


class EventMessage:
    """ Wrapper for an event message.
    """

    def __init__(self, subscriber, variables, event_delay, cargo):
        """ Constructor for the EventMessage class.

        @param subscriber: subscriber that will receive the message
        @param variables: variables of the event
        @param event_delay: delay to wait before sending the event
        @param cargo: callback parameters

        @type subscriber: Subscriber
        @type variables: dict
        @type event_delay: float
        """
        log.debug("event message")

        if not variables:
            log.error("There are no variables to send")
            return

        self.cargo = cargo

        headers = {}
        headers["HOST"] = subscriber.delivery_url
        headers["CONTENT-TYPE"] = 'text/xml'
        headers["NT"] = 'upnp:event'
        headers["NTS"] = 'upnp:propchange'
        headers["SID"] = "uuid:" + str(subscriber.subscription_id)
        headers["SEQ"] = str(subscriber.event_key)
        subscriber.event_key_increment()

        event_body = self._build_message_body(variables)

        headers["CONTENT-LENGTH"] = str(len(event_body))

        log.debug("Running http call")
        run_async_call(http_call, success_callback=self.response,
                       error_callback=self.error, delay=event_delay,
                       method='NOTIFY', url=subscriber.delivery_url,
                       body=event_body, headers=headers)

    def _build_message_body(self, variables):
        log.debug("Building unicast message body to variables: %s" 
                  % str(variables))
        preamble = """<?xml version="1.0" encoding="utf-8"?>"""
        return '%s%s' % (preamble, build_notify_message_body(variables))

    def error(self, cargo, error):
        """ Callback for receiving an error.

        @param cargo: callback parameters passed at construction
        @param error: exception raised

        @type error: Exception

        @rtype: boolean
        """
        log.debug("error", error)
        return True

    def response(self, http_response, cargo):
        """ Callback for receiving the HTTP response on a successful HTTP call.

        @param http_response: response object
        @param cargo: callback parameters passed at construction

        @type http_response: HTTPResponse

        @rtype: boolean
        """
        log.debug("response")
        return True


class MulticastEventController:

    msg_already_started = 'tried to start() MulticastEventController when already started'
    msg_already_stopped = 'tried to stop() MulticastEventController when already stopped'

    def __init__(self, parent_udn, service, event_reload_time, force_event_reload):
        self.service = service
        self.parent_udn = parent_udn
        self.udp_transport = UDPTransport()
        self.eventing_variables = {}
        self.event_key = 0
        self.event_reload_time = event_reload_time
        self.force_event_reload = force_event_reload

        if not self.force_event_reload:
            self.l_call = LoopingCall(self.send_variables)
            reactor.add_after_stop_func(self.stop)
        self._is_running = False

    def send_variables(self):
        if not self.eventing_variables:
            return

        #FIXME - fix BOOTID.UPNP.ORG
        notify_msg = ['NOTIFY * HTTP/1.0',
                'HOST: %s:%d' % (UPnPDefaults.MULTICAST_EVENT_ADDR,
                                 UPnPDefaults.MULTICAST_EVENT_PORT),
                'CONTENT-TYPE: text/xml; charset="utf-8"',
                'USN: %s::%s' % (str(self.parent_udn), self.service.service_type),
                'SVCID: %s' % (str(self.service.id)),
                'NT: upnp:event',
                'NTS: upnp:propchange',
                'SEQ: %d' % (self.event_key),
                'LVL: upnp:/info',
                'BOOTID.UPNP.ORG: 0']

        body = self._build_message_body(self.eventing_variables)

        notify_msg.append('CONTENT-LENGTH: %d' % len(body))
        # Empyt line
        notify_msg.append('')
        notify_msg.append(body)

        self.udp_transport.send_data('\r\n'.join(notify_msg), UPnPDefaults.MULTICAST_EVENT_ADDR,
                                     UPnPDefaults.MULTICAST_EVENT_PORT)
        self.event_key_increment()
        self.eventing_variables = {}

    def _update_variable(self, name, value):
        if self.force_event_reload:
            self.eventing_variables[name] = value
            self.send_variables()
            return

        if name in self.eventing_variables and \
            self.eventing_variables[name] != value:
            self.send_variables()

        self.eventing_variables[name] = value

    def _build_message_body(self, variables):
        log.debug("Building multicast message body to variables: %s" 
                  % str(variables))
        preamble = """<?xml version="1.0"?>"""
        return '%s%s' % (preamble, build_notify_message_body(variables))

    def event_key_increment(self):
        self.event_key += 1
        if self.event_key > 4294967295:
            self.event_key = 1

    def is_running(self):
        """ Returns True if the listener is running.

        @rtype: boolean
        """
        if not self.force_event_reload:
            self._is_running = self.l_call.is_running()
        return self._is_running

    def start(self):
        """ Starts the listener.
        """
        if not self.is_running():
            for name, state_var in list(self.service.get_variables().items()):
                if state_var.send_events and state_var.multicast:
                    state_var.subscribe_for_update(self._update_variable)

            if not self.force_event_reload:
                self.l_call.start(self.event_reload_time)
            self._is_running = True
            log.debug('Multicast event controller started with event reload time: %d'
                      % self.event_reload_time)
        else:
            log.warning(self.msg_already_started)

    def stop(self):
        """ Stops the search.
        """
        if self.is_running():
            log.debug('Multicast event controller stopped')
            for name, state_var in list(self.service.get_variables().items()):
                if state_var.send_events and state_var.multicast:
                    state_var.unsubscribe_for_update(self._update_variable)

            if not self.force_event_reload:
                self.l_call.stop()
                reactor.rem_after_stop_func(self.stop)
            self._is_running = False
        else:
            log.warning(self.msg_already_stopped)

    def destroy(self):
        """ Destroys and quits MSearch.
        """
        if self.is_running():
            self.stop()
        self._cleanup()

    def _cleanup(self):
        """ Clean up references.
        """
        self.service = None
        self.udp_transport = None
        self.eventing_variables = None
        self.l_call = None
