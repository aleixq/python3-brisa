# Licensed under the MIT license
# http://opensource.org/licenses/mit-license.php or see LICENSE file.
#
# Copyright 2005, Tim Potter <tpot@samba.org>
# Copyright 2006 John-Mark Gurney <gurney_j@resnet.uroegon.edu>
# Copyright 2007-2008 Brisa Team <brisa-develop@garage.maemo.org>

""" SSDP Server implementation which listens for devices messages and searches.

When used implementing a device, it's used for announcing the device, its
embedded devices and all services.

When used on a control point, it's used for keeping record of known devices
(obtained through search or announcements).
"""

import random

from brisa.core import log
from brisa.core.network_senders import UDPTransport
from brisa.core.network_listeners import UDPListener

from brisa.utils.looping_call import LoopingCall

from brisa.upnp.upnp_defaults import UPnPDefaults

SSDP_ADDR = UPnPDefaults.SSDP_ADDR
SSDP_PORT = UPnPDefaults.SSDP_PORT

log = log.getLogger('upnp.ssdp')


class SSDPServer(object):
    """ Implementation of a SSDP server.

    The notify_received and search_received methods are called when the
    appropriate type of datagram is received by the server.
    """

    msg_already_started = 'tried to start() SSDPServer when already started'
    msg_already_stopped = 'tried to stop() SSDPServer when already stopped'

    def __init__(self, server_name, xml_description_filename, max_age=1800,
                receive_notify=True, http_version="1.1",
                search_type="sspd:all", additional_headers={}):
        """ Constructor for the SSDPServer class.

        @param server_name: server name
        @param xml_description_filename: XML description filename
        @param max_age: max age parameter, default 1800.
        @param receive_notify: if False, ignores notify messages

        @type server_name: string
        @type xml_description_filename:
        @type max_age: integer
        @type receive_notify: boolean
        """
        self.server_name = server_name
        self.xml_description_filename = xml_description_filename
        self.max_age = max_age
        self.receive_notify = receive_notify
        self.running = False
        self.http_version = http_version
        self.known_device = {}
        self.advertised = {}
        self._callbacks = {}
        self.additional_headers = additional_headers
        self.search_type = search_type
        self.udp_transport = UDPTransport()
        self.udp_listener = UDPListener(SSDP_ADDR, SSDP_PORT,
                                        data_callback=self._datagram_received)
        self.renew_loop = LoopingCall(self._renew_notifications)
        self.renew_loop.start(0.8 * self.max_age, now=True)

    def is_running(self):
        """ Returns True if the SSDPServer is running, False otherwise.
        """
        return self.running

    def start(self):
        """ Starts the SSDPServer.
        """
        if not self.is_running():
            self.udp_listener.start()
            self.running = True
        else:
            log.warning(self.msg_already_started)

    def stop(self):
        """ Sends bye bye notifications and stops the SSDPServer.
        """
        if self.is_running():
            # Avoid racing conditions
            own_temp = self.advertised.copy()
            for usn in own_temp:
                self._do_byebye(usn)

            self.renew_loop.stop()
            self.udp_listener.stop()
            self.running = False
        else:
            log.warning(self.msg_already_stopped)

    def destroy(self):
        """ Destroys the SSDPServer.
        """
        if self.is_running():
            self.stop()
        self.renew_loop.destroy()
        self.udp_listener.destroy()
        self._cleanup()

    def clear_device_list(self):
        """ Clears the device list.
        """
        self.known_device.clear()

    def discovered_device_failed(self, dev):
        """ Device could not be fully built, so forget it.
        """
        usn = dev['USN']
        if usn in self.known_device:
            self.known_device.pop(usn)

    def is_known_device(self, usn):
        """ Returns if the device with the passed usn is already known.

        @param usn: device's usn
        @type usn: string

        @return: True if it is known
        @rtype: boolean
        """
        return usn in self.known_device

    def subscribe(self, name, callback):
        """ Subscribes a callback for an event.

        @param name: name of the event. May be "new_device_event" or
                     "removed_device_event"
        @param callback: callback

        @type name: string
        @type callback: callable
        """
        self._callbacks.setdefault(name, []).append(callback)

    def unsubscribe(self, name, callback):
        """ Unsubscribes a callback for an event.

        @param name: name of the event
        @param callback: callback

        @type name: string
        @type callback: callable
        """
        callbacks = self._callbacks.get(name, [])
        [callbacks.remove(c) for c in callbacks]
        self._callbacks[name] = callbacks

    def announce_device(self):
        """ Announces the device.
        """
        [self._do_notify(usn) for usn in self.advertised]

    def register_device(self, device):
        """ Registers a device on the SSDP server.

        @param device: device to be registered
        @type device: Device
        """
        self._register_device(device)
        if device.is_root_device():
            [self._register_device(d) for d in list(device.devices.values())]

    # Messaging

    def _datagram_received(self, data, address):
        """ Handles a received multicast datagram.

        @param data: raw data
        @param host: datagram source host
        @param port: datagram source port

        @type data: string
        @type host: string
        @type port: integer
        """
        (host, port) = address
        try:
            header, payload = data.split('\r\n\r\n')
        except ValueError as err:
            log.error('Error while receiving datagram packet: %s', str(err))
            return

        lines = header.split('\r\n')
        cmd = lines[0].split(' ')
        lines = [x.replace(': ', ':', 1) for x in lines[1:]]
        lines = [x for x in lines if len(x) > 0]

        headers = [x.split(':', 1) for x in lines]
        headers = dict([(x[0].lower(), x[1]) for x in headers])

        # TODO: check http version
        if cmd[0] == 'M-SEARCH' and cmd[1] == '*' \
           and headers['man'] == '"ssdp:discover"':
           # SSDP discovery
           log.debug('Received M-Search command from %s:%s', host, port)
           self._discovery_request(headers, (host, port))
        elif cmd[0] == 'NOTIFY' and cmd[1] == '*':
            if not self.receive_notify:
                # Ignore notify
                      log.debug('Received NOTIFY command from %s:%s (ignored '\
                        'because of SSDPServer.receive_notify is False)',
                        host, port)
                      return
            if self.search_type != "upnp:rootdevice" and \
                self.search_type != "sspd:all" and \
                self.search_type != headers['nt']:
                # Ignore notify
                      log.debug('Received NOTIFY command from %s:%s (ignored '\
                        'because of SSDPServer.search_type is different'\
                        'than headers["nt"])',
                        host, port)
                      return
            # SSDP presence
            self._notify_received(headers, (host, port))
        else:
           log.warning('Received unknown SSDP command %s with headers %s '\
                       'from %s:%s', cmd, str(headers), host, port)

    def _discovery_request(self, headers, address):
        """ Processes discovery requests and responds accordingly.

        @param headers: discovery headers
        @param host: discovery source host
        @param port: discovery source port

        @type headers: dictionary
        @type host: string
        @type port integer
        """
        (host, port) = address
        for dev_info in list(self.known_device.values()):
            if (headers['st'] == 'ssdp:all' or dev_info['ST'] == headers['st']):
                response = []
                append = response.append
                append('HTTP/%s 200 OK' % self.http_version)
                additional_headers = dev_info.pop("ADDITIONAL_HEADERS", {})
                [append('%s: %s' % (k, v)) for k, v in list(dev_info.items())]
                [append('%s: %s' % (k, v)) for k, v in list(additional_headers.items())]
                dev_info['ADDITIONAL_HEADERS'] = additional_headers
                response.extend(('', ''))
                delay = random.randint(0, int(headers['mx']))
                # Avoid using a timer with delay 0 :)
                if delay:
                    self.udp_transport.send_delayed(delay, '\r\n'.join(response),
                                                    host, port)
                else:
                    self.udp_transport.send_data('\r\n'.join(response),
                                                        host, port)
                log.debug('Discovery request response sent to (%s, %d)',
                                                    host, port)

    def _notify_received(self, headers, address):
        """ Processes a presence announcement.

        @param headers: notify headers
        @param host: notify source host
        @param port: notify source port

        @type headers: dictionary
        @type host: string
        @type port: integer
        """
        (host, port) = address
        if headers['nts'] == 'ssdp:alive':
            if 'cache-control' not in headers:
                headers['cache-control'] = 'max-age=1800'
            try:
                self.known_device[headers['usn']]
            except KeyError:
                default_fields_name = ["usn", "nt", "location", "server",
                                       "cache-control", "host", "nts"]
                default_header = {}
                for field in default_fields_name:
                    default_header[field] = headers.pop(field, "")
                self.register(default_header['usn'],
                                   default_header['nt'],
                                   default_header['location'],
                                   default_header['server'],
                                   default_header['cache-control'],
                                   "remote", headers)
        elif headers['nts'] == 'ssdp:byebye':
            if self.is_known_device(headers['usn']):
                self._unregister(headers['usn'])
        else:
            log.warning('Unknown subtype %s for notification type %s',
                        headers['nts'], headers['nt'])

    # Registering

    def register(self, usn, st, location, server, cache_control,
                  where='remote', additional_headers={}):
        """ Registers a service or device.

        @param usn: usn
        @param st: st
        @param location: location
        @param server: server
        @param cache_control: cache control

        @type usn: string
        @type location: string
        @type st: string
        @type server: string
        @type cache_control: string

        @note: these parameters are part of the UPnP Specification. Even though
        they're abstracted by the framework (devices and services messages
        already contain these parameters), if you want to understand it please
        refer to the UPnP specification. Links can be found at the developer
        documentation homepage.
        """
        if where == 'remote':
            self.known_device[usn] = {'USN': usn,
                                      'LOCATION': location,
                                      'ST': st,
                                      'EXT': '',
                                      'SERVER': server,
                                      'CACHE-CONTROL': cache_control,
                                      'ADDITIONAL_HEADERS': additional_headers}
        elif where == 'local':
            self.advertised[usn] = {'USN': usn,
                                      'LOCATION': location,
                                      'ST': st,
                                      'EXT': '',
                                      'SERVER': server,
                                      'CACHE-CONTROL': cache_control,
                                      'ADDITIONAL_HEADERS': ""}

        #if st == 'upnp:rootdevice' and where == 'remote':
        if where == 'remote':
            self._callback("new_device_event", st, self.known_device[usn])

    def _local_register(self, usn, st, location, server, cache_control):
        """ Registers locally a new service or device.
        """
        log.debug('Registering locally %s (%s)', st, location)
        self.register(usn, st, location, server, cache_control, 'local')
        self._do_notify(usn)

    def _register_device(self, device):
        device_id = device.udn
        device_type = device.device_type
        device_server = "BRisa Webserver UPnP/1.0 %s" % self.server_name
        device_location = "%s/%s" % (device.location,
                                     self.xml_description_filename)
        age = 'max-age=%d' % self.max_age

        # uuid:device-UUID::upnp:rootdevice
        self._local_register('%s::upnp:rootdevice' % device_id,
                             'upnp:rootdevice',
                             device_location,
                             device_server, age)

        # uuid:device-UUID
        self._local_register(device_id,
                             device_id,
                             device_location,
                             device_server, age)


        # urn:schemas-upnp-org:device:deviceType:v
        self._local_register('%s::%s' % (device_id, device_type),
                             device_type, device_location,
                             device_server, age)

        for serv_type, service in list(device.services.items()):
            # urn:schemas-upnp-org:service:serviceType:v
            self._local_register('%s::%s' % (device_id, service.service_type),
                                 service.service_type,
                                 device_location, device_server, age)

    def _renew_notifications(self):
        """ Renew notifications (sends a notify
        """
        own_temp = self.advertised.copy()
        for usn in own_temp:
            log.debug('Renew notification for %s ', own_temp[usn]['USN'])
            self._do_notify(own_temp[usn]['USN'])

    def _unregister(self, usn):
        log.debug("Unregistering %s", usn)

        try:
            self._callback("removed_device_event", self.known_device[usn])
            if usn in self.known_device:
                del self.known_device[usn]
        except:
            log.debug("Error unregistering device with usn %s" % usn)

    # Notify and byebye

    def _do_notify(self, usn):
        """ Do a notification for the usn specified.

        @param usn: st
        @type usn: string
        """
        log.debug('Sending alive notification for %s', usn)
        response = ['NOTIFY * HTTP/%s' % self.http_version,
                'HOST: %s:%d' % (SSDP_ADDR, SSDP_PORT),
                'NTS: ssdp:alive', ]
        stcpy = dict(iter(list(self.advertised[usn].items())))
        stcpy['NT'] = stcpy['ST']
        del stcpy['EXT']
        del stcpy['ST']
        response.extend([': '.join(x) for x in iter(list(stcpy.items()))])
        append = response.append
        [append('%s: %s' % (k, v)) for k, v in list(self.additional_headers.items())]
        response.extend(('', ''))
        log.debug('Sending notify message with content %s' % response)
        try:
            self.udp_transport.send_data('\r\n'.join(response), SSDP_ADDR, SSDP_PORT)
            self.udp_transport.send_data('\r\n'.join(response), SSDP_ADDR, SSDP_PORT)
        except Exception as e:
            log.info("Failure sending notify with message %s" % str(e))

    def _do_byebye(self, usn):
        """ Do byebye notification for the usn specified.

        @param usn: usn
        @type usn: string
        """
        log.debug('Sending byebye notification for %s', usn)
        response = ['NOTIFY * HTTP/1.1', 'HOST: %s:%d' % (SSDP_ADDR, SSDP_PORT),
                'NTS: ssdp:byebye', ]
        stcpy = dict(iter(list(self.advertised[usn].items())))
        stcpy['NT'] = stcpy['ST']
        del stcpy['ST']
        del stcpy['EXT']
        response.extend([': '.join(x) for x in iter(list(stcpy.items()))])
        response.extend(('', ''))
        self.udp_transport.send_data('\r\n'.join(response), SSDP_ADDR, SSDP_PORT)
        self.udp_transport.send_data('\r\n'.join(response), SSDP_ADDR, SSDP_PORT)

    # Eventing

    def _callback(self, name, *args):
        """ Performs callbacks for events.
        """
        for callback in self._callbacks.get(name, []):
            callback(*args)

    # Cleanup

    def _cleanup(self):
        """ Cleans the SSDPServer by removing known devices and internal cache.
        """
        self.clear_device_list()
