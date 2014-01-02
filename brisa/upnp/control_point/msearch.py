# Licensed under the MIT license
# http://opensource.org/licenses/mit-license.php or see LICENSE file.
#
# Copyright (C) 2006 Fluendo, S.A. (www.fluendo.com).
# Copyright 2006, Frank Scholz <coherence@beebits.net>
# Copyright 2007-2008 Brisa Team <brisa-develop@garage.maemo.org>

""" Contains the MSearch class which can search for devices.
"""

from brisa.core import log
from brisa.core.network import parse_http_response
from brisa.core.network_senders import UDPTransport
from brisa.core.network_listeners import UDPListener
from brisa.utils.looping_call import LoopingCall
from brisa.upnp.upnp_defaults import UPnPDefaults


DEFAULT_SEARCH_TIME = UPnPDefaults.MSEARCH_DEFAULT_SEARCH_TIME
DEFAULT_SEARCH_TYPE = UPnPDefaults.MSEARCH_DEFAULT_SEARCH_TYPE
DEFAULT_SSDP_ADDR = UPnPDefaults.SSDP_ADDR


class MSearch(object):
    """ Represents a MSearch. Contains some control functions for starting and
    stopping the search. While running, search will be repeated in regular
    intervals specified at construction or passed to the start() method.
    """

    msg_already_started = 'tried to start() MSearch when already started'
    msg_already_stopped = 'tried to stop() MSearch when already stopped'

    def __init__(self, ssdp, start=True, interval=DEFAULT_SEARCH_TIME,
                 ssdp_addr=DEFAULT_SSDP_ADDR, ssdp_port=1900):
        """ Constructor for the MSearch class.

        @param ssdp: ssdp server instance that will receive new device events
        and subscriptions
        @param start: if True starts the search when constructed
        @param interval: interval between searchs
        @param ssdp_addr: ssdp address for listening (UDP)
        @param ssdp_port: ssdp port for listening (UDP)

        @type ssdp: SSDPServer
        @type start: boolean
        @type interval: float
        @type ssdp_addr: string
        @type ssdp_port integer
        """
        self.ssdp = ssdp
        self.ssdp_addr = ssdp_addr
        self.ssdp_port = ssdp_port
        self.udp_transport = UDPTransport()
        self.listen_udp = UDPListener(ssdp_addr,
                                      data_callback=self._datagram_received,
                                      shared_socket=self.udp_transport.socket)
        self.loopcall = LoopingCall(self.double_discover)
        if start:
            self.start(interval)

    def is_running(self):
        """ Returns True if the search is running (it's being repeated in the
        interval given).

        @rtype: boolean
        """
        return self.loopcall.is_running()

    def start(self, interval=DEFAULT_SEARCH_TIME,
              search_type=DEFAULT_SEARCH_TYPE, http_version="1.1",
              man='"ssdp:discover"', mx=1, additionals={}):
        """ Starts the search.

        @param interval: interval between searchs. Default is 600.0 seconds
        @param search_type: type of the search, default is "ssdp:all"
        @param http_version: http version for m-search (default is 1.1)
        @param man: man field for m-search (default is ssdp:discover)
        @param mx: mx field for m-search (default is 1)
        @param additionals: dict containing additional field to be appended
                            in the end of the m-search message (default is
                            a empty dictionary)

        @type interval: float
        @type search_type: string
        @type http_version: string
        @type man: string
        @type mx: int
        @type additionals: dict
        """
        if not self.is_running():
            self.ssdp.search_type = search_type
            self.listen_udp.start()
            self.loopcall._args = (search_type, http_version, man, mx,
                                       additionals, )
            self.loopcall.start(interval, now=True)
            log.debug('MSearch started')
        else:
            log.warning(self.msg_already_started)

    def stop(self):
        """ Stops the search.
        """
        if self.is_running():
            log.debug('MSearch stopped')
            self.listen_udp.stop()
            self.loopcall.stop()
        else:
            log.warning(self.msg_already_stopped)

    def destroy(self):
        """ Destroys and quits MSearch.
        """
        if self.is_running():
            self.stop()
        self.listen_udp.destroy()
        self.loopcall.destroy()
        self._cleanup()

    def double_discover(self, search_type=DEFAULT_SEARCH_TYPE,
                            http_version="1.1", man='"ssdp:discover"', mx=1,
                        additionals={}):
        """ Sends a MSearch imediatelly. Each call to this method will yield a
        MSearch message, that is, it won't repeat automatically.
        """
        log.info("Doing double discover for %s, HTTP_VERSION=%s, MAN=%s, \
                 MX=%d, additionals=%s" % (search_type, http_version, man, mx,
                                            additionals))
        self.discover(search_type, http_version, man, mx, additionals)

    def discover(self, search_type=DEFAULT_SEARCH_TYPE, http_version="1.1",
                     man='"ssdp:discover"', mx=1, additionals={}):
        """ Builds and sends the discover message (MSearch).

        @param type: search type
        @type type: string
        """
        if (mx > 120):
            mx = 120
        elif (mx < 1):
            mx = 1
        req = ['M-SEARCH * HTTP/%s' % http_version,
               'HOST: %s:%d' % (self.ssdp_addr, self.ssdp_port),
               'MAN: %s' % man,
               'MX: %s' % mx,
               'ST: %s' % search_type]
        append = req.append
        [append('%s: %s' % (k, v)) for k, v in list(additionals.items())]
        append('')
        append('')
        req = '\r\n'.join(req)
        self.udp_transport.send_data(req, self.ssdp_addr, self.ssdp_port)

    def _datagram_received(self, data, address):
        """ Callback for the UDPListener when messages arrive.

        @param data: raw data received
        @param host: host where data came from
        @param port: port where data came from

        @type data: string
        @type host: string
        @type port: integer
        """
        (host, port) = address
        cmd, headers = parse_http_response(data)
        if cmd[0].startswith('HTTP/1.') and cmd[1] == '200':
            if self.ssdp != None:
                if not self.ssdp.is_known_device(headers['usn']):
                    log.debug('Received MSearch answer %s,%s from %s:%s',
                              headers['usn'], headers['st'], host, port)
                    default_fields_name = ["usn", "st", "location", "server",
                                           "cache-control", "ext"]
                    default_header = {}
                    for field in default_fields_name:
                        default_header[field] = headers.pop(field, "")
                    self.ssdp.register(default_header['usn'],
                                       default_header['st'],
                                       default_header['location'],
                                       default_header['server'],
                                       default_header['cache-control'],
                                       "remote", headers)

    def _cleanup(self):
        """ Clean up references.
        """
        self.ssdp = None
        self.listen_udp = None
        self.loopcall = None
