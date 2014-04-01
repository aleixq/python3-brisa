# Licensed under the MIT license
# http://opensource.org/licenses/mit-license.php or see LICENSE file.
# Copyright 2007-2008 Brisa Team <brisa-develop@garage.maemo.org>

""" Provides a base control point class that can be extended to any specialized
control point.
"""

from brisa.core import log
from brisa.upnp.ssdp import SSDPServer
from brisa.upnp.control_point.msearch import MSearch
from brisa.upnp.control_point.event import EventListenerServer, MulticastEventListener
from brisa.upnp.control_point.device import Device


log = log.getLogger('control-point.basic')


class ControlPoint(object):
    """ This class implements UPnP Control Point functionalities.

    The simplest way of using it is by subscribing for the device events,
    starting it with start() and search for devices with start_search().
    Note that after start() the control point will be already listening for
    notifications. It will be listening for search responses only after
    start_search().

    Available events for subscription:
        - new_device_event     - triggered when a new device is found
        - removed_device_event - triggered when a device announces its departure
        - device_event         - triggered when a device sends an event message

    You may stop the control point anytime with stop() and it can be reused by
    calling start() again. If you want to stop it definitely, you may use
    destroy().
    """
    msg_already_started = 'tried to start() ControlPoint when already started'
    msg_already_stopped = 'tried to stop() ControlPoint when already stopped'

    def __init__(self, receive_notify=True):
        """ControlPoint class constructor.

        @param receive_notify: if False, ignores notify messages from devices.
        Default value is True and it can be set during runtime

        @type receive_notify: boolean
        """
        self._ssdp_server = SSDPServer("BRisa Control Point", None,
                                      receive_notify=receive_notify)
        self._ssdp_server.subscribe("new_device_event", self._new_device_event)
        self._ssdp_server.subscribe("removed_device_event",
                                   self._removed_device_event)
        self._msearch = MSearch(self._ssdp_server, start=False)
        self._event_listener = EventListenerServer(self)
        self._multicast_event_listener = MulticastEventListener(self, start=False)
        self.event_host = self._event_listener.host()
        self._callbacks = {}
        self._known_devices = {}

    def get_devices(self):
        """ Returns a dict of devices found.
        """
        return self._known_devices

    def is_running(self):
        return self._ssdp_server.is_running() and \
               self._event_listener.is_running() and \
               self._multicast_event_listener.is_running()

    def start(self):
        """ Starts the control point.
        """
        if not self.is_running():
            self._ssdp_server.start()
            self._event_listener.start(self.event_host)
            self._multicast_event_listener.start()
        else:
            log.warning(self.msg_already_started)

    def stop(self):
        """ Stops the control point.
        """
        if self.is_running():
            if self.is_msearch_running():
                self.stop_search()
            self._ssdp_server.stop()
            self._event_listener.stop()
            self._multicast_event_listener.stop()
        else:
            log.warning(self.msg_already_stopped)

    def destroy(self):
        """ Destroys and quits the control point definitely.
        """
        if self.is_running():
            self.stop()
        self._msearch.destroy()
        self._ssdp_server.destroy()
        self._event_listener.destroy()
        self._multicast_event_listener.destroy()
        self._cleanup()

    def _cleanup(self):
        """ Cleanup references.
        """
        self._known_devices.clear()
        self._msearch = None
        self._ssdp_server = None
        self._event_listener = None
        self._multicast_event_listener = None

    def subscribe(self, name, callback):
        """ Subscribes the callback for an event.

        @param name: event name
        @param callback: callback which will listen on the event

        @type name: string
        @type callback: callable
        """
        self._callbacks.setdefault(name, []).append(callback)

    def unsubscribe(self, name, callback):
        """ Unsubscribes the callback for an event.

        @param name: event name
        @param callback: callback which listens for the event

        @type name: string
        @type callback: callable
        """
        callbacks = self._callbacks.get(name, [])
        if callback in callbacks:
            callbacks.remove(callback)

    def start_search(self, interval, search_type="ssdp:all", reset=False,
                         http_version="1.1", man='"ssdp:discover"', mx=1,
                     additionals={}):
        """ Sends a multicast M-SEARCH message to discover UPnP devices.

        @param interval: interval to wait between sending search messages
        @param search_type: UPnP type search. Default value is "ssdp:all"
        @param reset: clears the device list from any previous search
        @param http_version: http version for m-search (default is 1.1)
        @param man: man field for m-search (default is ssdp:discover)
        @param mx: mx field for m-search (default is 1)
        @param additionals: dict containing additional field to be appended
                            in the end of the m-search message (default is
                            a empty dictionary)


        @type interval: float
        @type search_type: string
        @type reset: boolean
        @type http_version: string
        @type man: string
        @type mx: int
        @type additionals: dict
        """
        if reset:
            self._ssdp_server.clear_device_list()
        self._msearch.start(interval, search_type, http_version, man, mx,
                            additionals)

    def stop_search(self):
        """ Stops the device search.
        """
        self._msearch.stop()

    def force_discovery(self, search_type="ssdp:all", http_version="1.1",
                            man='"ssdp:discover', mx=1, additionals={}):
        """ Forces a multicast MSearch bypassing the time interval. This method
        force msearch to send discovery message, bypassing the initial time
        interval passed to start_search function. Note this method doesn't
        cause any effect if the start_search call was never called. The
        additionals parameter is used to add additional fields in the
        M-SEARCH message.

        @param search_type: UPnP type search
        @param http_version: http version for m-search (default is 1.1)
        @param man: man field for m-search (default is ssdp:discover)
        @param mx: mx field for m-search (default is 1)
        @param additionals: dict containing additional field to be appended
                            in the end of the m-search message (default is
                            a empty dictionary)

        @type search_type: string
        @type http_version: string
        @type man: string
        @type mx: int
        @type additionals: dict
        """
        self._msearch.double_discover(search_type, http_version, man, mx,
                                      additionals)

    def is_msearch_running(self):
        """ Returns whether MSEARCH is running or not.

        @return: Status of the MSearch
        @rtype: boolean
        """
        return self._msearch.is_running()

    def _get_recv_notify(self):
        """ GET function for the receive_notify property. Use
        self.receive_notify instead.

        @return: The receive_notify status
        @rtype: boolean
        """
        return self._ssdp_server.receive_notify

    def _set_recv_notify(self, n):
        """ SET function for the receive_notify property. Use
        self.receive_notify instead.

        @param n: The value to be set.
        @type n: boolean
        """
        self._ssdp_server.receive_notify = n

    receive_notify = property(_get_recv_notify,
                              _set_recv_notify,
                              doc='If False, the control point ignores NOTIFY\
                              messages from devices.')

    def _new_device_event(self, st, device_info):
        """ Receives a new device event.

        @param st: defines the device type
        @param device_info: informations about the device

        @type st: string
        @type device_info: dict
        """
        # Callback assigned for new device event, processes asynchronously
        if 'LOCATION' not in device_info:
            return
        Device.get_from_location_async(device_info['LOCATION'],
                                       self._new_device_event_impl,
                                       device_info)

    def _new_device_event_impl(self, device_info, device):
        """ Real implementation of the new device event handler.

        @param device_info: informations about the device
        @param device: the device object itself

        @type device_info: dict
        @type device: Device
        """
        if not device and self._ssdp_server:
            # Device creation failed, tell SSDPSearch to forget it
            self._ssdp_server.discovered_device_failed(device_info)
            return

        device.additional_headers = device_info['ADDITIONAL_HEADERS']
        self._known_devices[device.udn] = device
        self._callback("new_device_event", device)
        log.info('Device found: %s' % device.friendly_name)

    def _removed_device_event(self, device_info):
        """ Receives a removed device event.

        @param device_info: information about the device

        @type device_info: dict
        """
        udn = device_info['USN'].split('::')[0]
        if udn in self._known_devices:
            log.info('Device is gone: %s' %
                     self._known_devices[udn].friendly_name)

        self._known_devices.pop(udn, None)
        self._callback("removed_device_event", udn)

    def _on_event(self, sid, changed_vars):
        """ Receives an event.

        @param sid: Service id
        @param changed_vars: Variables that have changed

        @type sid: str
        @type changed_vars: dict
        """
        self._callback("device_event", sid, changed_vars)

    def _callback(self, name, *args):
        """ Callback for any event. Forwards the event to the subscribed
        callbacks.

        @param name: event name
        @param args: arguments for the callbacks

        @type name: string
        @type args: tuple
        """
        for callback in self._callbacks.get(name, []):
            callback(*args)
