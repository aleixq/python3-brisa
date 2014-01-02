# Licensed under the MIT license
# http://opensource.org/licenses/mit-license.php or see LICENSE file.
# Copyright 2007-2008 Brisa Team <brisa-develop@garage.maemo.org>

""" Control Point side action class used for implementing UPnP actions.
"""

from brisa.upnp.base_action import BaseAction, BaseArgument


class Argument(BaseArgument):
    pass


class Action(BaseAction):
    """ Represents a service action.
    """

    def __init__(self, service, name, arguments = []):
        """ Constructor for the Action class.

        @param service: service which holds this action
        @param name: action name
        @param arguments: arguments list

        @type service: Service
        @type name: string
        @type arguments: list of Argument
        """
        BaseAction.__init__(self, service, name, arguments)

    def __call__(self, **kwargs):
        if not self.service._soap_service:
            raise RuntimeError('Service\'s soap service not created. Maybe '\
                               'generate_soap_service() was not called.')
        self.service._soap_service.soap_header = self.service.call_headers
        if "call_headers" in kwargs:
            self.service._soap_service.soap_header = kwargs.pop("call_headers",
                                                                {})
        response = self.service._soap_service.call_remote(self.name, **kwargs)
        self.service._soap_service.soap_header = self.service.call_headers
        return response
