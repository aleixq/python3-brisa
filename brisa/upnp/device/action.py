# Licensed under the MIT license
# http://opensource.org/licenses/mit-license.php or see LICENSE file.
# Copyright 2007-2008 Brisa Team <brisa-develop@garage.maemo.org>

""" Device-side action class used for implementing UPnP actions.
"""

from brisa.upnp.base_action import BaseAction, BaseArgument

from brisa.core import log


class InvalidActionOutput(Exception):
    pass


class InvalidActionInput(Exception):
    pass


class Argument(BaseArgument):
    pass


class Action(BaseAction):

    def __init__(self, service, name, arguments = []):
        BaseAction.__init__(self, service, name, arguments)
        self.run_function = self.run

    def add_argument(self, argument):
        """ Adds an argument to the action.
        
        @param argument: the argument
        @type argument: ArgumentDevice
        """        
        if argument:
            self.arguments.append(argument)

    def get_in_argument(self, name):
        """ Returns the in argument with the given name.
        
        @param name: argument name
        @type name: string
        
        @rtype: Argument
        """        
        for arg in self.arguments:
            if arg.direction == Argument.IN and arg.name == name:
                return arg
        return None

    def get_out_argument(self, name):
        """ Returns the out argument with the given name.
        
        @param name: argument name
        @type name: string
        
        @rtype: Argument
        """        
        for arg in self.arguments:
            if arg.direction == Argument.OUT and arg.name == name:
                return arg
        return None

    def __call__(self, *args, **kwargs):
        log.debug('Entering at action %s __call__' % self.name)
        # Update in arguments
        in_kwargs = {}

        log.debug('Updating IN variables')
        for arg_name, arg_value in list(kwargs.items()):
            if arg_name != '__header__':
                arg = self.get_in_argument(arg_name)
                if not arg:
                    log.error('Input argument "%s" not' \
                              ' present on action definition.' \
                              % arg_name)
                    raise InvalidActionInput('Input argument "%s" not' \
                                             ' present on action definition.' \
                                             % arg_name)
                if arg.state_var:
                    arg.state_var.update(arg_value)
            in_kwargs[arg_name] = arg_value

        log.debug('Calling run function')
        returned_kwargs = self.run_function(*(), **in_kwargs)

        if not isinstance(returned_kwargs, dict):
            msg = 'returned value from service function is not a dict.'
            log.error(msg)
            raise InvalidActionOutput(msg)

        # Update out arguments
        out_kwargs = {}

        log.debug('Updating OUT variables')
        for arg_name, arg_value in list(returned_kwargs.items()):
            if arg_name != '__header__':
                arg = self.get_out_argument(arg_name)
                if not arg:
                    log.error('output contains argument "%s" not'\
                              ' present on action definition' % \
                              arg_name)
                    raise InvalidActionOutput('output contains argument "%s" not'\
                                              ' present on action definition' % \
                                              arg_name)

                if arg.state_var:
                        arg.state_var.update(arg_value)
            out_kwargs[arg_name] = arg_value

        log.debug('Returning from action %s __call__' % self.name)
        if "__header__" in out_kwargs:
            header = out_kwargs.pop('__header__', {})
            return {self.name + "Response": out_kwargs,
                    "__header__": header}
        else:
            return {self.name + "Response": out_kwargs}

    def run(self, *args, **kwargs):
        return {}
