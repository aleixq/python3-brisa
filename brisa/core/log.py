# Licensed under the MIT license
# http://opensource.org/licenses/mit-license.php or see LICENSE file.
# Copyright 2007-2008 Brisa Team <brisa-develop@garage.maemo.org>

""" Log module with colored logging feature. Common usage of this module can
be only importing it and calling one of the available functions: debug,
warning, info, critical, error.
"""

import os
import logging

from logging import getLogger

from brisa import __enable_logging__
from brisa.core import config


BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = list(range(8))
RESET_SEQ = '\033[0m'
COLOR_SEQ = '\033[1;%dm'
BOLD_SEQ = '\033[1m'

COLORS = {
    'WARNING': YELLOW,
    'INFO': WHITE,
    'DEBUG': BLUE,
    'CRITICAL': YELLOW,
    'ERROR': RED}


def formatter_message(message, use_color = True):
    """ Method to format the pattern in which the log messages will be
    displayed.

    @param message: message log to be displayed
    @param use_color: Flag to indicates the use of colors or not

    @type message: str
    @type use_color: boolean

    @return: the new formatted message
    @rtype: str
    """
    if use_color:
        message = message.replace('$RESET', RESET_SEQ).replace('$BOLD',
                                                               BOLD_SEQ)
    else:
        message = message.replace('$RESET', '').replace('$BOLD', '')
    return message


class ColoredFormatter(logging.Formatter):
    """ ColoredFormatter class, which wrappers logging.Formatter. """

    def __init__(self, msg, use_color = True):
        """ Constructor of the ColoredFormatter class.

        @param msg: message to be displayed
        @param use_color: Flag to indicate the use of color or not

        @type msg: str
        @type use_color: boolean
        """
        logging.Formatter.__init__(self, msg)
        self.use_color = use_color

    def format(self, record):
        """ format method to the ColoredFormatter class that organizes the log
        message.

        @parameter record: information about the logger
        @type record: Instance of Logger, either its RootLogger or not
        """
        levelname = record.levelname
        if self.use_color and levelname in COLORS:
            levelname_color = COLOR_SEQ % (30 + COLORS[levelname]) + levelname\
                              + RESET_SEQ
            record.levelname = levelname_color
        return logging.Formatter.format(self, record)


class ColoredLogger(logging.Logger):

    FORMAT = '%(created)f $BOLD%(levelname)s$RESET $BOLD%(module)s:%(lineno)d'\
             ':%(funcName)s()$RESET %(message)s'
    COLOR_FORMAT = formatter_message(FORMAT, True)

    def __init__(self, name):
        """ Constructor for the ColoredLogger class.

        @param name: name of the Logger.
        @type name: str
        """
        global level
        logging.Logger.__init__(self, name, level)
        color_formatter = ColoredFormatter(self.COLOR_FORMAT)
        console = logging.StreamHandler()
        console.setFormatter(color_formatter)
        self.addHandler(console)


log_dict = {'WARNING': logging.WARNING,
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'CRITICAL': logging.CRITICAL,
            'ERROR': logging.ERROR}


def setup_logging():
    """ Method to setup the logging options. """
    global debug, info, warning, critical, error, root_logger, set_level,\
           setLevel, filename, level

    level = log_dict.get(config.get_parameter('brisa', 'logging'),
                         logging.DEBUG)
    filename = config.get_parameter('brisa', 'logging_output')

    if filename == 'file':
        filename = os.path.join(config.brisa_home, 'brisa.log')
        logging.basicConfig(level=level, filename=filename,
                            format='%(created)f %(levelname)s %(module)s:'\
                                   '%(lineno)d:%(funcName)s() %(message)s')
        root_logger = logging.getLogger('RootLogger')
    else:
        logging.setLoggerClass(ColoredLogger)
        root_logger = getLogger('RootLogger')
        root_logger.setLevel(level)

    def set_level(level):
        """ Real implementation of the set level function. """
        root_logger.setLevel(log_dict.get(level))

    def setLevel(level):
        """ Method to set the log level. """
        set_level(level)


root_logger = getLogger()

if __enable_logging__:
    setup_logging()

debug = root_logger.debug
info = root_logger.info
warning = root_logger.warning
critical = root_logger.critical
error = root_logger.error
