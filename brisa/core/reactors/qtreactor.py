# Licensed under the GPLv2 License
# Copyright 2009 Brisa Team <brisa-develop@garage.maemo.org>

import signal

try:
    from PyQt5.QtCore import QSocketNotifier, QObject, QTimer, \
                                                QEventLoop
    from PyQt5 import QtCore
    from PyQt5.QtWidgets import *
    from brisa.core.ireactor import ReactorInterface, EVENT_TYPE_READ, \
                                EVENT_TYPE_WRITE, EVENT_TYPE_EXCEPTION, \
                                REACTOR_STATE_STOPPED, REACTOR_STATE_RUNNING
    __all__ = ('QtReactor', )
except ImportError:
    __all__ = ()

#from brisa.core import log
#log = log.getLogger('reactor.qt')

SEC_TO_MSEC = 10**3


class QtBRisaSocketNotifier(QObject):

    def __init__(self, fd, write, read, exception, event_callback):
        self.notifiers = []
        self.event_callback = event_callback
        fd = fd.fileno()
        if read:
            qsn = QSocketNotifier(fd, QSocketNotifier.Read)
            qsn.activated.connect(self.cb_read)
            qsn.setEnabled(True)
            self.notifiers.append(qsn)
        if write:
            qsn = QSocketNotifier(fd, QSocketNotifier.Write)
            qsn.activated.connect(self.cb_write)
            qsn.setEnabled(True)
            self.notifiers.append(qsn)
        if exception:
            qsn = QSocketNotifier(fd, QSocketNotifier.Exception)
            qsn.activated.connect(self.cb_exception)
            qsn.setEnabled(True)
            self.notifiers.append(qsn)

    def stop(self):
        for notifier in self.notifiers:
            notifier.setEnabled(False)

    def cb_read(self, sock):
        self.event_callback(sock, EVENT_TYPE_READ)

    def cb_write(self, sock):
        self.event_callback(sock, EVENT_TYPE_WRITE)

    def cb_exception(self, sock):
        self.event_callback(sock, EVENT_TYPE_EXCEPTION)


class QtReactor(ReactorInterface):

    _stop_funcs = []
    _start_funcs = []

    def __init__(self):
        ReactorInterface.__init__(self)
        self.qApp = QApplication([])
        self.state = REACTOR_STATE_STOPPED
        signal.signal(signal.SIGTERM, self._main_quit_sig_handler)
        signal.signal(signal.SIGINT, self._main_quit_sig_handler)

    def add_timer(self, interval, callback, threshold=0):
        """ Add timer.

        @note: should return an ID assigned to the timer, so that it can be
               removed by rem_timer().
        """
        timer = QTimer()
        timer.setInterval(interval * SEC_TO_MSEC)
        timer.timeout.connect(callback)
        timer.start()
        return timer

    def rem_timer(self, timer):
        """ Removes a timer.
        """
        timer.stop()

    def add_fd(self, fd, event_callback, event_type):
        """ Adds a fd for watch.
        """
        read = write = exception = False
        if event_type & EVENT_TYPE_READ:
            read = True
        if event_type & EVENT_TYPE_WRITE:
            write = True
        if event_type & EVENT_TYPE_EXCEPTION:
            exception = True

        return QtBRisaSocketNotifier(fd, write, read, exception,
                                     event_callback)

    def rem_fd(self, fd_handler):
        """ Removes a fd from being watched.
        """
        fd_handler.stop()

    def add_after_stop_func(self, func):
        """ Registers a function to be called before entering the STOPPED
        state.

        @param func: function
        @type func: callable
        """
        if func not in self._stop_funcs:
            self._stop_funcs.append(func)

    def rem_after_stop_func(self, func):
        """ Removes a registered function.

        @param func: function
        @type func: callable
        """
        if func in self._stop_funcs:
            self._stop_funcs.remove(func)

    def add_before_start_func(self, func):
        """ Registers a function to be called before starting the main loop.

        @param func: function
        @type func: callable
        """
        if func in self._start_funcs:
            self._start_funcs.append(func)

    def rem_before_start_func(self, func):
        """ Removes a registered function.

        @param func: function
        @type func: callable
        """
        if func in self._start_funcs:
            self._start_funcs.remove(func)

    def main_loop_iterate(self):
        """ Runs a single iteration of the main loop. Reactor enters the
        RUNNING state while this method executes.
        """
        self.qApp.processEvents(QEventLoop.AllEvents)

    def main(self):
        """ Enters the RUNNING state by running the main loop until
        main_quit is called.
        """
        self._main_call_before_start_funcs()
        self.state = REACTOR_STATE_RUNNING
        self.qApp.exec_()
        self.state = REACTOR_STATE_STOPPED
        self._main_call_after_stop_funcs()

    def main_quit(self):
        """ Terminates the main loop.
        """
        self.qApp.quit()

    def _main_quit_sig_handler(self, sig, frame):
        self.main_quit()

    def is_running(self):
        """ Returns True if the main loop is running
        """
        return True if self.state else False

    def _main_call_after_stop_funcs(self):
        """ Calls registered functions to be called after the main loop is
        stopped.
        """
        for cb in self._stop_funcs:
            cb()

    def _main_call_before_start_funcs(self):
        """ Calls registered functions to be called before starting the main
        loop.
        """
        for cb in self._start_funcs:
            cb()
