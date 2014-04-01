# Licensed under the MIT license
# http://opensource.org/licenses/mit-license.php or see LICENSE file.
# Copyright 2007-2008 Brisa Team <brisa-develop@garage.maemo.org>

""" Network related functions, such as get_ip_address(), http_call(),
parse_url() and others.
"""

import urllib.request, urllib.error, urllib.parse
import http.client
import shutil
import socket
import fcntl
from time import time, sleep
from struct import pack
from urllib.parse import urlparse
from xml.etree import ElementTree

import brisa
from brisa.core import log

socket.setdefaulttimeout(15)


def get_ip_address(ifname):
    """ Determine the IP address given the interface name

    http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/439094
    (c) Paul Cannon
    Uses the Linux SIOCGIFADDR ioctl to find the IP address associated
    with a network interface, given the name of that interface, e.g. "eth0".
    The address is returned as a string containing a dotted quad.

    @param ifname: interface name
    @type ifname: string

    @return: ip address in the interface specified
    @rtype: string
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915,
                                          pack('256s',
                                          str(ifname[:15])))[20:24])
        return ip
    except:
        return socket.gethostbyname(socket.gethostname())


def get_active_ifaces():
    """ Return a list of the active network interfaces

    Default route of /proc/net/route has the destination field set to 00000000


    @return: active network interfaces
    @rtype: list
    """
    try:
        rd = open('/proc/net/route').readlines()
    except (IOError, OSError):
        return []
    net = [line.split('\t')[0:2] for line in rd]
    return [v[0] for v in net if v[1] == '00000000']


def http_call(method, url, body='', headers={}):
    """ Returns a HTTPResponse object for the given call.

    @param method: HTTP method (NOTIFY, POST, etc...)
    @param url: receiver URL
    @param body: body of the message
    @param headers: additional headers

    @type method: string
    @type url: string
    @type body: string
    @type headers: dictionary
    """
    parsed_url = parse_url(url)
    
    (host, ip, port) = ('', '', 80)
    
    if parsed_url.hostname:
        host = parsed_url.hostname
    
    if parsed_url.port:
        port = parsed_url.port
    
    path = parsed_url.path
    if parsed_url.query != '':
        path += '?%s' % parsed_url.query
    
    if host:
        ip = socket.gethostbyname(host)
    else:
        log.debug('error: host is empty')

    log.debug('http call (host, port, ip): (%s, %d, %s)' % \
              (host, port, str(ip)))

    con = http.client.HTTPConnection("%s:%d" % (ip, port))
    con.connect()

    if body or headers:
        con.request(method, path, body=body, headers=headers)
    else:
        return None

    return con.getresponse()


def url_fetch(url, filename='', attempts=0, interval=0):
    """ Fetches an URL into a file or returns a file descriptor. If attempts
    and interval are not specified, they get their values from
    brisa.url_fetch_attempts and brisa.url_fetch_attempts_interval.

    @param url: URL to be fetched
    @param filename: if specified fetch result gets written on this path
    @param attempts: number of attempts
    @param interval: interval between attempts in seconds

    @type url: string
    @type filename: string
    @type attempts: integer
    @type interval: float
    """
    if not attempts:
        attempts = brisa.url_fetch_attempts
    if not interval:
        interval = brisa.url_fetch_attempts_interval

    handle = None
    last_exception = None
    for k in range(attempts):
        log.debug('Fetching %r (attempt %d)' % (url, k))
        req = urllib.request.Request(url)
        try:
            handle = urllib.request.urlopen(req)
        except IOError as e:
            if hasattr(e, 'reason'):
                log.warning('Attempt %d: failed to reach a server. Reason: %s'%
                            (k, e.reason))
            elif hasattr(e, 'code'):
                log.warning('Attempt %d: the server couldn\'t fulfill the '\
                            'request. Error code: %s' % (k, e.code))
            handle = None
            last_exception = e
        finally:
            if handle != None:
                if not filename:
                    # Return mode
                    log.debug('url %r fetched successfully' % url)
                    return handle
                else:
                    log.debug('writing data to filename %s' % filename)
                    # Writing mode
                    shutil.copyfile(handle, open(filename, 'w'))
                    return None
            sleep(interval)

    if last_exception:
        raise last_exception
    else:
        return None


def decode(text):
    """ Converts an arbitrary string to byte string in UTF-8. On failure
    returns the given string.

    @param text: string to be converted
    @type text: string
    """

    if type(text) is str:
        return text.encode("utf-8")

    encoding_lst = [("iso-8859-15", ), ("utf-8", ), ("latin-1", ),
                    ("utf-8", "replace")]
    for encoding in encoding_lst:
        try:
            return text.decode(*encoding).encode("utf-8")
        except:
            return text


def parse_xml(data):
    """ Parses XML data into an ElementTree.

    @param data: raw XML data
    @type data: string

    @rtype: ElementTree
    """
    p = ElementTree.XMLParser()
    p.feed(decode(data))
    return ElementTree.ElementTree(p.close())


def parse_http_response(data):
    """ Parses HTTP response data into a tuple in the form (cmd, headers).

    @param data: HTTP response data
    @type data: string

    @return: (cmd, headers) for the given data
    @rtype: tuple
    """
    header, payload = data.split('\r\n\r\n')
    lines = header.split('\r\n')
    cmd = lines[0].split(' ')
    lines = [x.replace(': ', ':', 1) for x in lines[1:]]
    lines = [x for x in lines if len(x) > 0]
    headers = [x.split(':', 1) for x in lines]
    headers = dict([(x[0].lower(), x[1]) for x in headers])
    return cmd, headers


def parse_url(url):
    """ Parse a URL into 6 components.

    @param url: scheme://netloc/path;params?query#fragment
    @type url: string

    @return: a 6-tuple: (scheme, netloc, path, params, query, fragment). Note
    that we don't break the components up in smaller bits (e.g. netloc is a
    single string) and we don't expand % escapes.
    @rtype: tuple
    """
    return urlparse(url)
