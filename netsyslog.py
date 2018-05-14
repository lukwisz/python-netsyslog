# Copyright (C) 2005 Graham Ashton <ashtong@users.sourceforge.net>
# Copyright (C) 2010 Daniel Pocock http://danielpocock.com
#
# This module is free software, and you may redistribute it and/or modify
# it under the same terms as Python itself, so long as this copyright message
# and disclaimer are retained in their original form.
#
# IN NO EVENT SHALL THE AUTHOR BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT,
# SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF
# THIS CODE, EVEN IF THE AUTHOR HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH
# DAMAGE.
#
# THE AUTHOR SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
# PARTICULAR PURPOSE.  THE CODE PROVIDED HEREUNDER IS ON AN "AS IS" BASIS,
# AND THERE IS NO OBLIGATION WHATSOEVER TO PROVIDE MAINTENANCE,
# SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
#
# $Id: netsyslog.py,v 1.9 2005/11/22 16:35:40 ashtong Exp $


"""netsyslog enables you to construct syslog messages and send them
(via UDP) to a remote syslog server directly from Python. You can send
log messages that contain the current time, local hostname and calling
program name (i.e. the typical requirement of a logging package) to
one or more syslog servers.

Unlike other syslog modules netsyslog also allows you to set the
metadata (e.g. time, host name, program name, etc.) yourself, giving
you full control over the contents of the UDP packets that it creates.

See L{Logger.log} and L{Logger.send_packet} for a synopsis of these
two techniques.

The format of the UDP packets sent by netsyslog adheres closely to
that defined in U{RFC 3164<http://www.ietf.org/rfc/rfc3164.txt>}. Much
of the terminology used in the RFC has been incorporated into the
names of the classes and properties and is used throughout this
documentation.

Further information and support can be found from the U{netsyslog home
page<http://hacksaw.sourceforge.net/netsyslog/>}.

"""


__version__ = "0.1.1"


import os
import logging
import socket
import SocketServer
import sys
import time
import syslog

class Error(Exception):
    """Base class for exceptions in this module."""
    pass

class ParseError(Error):
    """Exception raised for errors parsing frames from the wire.

    Attributes:
        field -- input expression in which the error occurred
        msg   -- explanation of the error
    """

    def __init__(self, field, msg):
        print field + ", " + msg
        self.field = field
        self.msg = msg

class PriPart(object):

    """The PRI part of the packet.

    Though never printed in the output from a syslog server, the PRI
    part is a crucial part of the packet. It encodes both the facility
    and severity of the packet, both of which are defined in terms of
    numerical constants from the standard syslog module.

    See Section 4.1.1 of RFC 3164 for details.

    """

    def __init__(self, facility, severity):
        """Initialise the object, specifying facility and severity.

        Specify the arguments using constants from the syslog module
        (e.g. syslog.LOG_USER, syslog.LOG_INFO).

        """
        assert facility is not None
        assert severity is not None
        self.facility = facility
        self.severity = severity

    @classmethod
    def fromWire(cls, pri_text):
        """Initialise the object, specifying a numerical priority from the wire.
        """
        assert pri_text is not None
        try:
            pri_n = int(pri_text)
        except ValueError:
            raise ParseError("priority", "not numeric")
        facility = pri_n & 0xf8
        severity = pri_n & 0x07
        return cls(facility, severity)

    def __str__(self):
        value = self.facility + self.severity
        return "<%s>" % value


class HeaderPart(object):

    """The HEADER part of the message.

    The HEADER contains a timestamp and a hostname. It is the first
    component of the log message that is displayed in the output of
    syslog.

    See Section 4.1.2 of RFC 3164 for details.

    """

    def __init__(self, timestamp=None, hostname=None):
        """Initialise the object, specifying timestamp and hostname.

        The timestamp represents the local time when the log message
        was created. If the timestamp is not set the current local
        time will be used. See the L{HeaderPart.timestamp} property
        for a note on the format.

        The hostname should be set to the hostname of the computer
        that originally generated the log message. If the hostname is
        not set the hostname of the local computer will be used. See
        the L{HeaderPart.hostname} property for a note on the format.

        """
        self.timestamp = timestamp
        self.hostname = hostname

    @classmethod
    def fromWire(cls, header_text):
        """Initialise the object, specifying text from the wire.
        """
        assert header_text is not None

        # timestamp (15 bytes), space (1 byte), hostname (at least one byte)
        if len(header_text) < 17:
            raise ParseError("header", "should be at least 17 bytes")
        # timestamp is fixed length
        if header_text[15] != " ":
            raise ParseError("header", "16th byte should be a space")

        timestamp = header_text[0:15]
        if not cls._timestamp_is_valid(timestamp):
            raise ParseError("header/timestamp", "invalid timestamp: '%s'" % timestamp)
        hostname = header_text[16:]
        return cls(timestamp, hostname)

    def __str__(self):
        return "%s %s" % (self.timestamp, self.hostname)

    def _get_timestamp(self):
        return self._timestamp

    def parse_timestamp(self):
        """Parses the syslog timestamp string into a struct_time object.

        """
        # syslog RFC3164 timestamps don't include a year value so
        # we must substitute it manually
        localtime = time.localtime()
        year = localtime.tm_year
        full_ts = "%d %s" % (year, self._timestamp)
        result = time.strptime(full_ts, "%Y %b %d %H:%M:%S")
        # In the first day of a year (tm_mon==1) we may still
        # receive some values from the last day of the previous year
        if result.tm_mon == 12 and localtime.tm_mon == 1:
            year = year - 1
            full_ts = "%d %s" % (year, self._timestamp)
            result = time.strptime(full_ts, "%Y %b %d %H:%M:%S")
        return result

    def _format_timestamp_rfc3164(self, _timestamp):
        day = time.strftime("%d", _timestamp)
        if day[0] == "0":
            day = " " + day[1:]
        value = time.strftime("%b %%s %H:%M:%S", _timestamp)
        return value % day

    def _calculate_current_timestamp(self):
        localtime = time.localtime()
        return self._format_timestamp_rfc3164(localtime)

    @classmethod
    def _timestamp_is_valid(self, value):
        if value is None:
            return False
        for char in value:
            if ord(char) < 32 or ord(char) > 126:
                return False
        return True
    
    def _set_timestamp(self, value):
        if not self._timestamp_is_valid(value):
            value = self._calculate_current_timestamp()
        self._timestamp = value

    timestamp = property(_get_timestamp, _set_timestamp, None,
                         """The local time when the message was written.

                         Must follow the format 'Mmm DD HH:MM:SS'.  If
                         the day of the month is less than 10, then it
                         MUST be represented as a space and then the
                         number.

                         """)

    def _get_hostname(self):
        return self._hostname

    def _set_hostname(self, value):
        if value is None:
            value = socket.gethostname()
        self._hostname = value

    hostname = property(_get_hostname, _set_hostname, None,
                        """The hostname where the log message was created.

                        Should be the first part of the hostname, or
                        an IP address. Should NOT be set to a fully
                        qualified domain name.

                        """)


class MsgPart(object):

    """Represents the MSG part of a syslog packet.

    The MSG part of the packet consists of the TAG and CONTENT. The
    TAG and the CONTENT fields must be separated by a non-alphanumeric
    character. Unless you ensure that the CONTENT field begins with
    such a character a seperator of a colon and space will be inserted
    between them when the C{MsgPart} object is converted into a UDP
    packet.

    See Section 4.1.3 of RFC 3164 for details.

    """

    MAX_TAG_LEN = 32

    def __init__(self, tag=None, content="", pid=None):
        """Initialise the object, specifying tag and content.

        See the documentation for the L{MsgPart.tag} and
        L{MsgPart.content} properties for further documentation.

        If the pid is set it will be prepended to the content in
        square brackets when the packet is created.

        """        
        self.tag = tag
        self.content = content
        self.pid = pid

    @classmethod
    def fromWire(cls, message_text):
        """Initialise the object, specifying text from the wire."""

        assert message_text is not None

        # look for the tag[PID] text
        _colon = message_text.find(":")
        if _colon < 0:
            raise ParseError("message", "missing colon to separate tag from message")
        tag_text = message_text[0:_colon]
        begin_pid = tag_text.find("[")
        end_pid = tag_text.find("]")
        _pid = None
        if begin_pid > -1:
            if end_pid < 0:
                # not a valid message
                raise ParseError("message", "missing ']' in tag/pid section")
            _tag = tag_text[0:begin_pid]
            _pid = tag_text[begin_pid+1:end_pid]
        else:
            _tag = tag_text
            _pid = None
        _content = message_text[_colon+2:]
        return cls(_tag, _content, _pid)

    def __str__(self):
        content = self._prepend_seperator(self.content)
        if self.pid is not None:
            content = "[%s]" % self.pid + content
        return self.tag + content

    def _get_tag(self):
        return self._tag

    def _set_tag(self, value):
        if value is None:
            value = sys.argv[0]
        self._tag = value[:self.MAX_TAG_LEN]

    tag = property(_get_tag, _set_tag, None,
                   """The name of the program that generated the log message.

                   The tag can only contain alphanumeric
                   characters. If the tag is longer than %d characters
                   it will be truncated automatically.

                   """ % MAX_TAG_LEN)

    def _get_content(self):
        return self._content

    def _prepend_seperator(self, value):
        try:
            first_char = value[0]
        except IndexError:
            pass
        else:
            if first_char.isalnum():
                value = ": " + value
        return value

    def _set_content(self, value):
        self._content = value

    content = property(_get_content, _set_content, None,
                       """The main component of the log message.

                       The content field is a freeform field that
                       often begins with the process ID (pid) of the
                       program that created the message.

                       """)


class Packet(object):

    """Combines the PRI, HEADER and MSG into a packet.

    If the packet is longer than L{MAX_LEN} bytes in length it is
    automatically truncated prior to sending; any extraneous bytes are
    lost.

    """

    MAX_LEN = 1024

    def __init__(self, pri, header, msg):
        """Initialise the object.

        The three arguments must be instances of the L{PriPart},
        L{HeaderPart} and L{MsgPart} classes.

        """
        self.pri = pri
        self.header = header
        self.msg = msg

    @classmethod
    def fromWire(cls, packet_text):
        """Initialise the object, specifying packet text from the wire."""

        assert packet_text is not None

        if len(packet_text) < 6:
            # not long enough
            raise ParseError("frame", "too short")

        if packet_text[0] != "<":
            # not correct syntax
            raise ParseError("frame", "should begin with '<'")

        gt = packet_text.index(">", 1)
        pri_text = packet_text[1:gt]

        # skip the next space and the timestamp
        sp = gt + 1 + 15
        # now skip the hostname
        sp = packet_text.index(" ", sp + 1)
        header_text = packet_text[gt+1:sp]

        msg_text = packet_text[sp+1:]

        pri = PriPart.fromWire(pri_text)
        header = HeaderPart.fromWire(header_text)
        msg = MsgPart.fromWire(msg_text)
        return cls(pri, header, msg)

    def __str__(self):
        message = "%s%s %s" % (self.pri, self.header, self.msg)
        return message[:self.MAX_LEN]


class Logger(object):

    """Send log messages to syslog servers.

    The Logger class provides two different methods for sending log
    messages. The first approach (the L{log} method) is suitable for
    creating new log messages from within a normal application. The
    second (the L{send_packet} method) is designed for use in
    circumstances where you need full control over the contents of
    the syslog packet.

    """

    PORT = 514
    _name = ''

    def __init__(self, name):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._hostnames = {}
        self._name=name

    def add_host(self, hostname):
        """Add hostname to the list of hosts that will receive packets.

        Can be a hostname or an IP address. Note that if the hostname
        cannot be resolved calls to L{log} or L{send_packet} will take
        a long time to return.
        
        """
        self._hostnames[hostname] = 1

    def remove_host(self, hostname):
        """Remove hostname from the list of hosts that will receive packets."""
        del self._hostnames[hostname]

    def _send_packet_to_hosts(self, packet):
        for hostname in self._hostnames:
            self._sock.sendto(str(packet), (hostname, self.PORT))

    def log(self, facility, level, text, pid=False):
        """Send the message text to all registered hosts.

        The facility and level will be used to create the packet's PRI
        part. The HEADER will be automatically determined from the
        current time and hostname. The MSG will be set from the
        running program's name and the text parameter.

        This is the simplest way to use netsyslog, creating log
        messages containing the current time, hostname, program name,
        etc. This is how you do it::
        
            logger = netsyslog.Logger()
            logger.add_host("localhost")
            logger.log(syslog.LOG_USER, syslog.LOG_INFO, "Hello World")

        If pid is True the process ID will be prepended to the text
        parameter, enclosed in square brackets and followed by a
        colon.

        """
        pri = PriPart(facility, level)
        header = HeaderPart()
        if pid:
            msg = MsgPart(tag=self._name, content=text, pid=os.getpid())
        else:
            msg = MsgPart(tag=self._name, content=text)
        packet = Packet(pri, header, msg)
        self._send_packet_to_hosts(packet)

    def send_packet(self, packet):
        """Send a L{Packet} object to all registered hosts.

        This method requires more effort than L{log} as you need to
        construct your own L{Packet} object beforehand, but it does
        give you full control over the contents of the packet::

            pri = netsyslog.PriPart(syslog.LOG_USER, syslog.LOG_INFO)
            header = netsyslog.HeaderPart("Jun  1 18:34:03", "myhost")
            msg = netsyslog.MsgPart("myprog", "Hello World", mypid)
            packet = netsyslog.Packet(pri, header, msg)

            logger = netsyslog.Logger()
            logger.add_host("localhost")
            logger.send_packet(packet)

        """
        self._send_packet_to_hosts(packet)

class SyslogTCPHandler(SocketServer.BaseRequestHandler):

    BUF_SIZE = 2048
    MAX_CACHED = 4096
    MAX_FRAME = 2048
    TERM_CHAR = "\n"

    def setup(self):
        """Setup variables used by this instance."""
        self.logger = logging.getLogger(__name__)
        self.cached = None
        self.frame_size = None
        self.logger.info("incoming TCP connection accepted")

    def handle(self):
        """Handle the incoming bytes, try to resolve them to frames."""
        data = self.request.recv(self.BUF_SIZE)
        while len(data) > 0:
            if self.cached is None:
                self.cached = data
            else:
                if (len(self.cached) + len(data)) > self.MAX_CACHED:
                    # too many bytes
                    self.logger.warning("too much data")
                    self.request.close()
                    return
                self.cached = self.cached + data

            if len(self.cached) > 8:
                if self.frame_size is None:
                    if self.cached[0] == "<":
                        # non-transparent framing
                        self.frame_size = -1
                    else:
                        # octet counting
                        sp = self.cached.find(" ")
                        if sp < 0:
                            # didn't find frame length terminated by a space
                            self.logger.warning("suspected octet-framing, but frame length not terminated by a space")
                            self.request.close()
                            return
                        try:
                            self.frame_size = int(self.cached[0:sp])
                        except ValueError:
                            # frame length is not a number
                            self.logger.warning("frame length is not a number")
                            self.request.close()
                            return
                        if self.frame_size < 1 or self.frame_size > self.MAX_FRAME:
                            # specified frame size too small/big
                            self.logger.warning("specified frame size is too big or too small")
                            self.request.close()
                            return
                        # now we parsed the size, trim the frame size string from the
                        # beginning of the frame
                        self.cached = self.cached[sp+1:]

                try:
                    if self.frame_size > 0:
                        if len(self.cached) >= self.frame_size:
                            self.handle_frame_text(self.frame_size, self.frame_size)
                    else:
                        term_idx = self.cached.find(self.TERM_CHAR)
                        if term_idx >= 0:
                            # do not consider the TERM_CHAR as part of the frame
                            self.handle_frame_text(term_idx, term_idx + 1)
                except Exception as e:
                    self.logger.warning("exception occurred parsing/handling a frame: " + str(e))
                    self.request.close()
                    return
            # loop again
            data = self.request.recv(self.BUF_SIZE)

        # we get here if the received data size == 0 (connection closed)
        self.request.close()

    def handle_frame_text(self, frame_len, skip_len):
        """Handle the frame text, convert to L{Packet}."""
        # extract the frame itself
        frame_text = self.cached[0:frame_len]

        # manage the buffer, there may be more data available
        if len(self.cached) > skip_len:
            self.cached = self.cached[skip_len:]
        else:
            self.cached = None
        self.frame_size = None

        # parse the frame
        try:
            frame = Packet.fromWire(frame_text)
        except ParseError:
            # these are errors we noticed
            raise
        except Exception:
            # these are errors the parser didn't correctly detect, should
            # analyze them and improve the parser
            raise ParseError("frame", "unexpected parsing error")

        try:
            self.handle_message(frame)
        except Exception:
            # the application (subclass) raised some exception
            raise

    def handle_message(self, frame):
        """Handle parsed Syslog frames.

        Applications should override this method.

        This default implementation prints some data from each frame.

        """
        pass

class ThreadedSyslogServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

class Collector(object):
    """Accept log messages from Syslog clients.

    Accept Syslog messages over the network and pass them to the application.

    """

    def __init__(self, port=514, handler=SyslogTCPHandler):
        address = ("0.0.0.0", port)
        ThreadedSyslogServer.daemon_threads = True
        ThreadedSyslogServer.allow_reuse_address = True
        self.server = ThreadedSyslogServer(address, handler)

    def run(self):
        self.server.serve_forever()

