#!/usr/bin/env python

#/**
# * The example has been taken from Wireshark official repository
# * https://github.com/wireshark/wireshark/blob/master/doc/extcap_example.py
# */

from __future__ import print_function

import os
import sys
import signal
import re
import argparse
import time
import struct
import binascii
from threading import Thread

ERROR_USAGE          = 0
ERROR_ARG            = 1
ERROR_INTERFACE      = 2
ERROR_FIFO           = 3
"""
Table 8.2. Commands and application for controls
from https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html
"""
CTRL_CMD_INITIALIZED = 0
CTRL_CMD_SET         = 1
CTRL_CMD_ADD         = 2
CTRL_CMD_REMOVE      = 3
CTRL_CMD_ENABLE      = 4
CTRL_CMD_DISABLE     = 5
CTRL_CMD_STATUSBAR   = 6
CTRL_CMD_INFORMATION = 7
CTRL_CMD_WARNING     = 8
CTRL_CMD_ERROR       = 9

CTRL_ARG_MESSAGE     = 0
CTRL_ARG_CHANNEL     = 1
CTRL_ARG_HELP        = 4
CTRL_ARG_LOGGER      = 6
CTRL_ARG_NONE        = 255

initialized = False
message = ''
channel = 0.0
verify = False
button = False
button_disabled = False


"""
This code has been taken from http://stackoverflow.com/questions/5943249/python-argparse-and-controlling-overriding-the-exit-status-code - originally developed by Rob Cowie http://stackoverflow.com/users/46690/rob-cowie
"""
class ArgumentParser(argparse.ArgumentParser):
    def _get_action_from_name(self, name):
        """Given a name, get the Action instance registered with this parser.
        If only it were made available in the ArgumentError object. It is
        passed as it's first arg...
        """
        container = self._actions
        if name is None:
            return None
        for action in container:
            if '/'.join(action.option_strings) == name:
                return action
            elif action.metavar == name:
                return action
            elif action.dest == name:
                return action

    def error(self, message):
        exc = sys.exc_info()[1]
        if exc:
            exc.argument = self._get_action_from_name(exc.argument_name)
            raise exc
        super(ArgumentParser, self).error(message)


def extcap_version():
    print ("extcap {version=1.0}{help=https://github.com/kozachenkoartem/wireshark_extcap_example}{display=example interface}")

def extcap_interfaces():
    print ("extcap {version=1.0}{help=https://github.com/kozachenkoartem/wireshark_extcap_example}{display=example interface}")
    print ("interface {value=test_ifc 1}{display=test_ifc}")
    print ("control {number=%d}{type=selector}{display=Chennel}{tooltip=Channel}" % CTRL_ARG_CHANNEL)
    print ("control {number=%d}{type=string}{display=Raw message}{tooltip=Package message in hexdecimal format}{placeholder=Enter the raw package here ...}" % CTRL_ARG_MESSAGE)
    print ("control {number=%d}{type=button}{role=logger}{display=Log}{tooltip=Show capture log}" % CTRL_ARG_LOGGER)
    print ("control {number=%d}{type=button}{role=help}{display=Help}{tooltip=Show help}" % CTRL_ARG_HELP)
    print ("value {control=%d}{value=0}{display=0}{default=true}" % CTRL_ARG_CHANNEL)
    print ("value {control=%d}{value=1}{display=1}" % CTRL_ARG_CHANNEL)
    print ("value {control=%d}{value=2}{display=2}" % CTRL_ARG_CHANNEL)
    print ("value {control=%d}{value=3}{display=3}" % CTRL_ARG_CHANNEL)
    print ("value {control=%d}{value=4}{display=4}" % CTRL_ARG_CHANNEL)
    print ("value {control=%d}{value=5}{display=5}" % CTRL_ARG_CHANNEL)
    print ("value {control=%d}{value=6}{display=6}" % CTRL_ARG_CHANNEL)
    print ("value {control=%d}{value=7}{display=7}" % CTRL_ARG_CHANNEL)
    print ("value {control=%d}{value=8}{display=8}" % CTRL_ARG_CHANNEL)


def extcap_dlts():
    print ("dlt {number=150}{name=USER3}{display=HALO is using USER3}")


def validate_capture_filter(capture_filter):
    if capture_filter != "filter" and capture_filter != "valid":
        print("Illegal capture filter")

def unsigned(n):
    return int(n) & 0xFFFFFFFF

def pcap_fake_header():

    header = bytearray()
    header += struct.pack('<L', int ('a1b2c3d4', 16 ))
    header += struct.pack('<H', unsigned(2) ) # Pcap Major Version
    header += struct.pack('<H', unsigned(4) ) # Pcap Minor Version
    header += struct.pack('<I', int(0)) # Timezone
    header += struct.pack('<I', int(0)) # Accurancy of timestamps
    header += struct.pack('<L', int ('0000ffff', 16 )) # Max Length of capture frame
    header += struct.pack('<L', unsigned(150)) # USER_3
    return header

def pcap_package ( in_pkt ):
    pkt = bytearray()
    meta = bytearray()

    try:
        pkt = bytes.fromhex(in_pkt)
    except:
        pkt = in_pkt.decode("hex")

    pcap = bytearray()
    caplength = len(pkt)
    timestamp = int(time.time())

    pcap += struct.pack('<L', unsigned(timestamp ) ) # timestamp seconds
    pcap += struct.pack('<L', 0x00  ) # timestamp nanoseconds
    pcap += struct.pack('<L', unsigned(caplength ) ) # length captured
    pcap += struct.pack('<L', unsigned(caplength ) ) # length in frame
    pcap += pkt
    return pcap

def control_read(fn):
    try:
        header = fn.read(6)
        sp, _, length, arg, typ = struct.unpack('>sBHBB', header)
        if length > 2:
            payload = fn.read(length - 2).decode('utf-8', 'replace')
        else:
            payload = ''
        return arg, typ, payload
    except:
        return None, None, None


def control_read_thread(control_in, fn_out):
    global initialized, channel
    with open(control_in, 'rb', 0 ) as fn:
        arg = 0
        while arg != None:
            arg, typ, payload = control_read(fn)
            if typ == CTRL_CMD_INITIALIZED:
                initialized = True
            if initialized:
                if arg == CTRL_ARG_MESSAGE:
                    message = payload.replace(" ", "")
                    if not message: continue
                    control_write(fn_out, CTRL_ARG_LOGGER, CTRL_CMD_ADD, "Sending raw message:  %s\n" % message)
                elif arg == CTRL_ARG_CHANNEL:
                    channel = float(payload)
                    control_write(fn_out, CTRL_ARG_LOGGER, CTRL_CMD_ADD, "Channel:  %d\n" % channel)


def control_write(fn, arg, typ, payload):
    packet = bytearray()
    packet += struct.pack('>sBHBB', b'T', 0, len(payload) + 2, arg, typ)
    if sys.version_info[0] >= 3 and isinstance(payload, str):
        packet += payload.encode('utf-8')
    else:
        packet += payload
    fn.write(packet)

def control_write_defaults(fn_out):
    global initialized, message, channel

    while not initialized:
        time.sleep(.1)  # Wait for initial control values

    # Write startup configuration to Toolbar controls
    control_write(fn_out, CTRL_ARG_MESSAGE, CTRL_CMD_SET, message)
    control_write(fn_out, CTRL_ARG_CHANNEL, CTRL_CMD_SET, str(int(channel)))

    for i in range(1,8):
        control_write(fn_out, CTRL_ARG_CHANNEL, CTRL_CMD_ADD, str(i))

def extcap_capture(interface, fifo, control_in, control_out, in_channel):
    global channel
    channel = in_channel
    counter = 1
    fn_out = None

    with open(fifo, 'wb', 0 ) as fh:
        fh.write (pcap_fake_header())

        if control_out != None:
            fn_out = open(control_out, 'wb', 0)
            control_write(fn_out, CTRL_ARG_LOGGER, CTRL_CMD_SET, "Log started at " + time.strftime("%c") + "\n")
            control_write(fn_out, CTRL_ARG_LOGGER, CTRL_CMD_ADD, "Interface : " + str(interface)  + "   Channel : " + str(channel) + "\n")

        if control_in != None:
            # Start reading thread
            thread = Thread(target = control_read_thread, args = (control_in, fn_out))
            thread.start()

        if fn_out != None:
            control_write_defaults(fn_out)


        while True:
            """
            Example fake package with random bytes
            """
            pkt = "AEB205AEB205AEB205AEB205AEB205AEB205AEB205AEB205AEB205AEB205AEB205AEB205"
            fh.write (pcap_package(pkt))
            time.sleep(1)

    thread.join()
    if fn_out != None:
        fn_out.close()

def extcap_close_fifo(fifo):
    # This is apparently needed to workaround an issue on Windows/macOS
    # where the message cannot be read. (really?)
    fh = open(fifo, 'wb', 0 )
    fh.close()



def usage():
    print ( "Usage: %s <--extcap-interfaces | --extcap-dlts | --extcap-interface | --extcap-config | --capture | --extcap-capture-filter | --fifo>" % sys.argv[0] )

if __name__ == '__main__':
    interface = ""
    option = ""

    # Capture options
    channel = 0
    message = ""
    ts = 0

    parser = ArgumentParser(
            prog="Extcap Example",
            description="Extcap example program for python"
            )

    # Extcap Arguments
    parser.add_argument("--capture", help="Start the capture routine", action="store_true" )
    parser.add_argument("--extcap-interfaces", help="Provide a list of interfaces to capture from", action="store_true")
    parser.add_argument("--extcap-interface", help="Provide the interface to capture from")
    parser.add_argument("--extcap-dlts", help="Provide a list of dlts for the given interface", action="store_true")
    parser.add_argument("--extcap-capture-filter", help="Used together with capture to provide a capture filter")
    parser.add_argument("--fifo", help="Use together with capture to provide the fifo to dump data to")
    parser.add_argument("--extcap-control-in", help="Used to get control messages from toolbar")
    parser.add_argument("--extcap-control-out", help="Used to send control messages to toolbar")
    parser.add_argument("--extcap-version", help="Shows the version of this utility", nargs='?', default="")
    parser.add_argument("--extcap-reload-option", help="Reload elements for the given option")

    # Interface Arguments
    parser.add_argument("--channel", help="Demonstrates an integer variable", type=int, default=0, choices=[0, 1, 2, 3, 4, 5, 6] )

    try:
        args, unknown = parser.parse_known_args()
    except argparse.ArgumentError as exc:
        print( "%s: %s" % ( exc.argument.dest, exc.message ), file=sys.stderr)
        fifo_found = 0
        fifo = ""
        for arg in sys.argv:
            if (arg == "--fifo" or arg == "--extcap-fifo") :
                fifo_found = 1
            elif ( fifo_found == 1 ):
                fifo = arg
                break
        extcap_close_fifo(fifo)
        sys.exit(ERROR_ARG)



    if ( len(sys.argv) <= 1 ):
        parser.exit("No arguments given!")

    if ( args.extcap_version and not args.extcap_interfaces ):
        extcap_version()
        sys.exit(0)

    if ( args.extcap_interfaces == False and args.extcap_interface == None ):
        parser.exit("An interface must be provided or the selection must be displayed")
    if ( args.extcap_capture_filter and not args.capture ):
        validate_capture_filter(args.extcap_capture_filter)
        sys.exit(0)

    if ( args.extcap_interfaces == True or args.extcap_interface == None ):
        extcap_interfaces()
        sys.exit(0)
    import pynrfjprog

    if ( len(unknown) > 1 ):
        print("Extcap %d unknown arguments given" % len(unknown) )

    m = re.match ( 'test_ifc (\d+)', args.extcap_interface )
    if not m:
        sys.exit(ERROR_INTERFACE)
    interface = m.group(1)

    if ( args.extcap_reload_option and len(args.extcap_reload_option) > 0 ):
        option = args.extcap_reload_option

    if args.extcap_dlts:
        extcap_dlts()
    elif args.capture:
        if args.fifo is None:
            sys.exit(ERROR_FIFO)
        try:
            extcap_capture(interface, args.fifo, args.extcap_control_in, args.extcap_control_out, args.channel)
        except KeyboardInterrupt:
            pass
    else:
        usage()
        sys.exit(ERROR_USAGE)
