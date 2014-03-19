__author__ = 'krish'

import logging
# Change log level to suppress annoying IPv6 error
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.automaton import Automaton, ATMT


class OpenFlowSession(Automaton):
    # store request reply session as a map
    # add the xid to subsequent requests
    # start with initial xid and keep incrementing it
    CURRENT_XID = 676265

    def get_next_xid(self):
        xid = CURRENT_XID + 1
        if xid > 2147483647:
            return 1
        else:
            return (NEXT_XID + 1)

    xid_map = {}

    @ATMT.state(initial=1)
    def OFHELLO(self):
        raise self.wait_state()

    @ATMT.state()
    def wait_state(self):
        # wait user input

    @ATMT.state()
    def command(self, cmd):
        print 'received command', cmd

    @ATMT.state()
    def OFREQUEST(self):
        print "In OF REQUEST State"
        raise self.OFREPLY()

    @ATMT.state()
    def OFREPLY(self):
        print "In OF REPLY state"
        raise self.OFTEARDOWN()

    @ATMT.state(final=1)
    def OFTEARDOWN(self):
        print "Tearing down connection with controller.."

    @ATMT.state(error=1)
    def OFERROR(self):
        print "OF Error state - not hit"
