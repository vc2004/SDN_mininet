'''
Coursera:
- Software Defined Networking (SDN) course
-- Network Virtualization

Professor: Nick Feamster
Teaching Assistant: Arpit Gupta
'''

from pox.core import core
from collections import defaultdict

import pox.openflow.libopenflow_01 as of
import pox.openflow.discovery
import pox.openflow.spanning_tree

from pox.lib.revent import *
from pox.lib.util import dpid_to_str
from pox.lib.util import dpidToStr
from pox.lib.addresses import IPAddr, EthAddr
from collections import namedtuple
import os

log = core.getLogger()


class TopologySlice (EventMixin):

    def __init__(self):
        self.listenTo(core.openflow)
        log.debug("Enabling Slicing Module")

    def programmingflow(self, event, inport, outport):

        '''This function programs the switch S1'''

        flow = of.ofp_flow_mod()
        flow.match.in_port = inport
        flow.actions.append(of.ofp_action_output(port = outport))
        event.connection.send(flow)

        flow_reverse = of.ofp_flow_mod()
        flow_reverse.match.in_port = outport
        flow_reverse.actions.append(of.ofp_action_output(port = inport))
        event.connection.send(flow_reverse)
        
        
    """This event will be raised each time a switch will connect to the controller"""
    def _handle_ConnectionUp(self, event):
        
        # Use dpid to differentiate between switches (datapath-id)
        # Each switch has its own flow table. As we'll see in this 
        # example we need to write different rules in different tables.
        dpid = dpidToStr(event.dpid)
        log.debug("Switch %s has come up.", dpid)
        
        if dpid == "00-00-00-00-00-01" or dpid == "00-00-00-00-00-04":
            self.programmingflow(event, 3, 1)
            self.programmingflow(event, 4, 2)
        elif dpid == "00-00-00-00-00-02" or dpid == "00-00-00-00-00-03":
            self.programmingflow(event, 1, 2)

               

def launch():
    # Run spanning tree so that we can deal with topologies with loops
    pox.openflow.discovery.launch()
    pox.openflow.spanning_tree.launch()

    '''
    Starting the Topology Slicing module
    '''
    core.registerNew(TopologySlice)
