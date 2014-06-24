'''
Coursera:
- Software Defined Networking (SDN) course
-- Programming Assignment: Layer-2 Firewall Application

Professor: Nick Feamster
Teaching Assistant: Arpit Gupta
'''

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from collections import namedtuple
import os
import csv



log = core.getLogger()
policyFile = "%s/pox/pox/misc/firewall-policies.csv" % os.environ[ 'HOME' ]  


class Firewall (EventMixin):

    def __init__ (self):
        self.listenTo(core.openflow)
        log.debug("Enabling Firewall Module")

    def _handle_ConnectionUp (self, event):    
        
        
        deny_list = []
        
        with open(policyFile, 'rb') as f:
            reader = csv.reader(f)
            rownum = 0
            for row in reader:
                if rownum != 0:
                    deny_list.append((EthAddr(row[1]), EthAddr(row[2])))
                rownum = rownum + 1

        for (a,b) in deny_list:
            msg = of.ofp_flow_mod()
            msg.match.dl_src = a
            msg.match.dl_dst = b
            event.connection.send(msg)
    
        log.debug("Firewall rules installed on %s", dpidToStr(event.dpid))

def launch ():
    '''
    Starting the Firewall module
    '''
    core.registerNew(Firewall)
