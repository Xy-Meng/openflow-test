__author__ = 'krish'

import logging
from struct import pack
from scapy.all  import Packet, ShortEnumField, XByteField, ByteEnumField, ShortField, IntField, LongField, ByteField, XIntField, BitField
from scapy.layers.inet import IP, TCP 
from scapy.packet import bind_layers

# Change log level to suppress annoying IPv6 error
#logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# GLOBALS

# Global enum of type of OF packets
OF_TYPES =  {
                0:"ofpt_hello",
                1:"ofpt_err",
                2:"ofpt_echo_req",
                3:"ofpt_echo_reply",
                4:"ofpt_expt",

                5:"ofpt_features_req",
                6:"ofpt_features_reply",
                7:"ofpt_get_cfg_req",
                8:"ofpt_get_cfg_reply",
                9:"ofpt_set_cfg",

                10:"ofpt_pkt_in",
                11:"ofpt_flow_rem",
                12:"ofpt_port_status",

                13:"ofpt_pkt_out",
                14:"ofpt_flow_mod",
                15:"ofpt_grp_mod",
                16:"ofpt_port_mod",
                17:"ofpt_table_mod",

                18:"ofpt_multipart_req",
                19:"ofpt_multipart_rep",

                20:"ofpt_barrier_req",
                21:"ofpt_barrier_reply",

                22:"ofpt_q_get_cfg_req",
                23:"ofpt_q_get_cfg_reply",

                24:"ofpt_role_req",
                25:"ofpt_role_reply",

                26:"ofpt_get_async_req",
                27:"ofpt_get_async_reply",
                28:"ofpt_set_async",
                29:"ofpt_meter_mod",
            }

OFP_HELLO_ELEM_TYPES = {
                1:"ofphet_versionbitmap"
            }

OFP_CAPABILITIES = {
                (1<<0):'OFPC_FLOW_STATS',
                (1<<1):'OFPC_TABLE_STATS',
                (1<<2):'OFPC_PORT_STATS',
                (1<<3):'OFPC_GROUP_STATS',
                (1<<5):'OFPC_IP_REASM',
                (1<<6):'OFPC_QUEUE_STATS',
                (1<<8):'OFPC_PORT_BLOCKED',
            }

OFP_CONFIG_FLAGS = {
                0:'OFPC_FRAG_NORMAL',
                (1<<0):'OFPC_FRAG_DROP',
                (1<<1):'OFPC_FRAG_REASM',
                3:'OFPC_FRAG_MASK',
            }

## END OF GLOBALS SECTION ##
############################

class OpenFlowHello(Packet):
    name = "OpenFlowHello"
    fields_desc = [
        ShortEnumField("type", 1, OFP_HELLO_ELEM_TYPES),
        ShortField("length", None),
        XIntField("bitmap",0x10) #Field that stores a bitmap of supported
                                #versions, script only supports
                                #OF1.3 (0x04). Hence, set to
    ]

    def post_build(self, curr_layer, payload):
        if self.length is None:
            l = 8 + len(payload)
            curr_layer = curr_layer[:2] + pack("!H",l) + curr_layer[4:]
        return curr_layer+payload

class OpenFlowEchoRequest(OpenFlowHello):
    name = "OpenFlowEchoRequest"
    pass

class OpenFlowEchoReply(OpenFlowHello):
    name = "OpenFlowEchoReply"

    @classmethod
    def get_reply_packet(self, echo_req_pkt):
        # TODO Sanity test here
        reply = echo_req_pkt.copy()
        reply.type = 3
        reply.xid = echo_req_pkt.xid
        return reply
        
    def post_build(self, curr_layer, payload):
        if self.length is None:
            l = 8 + len(payload)
            curr_layer = curr_layer[:2] + pack("!H",l) + curr_layer[4:]
        return curr_layer+payload

class OpenFlowFeaturesRequest(Packet):
    name = "OpenFlowFeaturesRequest"

class OpenFlowFeaturesReply(Packet):
    name="OpenFlowFeaturesReply"
    fields_desc = [
        LongField("dpid", 1),
        IntField("nbuffers", 256),
        ByteField("ntables", 254),
        ByteField("auxilaryid", 0),
        ShortField("padding", 0),
        # the following will be bit fields set for each capability 
        # supported by the switch. As of 1.3.2 (0x04), 7 flags are 
        # supported (out of 32 available)
        # default here value is what mininet switch sends
        BitField("capabilities", 0x47, 32),
        IntField("reserved", 0),    # reserved 32 bit field
    ]

class OpenFlowHeader(Packet):
    name = "OpenFlowHeader"
    """
    length should be length of the payload OpenFlowRequest or
    OpenFlowResponse + 8 for header).
    I am condensing req and res to a single
    class OpenFlowMessage
    """
    fields_desc=[
                XByteField("version", 0x04),
                ByteEnumField("type", 0, OF_TYPES),
                ShortField("length", None),
                IntField("xid", 676265)
                ]

    def post_build(self, curr_layer, payload):
        if self.length is None:
            #l = 8 + len(payload)    # hardcoded 8 as size of header
            l = len(curr_layer) + len(payload)
            curr_layer = curr_layer[:2] + pack("!H",l) + curr_layer[4:]
        return curr_layer+payload

    def guess_payload_class(self, payload):
        if self.type == 0:
            return OpenFlowHello
        #if self.type == 1:
        #    return OpenFlowError
        elif self.type == 2:
            return OpenFlowEchoRequest
        elif self.type == 3:
            return OpenFlowEchoReply
        #if self.type == 4:
        #    return OpenFlowEchoReply
        elif self.type == 5:
            return OpenFlowFeaturesRequest
        elif self.type == 6:
            return OpenFlowFeaturesReply
        else:
            return Packet.guess_payload_class(self, payload)

bind_layers(TCP, OpenFlowHeader, sport=6633)
bind_layers(TCP, OpenFlowHeader, dport=6633)
bind_layers(TCP, OpenFlowHeader, sport=6653)
bind_layers(TCP, OpenFlowHeader, dport=6653)
bind_layers(OpenFlowHeader, OpenFlowHello, {'type': 0}) 
bind_layers(OpenFlowHeader, OpenFlowEchoRequest, {'type': 2})
bind_layers(OpenFlowHeader, OpenFlowEchoReply, {'type': 3})
bind_layers(OpenFlowHeader, OpenFlowFeaturesRequest, {'type': 5})
bind_layers(OpenFlowHeader, OpenFlowFeaturesReply, {'type': 6})

