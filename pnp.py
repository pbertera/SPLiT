#    Copyright 2015 Pietro Bertera <pietro@bertera.it>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import struct
import SocketServer
import re
import socket
import sys
import errno
import platform

# Regexp matching SIP messages:
rx_subscribe = re.compile("^SUBSCRIBE")
rx_uri_with_params = re.compile("sip:([^@]*)@([^;>$]*)")
rx_uri = re.compile("sip:([^@]*)@([^>$]*)")
rx_code = re.compile("^SIP/2.0 ([^ ]*)")
rx_request_uri = re.compile("^([^ ]*) sip:([^ ]*?)(;.*)* SIP/2.0")
rx_event = re.compile("^Event:")
rx_via = re.compile("^Via:")
rx_cvia = re.compile("^v:")

def hexdump( chars, sep, width ):
    """Dump chars in hex and ascii format
    """
    data = []
    while chars:
        line = chars[:width]
        chars = chars[width:]
        line = line.ljust( width, '\000' )
        data.append("%s%s%s" % ( sep.join( "%02x" % ord(c) for c in line ),sep, quotechars( line )))
    return data

def quotechars( chars ):
	return ''.join( ['.', c][c.isalnum()] for c in chars )

class pnp_phone(object):
    """Basic representation of a snom phone."""

    def __init__(self, mac=None, ip=None, mod=None, fw=None, subs=None):
        """Default constructor."""
        self.mac_addr = mac
        self.ip_addr = ip
        self.sip_port = 5060
        self.model = mod
        self.fw_version = fw
        self.subscribe = subs

    def __repr__(self):
        """Gets a string representation of the phone"""
        return "%s (MAC: %s) running Firmware %s found at IP %s" % (self.model, self.__macrepr(self.mac_addr), self.fw_version, self.ip_addr)

    def __macrepr(self, m):
        """ Normalize a MAC address to lower case unix style """  
        m = re.sub("[.:-]", "", m)
        m = m.lower()
        n =  "%s:%s:%s:%s:%s:%s" % (m[0:2], m[2:4], m[4:6], m[6:8], m[8:10], m[10:])
        return n

class SipTracedMcastUDPServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):
    def __init__(self, server_address, RequestHandlerClass, sip_logger, main_logger, options):
        # don't let the parent bind.
        SocketServer.UDPServer.__init__(self,(server_address[0], server_address[1]), RequestHandlerClass, bind_and_activate=False)
        self.sip_logger = sip_logger
        self.main_logger = main_logger
        self.options = options
       
        self.main_logger.info("NOTICE: PnP Server starting on %s:%d and %s:%d." % (server_address[0], server_address[1], self.options.ip_address, self.options.sip_port))
        
        # bind on the right interface where the options.ip_address is
        iface = socket.inet_aton(options.ip_address)
        group = socket.inet_aton(server_address[0])
        # make the socket multicast
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, group+iface)
        self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR, 1)
       
        # If Windows bind on any addr.
        if platform.system().lower() == 'windows':
            self.main_logger.debug("PnP: running on windows, don't select the IP")
            self.socket.bind(('', server_address[1]))
        else:
            self.socket.bind((server_address[0], server_address[1]))
        self.server_address = self.socket.getsockname()

class UDPHandler(SocketServer.BaseRequestHandler):   

    def sendTo(self, data, client_address):
        self.server.main_logger.debug("PnP: Sending to %s:%d" % (client_address))
        #TODO: don't use the hardcoded 1036 port.
        #TODO: 200 OK to the 1036 get missed
        try: 
            sendsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sendsock.bind((self.server.options.ip_address, 1036))
            sent = sendsock.sendto(data, client_address)
        
            self.server.main_logger.debug("PnP: Succesfully sent %d bytes" % sent)
            return True
        except Exception, e:
            self.server.main_logger.error("PnP: Error sending data: %s" % e)
            return False

    def processCode(self):
        self.server.main_logger.info("PnP: Code received: %s" % self.data[0])

    def parse(self):
        try:
            # Line 1 conatains the SUBSCRIBE and our MAC
            new_phone = pnp_phone()
            new_phone.mac_addr = self.data[0][20:32]
            
            for line in self.data:
                if rx_via.search(line) or rx_cvia.search(line):
                    new_phone.ip_addr = line[17:].split(';')[0].split(':')[0]
                    new_phone.sip_port = line[17:].split(';')[0].split(':')[1]
                if rx_event.search(line):
                    l_model_info =line.split(';')
                    new_phone.model = l_model_info[3].split('=')[1][1:-1]
                    new_phone.fw_version = l_model_info[4].split('=')[1][1:-1]
            return new_phone
        except Exception, e:
            self.main_logger("PnP: malformed request, cannot parse")
            return None    

    def get_sip_info(self):
        lines = self.data
        # Some SIP info we need
        call_id = lines[4][9:]
        cseq = lines[5][6]
        via_header = lines[1]
        from_header = lines[2]
        to_header = lines[3]
    
        return (call_id, cseq, via_header, from_header, to_header)   

    def processPnP(self):
        self.server.main_logger.info("PnP: Reqest received: %s" % self.data[0])
        phone = self.parse()
        (call_id, cseq, via_header, from_header, to_header) = self.get_sip_info()

        if phone:
            # Create a socket to send data
            #sendsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            #sendsock.bind(('%s' % self.server.options.ip, 1036))

            # If a phone has been recognized first send 200 OK
            ok_response = "SIP/2.0 200 OK\r\n"
            ok_response += via_header + "\r\n"
            ok_response += "Contact: <sip:" + phone.ip_addr + ":" + phone.sip_port + ";transport=tcp;handler=dum>\r\n"
            ok_response += to_header + "\r\n"
            ok_response += from_header + "\r\n"
            ok_response += "Call-ID: %s\r\n" % call_id
            ok_response += "CSeq: %s SUBSCRIBE\r\nExpires: 0\r\nContent-Length: 0\r\n" % cseq
            
            if self.sendTo(ok_response, (phone.ip_addr, int(phone.sip_port))):
                self.server.sip_logger.debug("PnP: Send to: %s:%s (%d bytes):\n\n%s" % (phone.ip_addr, phone.sip_port, len(ok_response),ok_response))

            # Now send a NOTIFY with the configuration URL
            if not self.server.options.pnp_uri:
                pnp_uri = "http://provisioning.snom.com/%s/%s.php?mac={mac}" % (phone.model, phone.model)
            else:
                pnp_uri = self.server.options.pnp_uri

            notify = "NOTIFY sip:%s:%s SIP/2.0\r\n" % (phone.ip_addr, phone.sip_port)
            notify += via_header + "\r\n"
            notify += "Max-Forwards: 20\r\n"
            notify += "Contact: <sip:%s:1036;transport=TCP;handler=dum>\r\n" % self.server.options.ip_address
            notify += to_header + "\r\n"
            notify += from_header + "\r\n"
            notify += "Call-ID: %s\r\n" % call_id
            notify += "CSeq: 3 NOTIFY\r\n"
            notify += "Content-Type: application/url\r\n"
            notify += "Subscription-State: terminated;reason=timeout\r\n"
            notify += "Event: ua-profile;profile-type=\"device\";vendor=\"OEM\";model=\"OEM\";version=\"7.1.19\"\r\n"
            notify += "Content-Length: %i\r\n" % (len(pnp_uri))
            notify += "\r\n%s" % pnp_uri

            self.sendTo(notify, (phone.ip_addr, int(phone.sip_port)))
            self.server.sip_logger.debug("PnP: Send to: %s:%s (%d bytes):\n\n%s" % (phone.ip_addr, phone.sip_port, len(notify), notify))
    
    def processRequest(self):
        #print "processRequest"
        if len(self.data) > 0:
            request_uri = self.data[0]
            if rx_subscribe.search(request_uri):
                self.processPnP()
            elif rx_code.search(request_uri):
                self.processCode()
            else:
                self.server.main_logger.error("PnP: request_uri %s" % request_uri)          
                #print "message %s unknown" % self.data
    
    def handle(self):
        data = self.request[0]
        self.data = data.split("\r\n")
        self.socket = self.request[1]
        request_uri = self.data[0]
        if rx_request_uri.search(request_uri) or rx_code.search(request_uri):
            self.server.sip_logger.debug("Received from %s:%d (%d bytes):\n\n%s" %  (self.client_address[0], self.client_address[1], len(data), data))
            self.processRequest()
        else:
            if len(data) > 4:
                self.server.sip_logger.debug("Received from %s:%d (%d bytes):\n\n" %  (self.client_address[0], self.client_address[1], len(data)))
                mess = hexdump(data,' ',16)
                self.server.sip_logger.debug('PnP Hex data:\n' + '\n'.join(mess))

if __name__ == '__main__':
    import utils

    class Options:
        ip = "127.0.0.1"
        pnp_uri = "http://test.com"
    
    options = Options()
    
    HOST = "224.0.1.75"
    PORT = 5060
    main_logger = utils.setup_logger('main_logger', None, True)
    sip_logger = utils.setup_logger('sip_logger', None, True)

    pnp_server = SipTracedMcastUDPServer((HOST, PORT), UDPHandler, main_logger, sip_logger, options)
    pnp_server.serve_forever()
