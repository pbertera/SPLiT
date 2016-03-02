#    Copyright 2015 Pietro Bertera <pietro@bertera.it>
#
#    This work is based on the https://github.com/tirfil/PySipProxy
#    from Philippe THIRION.
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

import SocketServer
import re
import string
import socket
import sys
import time
import hashlib
import random

# Regexp matching SIP messages:
rx_register = re.compile("^REGISTER")
rx_invite = re.compile("^INVITE")
rx_ack = re.compile("^ACK")
rx_prack = re.compile("^PRACK")
rx_cancel = re.compile("^CANCEL")
rx_bye = re.compile("^BYE")
rx_options = re.compile("^OPTIONS")
rx_subscribe = re.compile("^SUBSCRIBE")
rx_publish = re.compile("^PUBLISH")
rx_notify = re.compile("^NOTIFY")
rx_info = re.compile("^INFO")
rx_message = re.compile("^MESSAGE")
rx_refer = re.compile("^REFER")
rx_update = re.compile("^UPDATE")
rx_from = re.compile("^From:")
rx_cfrom = re.compile("^f:")
rx_to = re.compile("^To:")
rx_cto = re.compile("^t:")
rx_tag = re.compile(";tag=(.*)")
rx_contact = re.compile("^Contact:")
rx_ccontact = re.compile("^m:")
rx_useragent = re.compile("^User-Agent:")
rx_contentdisposition = re.compile("^Content-Disposition:")
rx_supported = re.compile("^Supported:")
rx_sessionexpires = re.compile("^Session-Expires:")
rx_maxforward = re.compile("^Max-Forwards:")
rx_uri_with_params = re.compile("sip:([^@]*)@([^;>$]*)")
rx_uri = re.compile("sip:([^@]*)@([^>$]*)")
rx_addr = re.compile("sip:([^ ;>$]*)")
#rx_addrport = re.compile("([^:]*):(.*)")
rx_code = re.compile("^SIP/2.0 ([^ ]*)")
#rx_invalid = re.compile("^192\.168")
#rx_invalid2 = re.compile("^10\.")
#rx_cseq = re.compile("^CSeq:")
#rx_callid = re.compile("Call-ID: (.*)$")
#rx_rr = re.compile("^Record-Route:")
rx_request_uri = re.compile("^([^ ]*) sip:([^ ]*?)(;.*)* SIP/2.0")
rx_route = re.compile("^Route: (.*)")
rx_record_route = re.compile("^Record-Route:")
rx_contentlength = re.compile("^Content-Length:")
rx_ccontentlength = re.compile("^l:")
rx_contenttype = re.compile("^Content-Type:")
rx_via = re.compile("^Via:")
rx_cvia = re.compile("^v:")
rx_branch = re.compile(";branch=([^;]*)")
rx_rport = re.compile(";rport$|;rport;")
rx_contact_expires = re.compile("expires=([^;$]*)")
rx_expires = re.compile("^Expires: (.*)$")
rx_authorization = re.compile("^Authorization: +\S{6} (.*)")
rx_proxy_authorization = re.compile("^Proxy-Authorization: +\S{6} (.*)")
rx_kv= re.compile("([^=]*)=(.*)")

local_tag = '123456-SPLiT'

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

def generateNonce(n, str="0123456789abcdef"):
    nonce = ""
    for i in range(n):
        a = int(random.uniform(0,len(str)))
        nonce += str[a]
    return nonce
    
class SipTracedUDPServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):
    def __init__(self, server_address, RequestHandlerClass, sip_logger, main_logger, options):
        self.allow_reuse_address = True
        SocketServer.UDPServer.__init__(self, server_address, RequestHandlerClass)
        self.sip_logger = sip_logger
        self.main_logger = main_logger
        self.options = options
       
        self.allow_reuse_address = True
        self.registrar = {}
        self.auth = {}
        if self.options.sip_exposed_ip:
            rr_ip = self.options.sip_exposed_ip
        else:
            rr_ip = server_address[0]
        if self.options.sip_exposed_port:
            rr_port = self.options.sip_exposed_port
        else:
            rr_port = server_address[1]
        self.recordroute = "Record-Route: <sip:%s:%d;lr>" % (rr_ip, rr_port)
        self.topvia = "Via: SIP/2.0/UDP %s:%d" % (server_address[0], server_address[1])
        self.main_logger.info("NOTICE: SIP Proxy starting on %s:%d" % (server_address[0], server_address[1]))
        #self.main_logger.debug("SIP: Config dump: %s" % self.options)

class UDPHandler(SocketServer.BaseRequestHandler):   

    def debugRegister(self):
        self.server.main_logger.debug("SIP: *** REGISTRAR ***")
        self.server.main_logger.debug("SIP: *****************")
        for key in self.server.registrar.keys():
            self.server.main_logger.debug("SIP: %s -> %s" % (key,self.server.registrar[key][0]))
        self.server.main_logger.debug("SIP: *****************")

    def checkAuthorization(self, authorization, password, nonce, method="REGISTER"):
        hash = {}
        list = authorization.split(",")
        for elem in list:
            md = rx_kv.search(elem)
            if md:
                value = string.strip(md.group(2),'" ')
                key = string.strip(md.group(1))
                hash[key]=value
        # check nonce (response/request)
        if hash["nonce"] != nonce:
            self.server.main_logger.warning("SIP: Authentication: Incorrect nonce")
            return False

        a1="%s:%s:%s" % (hash["username"],hash["realm"], password)
        a2="%s:%s" % (method, hash["uri"])
        ha1 = hashlib.md5(a1).hexdigest()
        ha2 = hashlib.md5(a2).hexdigest()
        b = "%s:%s:%s" % (ha1,nonce,ha2)
        expected = hashlib.md5(b).hexdigest()
        if expected == hash["response"]:
            self.server.main_logger.debug("SIP: Authentication: succeeded")
            return True
        self.server.main_logger.warning("SIP: Authentication: expected= %s" % expected)
        self.server.main_logger.warning("SIP: Authentication: response= %s" % hash["response"])
        return False

    def changeRequestUri(self):
        # change request uri
        md = rx_request_uri.search(self.data[0])
        if md:
            method = md.group(1)
            uri = md.group(2)
            if self.server.registrar.has_key(uri):
                uri = "sip:%s" % self.server.registrar[uri][0]
                self.server.main_logger.debug("SIP: changeRequestUri: %s -> %s" % ( self.data[0] , "%s %s SIP/2.0" % (method,uri)))
                self.data[0] = "%s %s SIP/2.0" % (method,uri)
            else:
                self.server.main_logger.debug("SIP: URI not found in Registrar: %s leaving the URI unchanged" % uri)

    def removeHeader(self, regex, data=None):
        """
        remove a SIP header.
        - `regex`contains the regex to extract the header
        - if `data` is defined the `regex`is searched into data, otherwise in self.data
        """
        if data == None:
            read_data = self.data
        else:
            read_data = data
        self.server.main_logger.debug("SIP: Removing header with regex %s" % regex.pattern)
        data = []
        for line in read_data:
            if not regex.search(line):
                data.append(line)
            else:
                self.server.main_logger.debug("SIP: Removed %s" % line)
        return data

    def removeMaxForward(self, data=None):
        return self.removeHeader(rx_maxforward, data)

    def removeRouteHeader(self, data=None):
        return self.removeHeader(rx_route, data)

    def removeRecordRouteHeader(self, data=None):
        return self.removeHeader(rx_record_route, data)

    def removeContact(self, data=None):
        return self.removeHeader(rx_contact, data)

    def removeContentType(self, data=None):
        return self.removeHeader(rx_contenttype, data)
    
    def removeUserAgent(self, data=None):
        return self.removeHeader(rx_useragent, data)
    
    def removeSessionExpires(self, data=None):
        return self.removeHeader(rx_sessionexpires, data)

    def removeSupported(self, data=None):
        return self.removeHeader(rx_supported, data)
    
    def removeContentDisposition(self):
        return self.removeHeader(rx_contentdisposition)

    def addTopVia(self):
        branch= ""
        data = []
        for line in self.data:
            if rx_via.search(line) or rx_cvia.search(line):
                md = rx_branch.search(line)
                if md:
                    branch=md.group(1)
                    via = "%s;branch=%s" % (self.server.topvia, branch)
                    data.append(via)
                    self.server.main_logger.debug("SIP: Adding Top Via header: %s" % via)
                # rport processing
                if rx_rport.search(line):
                    text = "received=%s;rport=%d" % self.client_address
                    via = line.replace("rport",text)   
                else:
                    text = "received=%s" % self.client_address[0]
                    via = "%s;%s" % (line,text)
                self.server.main_logger.debug("SIP: Adding Top Via header: %s" % via)
                data.append(via)
            else:
                data.append(line)
        return data
                
    def removeTopVia(self):
        data = []
        for line in self.data:
            if rx_via.search(line) or rx_cvia.search(line):
                if not line.startswith(self.server.topvia):
                    data.append(line)
            else:
                data.append(line)
        return data
        
    def checkValidity(self,uri):
        addrport, socket, client_addr, validity = self.server.registrar[uri]
        now = int(time.time())
        if validity > now:
            return True
        else:
            del self.server.registrar[uri]
            self.server.main_logger.warning("SIP: Registration for %s has expired" % uri)
            return False
    
    def getSocketInfo(self,uri):
        addrport, socket, client_addr, validity = self.server.registrar[uri]
        return (socket,client_addr)
        
    def getDestination(self, with_params=True):
        destination = ""
        for line in self.data:
            if rx_to.search(line) or rx_cto.search(line):
                if with_params:
                    md = rx_uri_with_params.search(line)
                else:
                    md = rx_uri.search(line)
                if md:
                    destination = "%s@%s" %(md.group(1),md.group(2))
                break
        return destination
                
    def getOrigin(self):
        origin = ""
        for line in self.data:
            if rx_from.search(line) or rx_cfrom.search(line):
                md = rx_uri_with_params.search(line)
                if md:
                    origin = "%s@%s" %(md.group(1),md.group(2))
                break
        return origin
        
    def sendResponse(self,code):
        self.server.main_logger.debug("SIP: Sending Response %s" % code)
        request_uri = "SIP/2.0 " + code
        self.data[0]= request_uri
        index = 0
        data = []
        for line in self.data:
            data.append(line)
            if rx_to.search(line) or rx_cto.search(line):
                if not rx_tag.search(line):
                    data[index] = "%s%s" % (line,";tag=%s" % local_tag)
            if rx_via.search(line) or rx_cvia.search(line):
                # rport processing
                if rx_rport.search(line):
                    text = "received=%s;rport=%d" % self.client_address
                    data[index] = line.replace("rport",text) 
                else:
                    text = "received=%s" % self.client_address[0]
                    data[index] = "%s;%s" % (line,text)      
            if rx_contentlength.search(line):
                data[index]="Content-Length: 0"
            if rx_ccontentlength.search(line):
                data[index]="l: 0"
            index += 1
            if line == "":
                break
        data.append("")
        text = string.join(data,"\r\n")
        self.sendTo(text, self.client_address)
        self.server.sip_logger.debug("Send to: %s:%d (%d bytes):\n\n%s" % (self.client_address[0], self.client_address[1], len(text),text))
    
    def sendTo(self, data, client_address, socket=None):
        self.server.main_logger.debug("SIP: Sending to %s:%d" % (client_address))
        if socket:
            sent = socket.sendto(data, client_address)
        else:
            sent = self.socket.sendto(data, client_address)
        self.server.main_logger.debug("SIP: Succesfully sent %d bytes" % sent)

    def processRegister(self):
        self.server.main_logger.info("SIP: Register received: %s" % self.data[0])
        fromm = ""
        contact = ""
        contact_expires = ""
        header_expires = ""
        expires = None
        validity = 0
        authorization = ""
        index = 0
        auth_index = 0
        data = []
        size = len(self.data)

        for line in self.data:
            if rx_to.search(line) or rx_cto.search(line):
                md = rx_uri.search(line)
                if md:
                    fromm = "%s@%s" % (md.group(1),md.group(2))
            if rx_contact.search(line) or rx_ccontact.search(line):
                md = rx_uri.search(line)
                if md:
                    contact = "%s@%s" % (md.group(1), md.group(2))
                    self.server.main_logger.debug("SIP: Registration: Contact from rx_uri regex: %s" % contact)
                else:
                    md = rx_addr.search(line)
                    if md:
                        contact = md.group(1)
                        self.server.main_logger.debug("SIP: Registration: Contact from rx_addr regex: %s" % contact)
                md = rx_contact_expires.search(line)
                if md:
                    contact_expires = md.group(1)
            md = rx_expires.search(line)
            if md:
                header_expires = md.group(1)
            
            md = rx_authorization.search(line)
            if md:
                authorization= md.group(1)
                auth_index = index
                #print authorization
            index += 1

        # remove Authorization header for response
        if auth_index > 0:
            self.data.pop(auth_index)

        if len(authorization)> 0 and self.server.auth.has_key(fromm):
            nonce = self.server.auth[fromm]
            if not self.checkAuthorization(authorization, self.server.options.sip_password, nonce):
                self.sendResponse("403 Forbidden")
                return
        else:
            nonce = generateNonce(32)
            self.server.auth[fromm]=nonce
            header = "WWW-Authenticate: Digest realm=\"%s\", nonce=\"%s\"" % ("dummy",nonce)
            self.data.insert(6,header)
            self.sendResponse("401 Unauthorized")
            return

        if len(contact_expires) > 0:
            expires = int(contact_expires)
        elif len(header_expires) > 0:
            expires = int(header_expires)

        if expires == 0:
            if self.server.registrar.has_key(fromm):
                del self.server.registrar[fromm]
                self.sendResponse("200 0K")
                return

        elif expires == None:
            expires = self.server.options.sip_expires
            header = "Expires: %s" % expires
            self.data.insert(6, header)

        if expires != 0:
            now = int(time.time())
            validity = now + expires

        self.server.main_logger.info("SIP: Registration: From: %s - Contact: %s" % (fromm,contact))
        self.server.main_logger.debug("SIP: Registration: Client address: %s:%s" % self.client_address)
        self.server.main_logger.debug("SIP: Registration: Expires= %d" % expires)
        self.server.registrar[fromm]=[contact,self.socket,self.client_address,validity]
        self.debugRegister()
        self.sendResponse("200 0K")

    def is_authenticated(function):
        def _is_authenticated(self, *args, **kwargs):
            proxy_auth = ""
            index = 0
            auth_index = 0

            md = rx_request_uri.search(self.data[0])
            if md:
                method = md.group(1)

            if method not in self.server.options.authenticated_requests:
                return function(self)

            self.server.main_logger.debug("SIP: Request %s received, checking auth" % method)

            for line in self.data:
                if rx_to.search(line) or rx_cto.search(line):
                    md = rx_uri.search(line)
                    if md:
                        fromm = "%s@%s" % (md.group(1),md.group(2))
                md = rx_proxy_authorization.search(line) or rx_authorization.search(line)
                if md:
                    proxy_auth= md.group(1)
                    auth_index = index
                index += 1

            # remove Authorization header for response
            if auth_index > 0:
                self.data.pop(auth_index)

            if len(proxy_auth)> 0 and self.server.auth.has_key(fromm):
                nonce = self.server.auth[fromm]
                if not self.checkAuthorization(proxy_auth, self.server.options.sip_password, nonce, method=method):
                    self.server.main_logger.debug("SIP: Authentication failure")
                    self.data = self.removeContact()
                    self.sendResponse("403 Forbidden")
                    return
            else:
                nonce = generateNonce(32)
                self.server.auth[fromm]=nonce
                header = "Proxy-Authenticate: Digest realm=\"%s\", nonce=\"%s\"" % ("dummy",nonce)
                self.data.insert(6,header)
                self.server.main_logger.debug("SIP: Requesting authentication")
                self.data = self.removeContact()
                self.sendResponse("401 Unauthorized")
                return
            self.server.main_logger.debug("SIP: Request authenticated")
            return function(self)
        return _is_authenticated

    def add_headers(function):
        def _add_headers(self, *args, **kwargs):
            if len(self.server.options.sip_custom_headers) > 0:
                for full_header in self.server.options.sip_custom_headers:
                    md = rx_request_uri.search(self.data[0])
                    if md:
                        method = md.group(1)
                        uri = md.group(2)
                    else:
                        self.server.main_logger.debug("SIP: Custom headers: received code, ignoring")
                        return function(self)

                    conf_header_method = full_header.split(':')[0]
                    try:
                        conf_header_uri_r = full_header.split(':')[1]
                        conf_header_value = ':'.join(full_header.split(':')[2:])
                    except IndexError:
                        self.server.main_logger.error("SIP: Invalid custom header value: '%s'" % full_header)
                        continue

                    if conf_header_method.upper() == method.upper() or conf_header_method == '*':
                        self.server.main_logger.debug("SIP: Matched custom method '%s' against '%s'" % (conf_header_method, method))
                        try:
                            match = re.match(conf_header_uri_r, uri)
                        except:
                            self.server.main_logger.error("SIP: Invalid regex: '%s'" % conf_header_uri_r)
                            continue
                        if match: 
                            self.server.main_logger.debug("SIP: Matched custom header regex '%s' against '%s' URI" % (conf_header_uri_r, uri))
                            self.server.main_logger.debug("SIP: Adding header '%s'" % conf_header_value)
                            self.data.insert(2, conf_header_value)

            return function(self)
        return _add_headers

    def is_redirect(function):
        def _is_redirect(self, *args, **kwargs):
            if self.server.options.sip_redirect:
                self.server.main_logger.debug("SIP: Acting as a redirect server")
                
                md = rx_request_uri.search(self.data[0])
                if md:
                    method = md.group(1)
                    uri = md.group(2)
                else:
                    if rx_code.search(self.data[0]):
                        self.server.main_logger.debug("SIP: Received code, ignoring")
                    return
                if method.upper() == "ACK":
                    self.server.main_logger.debug("SIP: Received ACK, ignoring")
                    return
                if method.upper() != "INVITE":
                    self.server.main_logger.debug("SIP: non-INVITE received")
                    self.sendResponse("405 Method Not Allowed")
                    return

                origin = self.getOrigin()
                if len(origin) == 0 or not self.server.registrar.has_key(origin):
                    self.server.main_logger.debug("SIP: Invite: Origin not found: %s" % origin)
                    self.sendResponse("400 Bad Request")
                    return
                destination = self.getDestination(with_params=True)
                if len(destination) > 0:
                    self.server.main_logger.debug("SIP: Destination: %s" % destination)
                    if self.server.registrar.has_key(destination) and self.checkValidity(destination):
                        contact = self.server.registrar[destination][0]
                        header = "Contact: <sip:%s>" % contact
                        self.data = self.removeContact()
                        self.data = self.removeContentType()
                        self.data = self.removeUserAgent()
                        self.data = self.removeSessionExpires()
                        self.data = self.removeSupported()
                        self.data = self.removeContentDisposition()
                        self.data = self.removeMaxForward()
                        #self.data = self.addTopVia()
                        self.data = self.removeRouteHeader()
                        self.server.main_logger.debug("SIP: Destination %s" % header)
                        self.data.insert(6,header)
                        self.sendResponse("302 Moved Temporarily")
                        self.server.main_logger.debug("SIP: Destination Contact: %s" % contact)
                        return
                    else:
                        self.server.main_logger.info("SIP: Destination not found in registrar")
                        self.sendResponse("404 Not Found")
                        return
                else:
                    self.server.main_logger.error("SIP: Error retreiving destination")
                    self.sendResponse("404 Not Found") #TODO: is the right message here ?
                    return
            else:
                self.server.main_logger.debug("SIP: Running in proxy mode")
            return function(self)
        return _is_redirect

    @is_authenticated
    @add_headers
    @is_redirect
    def processInvite(self):
        self.server.main_logger.debug("SIP: INVITE received")
        origin = self.getOrigin()
        if len(origin) == 0 or not self.server.registrar.has_key(origin):
            self.server.main_logger.debug("SIP: Invite: Origin not found: %s" % origin)
            self.sendResponse("400 Bad Request")
            return
        destination = self.getDestination(with_params=True)
        if len(destination) > 0:
            self.server.main_logger.info("SIP: Invite: destination %s" % destination)
            if self.server.registrar.has_key(destination) and self.checkValidity(destination):
                socket,claddr = self.getSocketInfo(destination)
                self.changeRequestUri()
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                data.insert(1, self.server.recordroute)
                text = string.join(data,"\r\n")
                self.sendTo(text , claddr, socket)
                self.server.main_logger.debug("SIP: Forwarding INVITE to %s:%d" % (claddr[0], claddr[1]))
                self.server.sip_logger.debug("Send to: %s:%d (%d bytes):\n\n%s" % (claddr[0], claddr[1], len(text),text))
            else:
                self.sendResponse("404 Not Found")
        else:
            self.sendResponse("500 Server Internal Error")

    @is_authenticated
    @add_headers
    @is_redirect
    def processAck(self):
        route = None
        self.server.main_logger.info("SIP: ACK received: %s" % self.data[0])
        #FIXME: really stupid way to idenitify an ACK belonging to a locally generated code.
        for line in self.data:
            if rx_to.search(line) or rx_cto.search(line):
                md = rx_tag.search(line)
                if md:
                    tag = md.group(1)
                    if tag == local_tag:
                        self.server.main_logger.warning("SIP: ACK to local code, ignoring")
                        return
        destination = self.getDestination()
        if len(destination) > 0:
            self.server.main_logger.info("SIP: ACK: destination %s" % destination)
            if self.server.registrar.has_key(destination):
                socket,claddr = self.getSocketInfo(destination)
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                data.insert(1, self.server.recordroute)
                text = string.join(data,"\r\n")
                self.sendTo(text, claddr, socket)
                self.server.sip_logger.debug("SIP: Send to: %s:%d (%d bytes):\n\n%s" % (claddr[0], claddr[1], len(text),text))
            else:
                self.server.main_logger.error("SIP: ACK not proxied: destination not found")

    @is_authenticated
    @add_headers
    @is_redirect
    def processGenericRequest(self):
        self.server.main_logger.info("SIP: Request received: %s" % self.data[0])
        origin = self.getOrigin()
        if len(origin) == 0 or not self.server.registrar.has_key(origin):
            self.server.main_logger.debug("SIP: Origin not found: %s" % origin)
            self.sendResponse("400 Bad Request")
            return
        destination = self.getDestination()
        if len(destination) > 0:
            self.server.main_logger.info("SIP: Destination %s" % destination)
            if self.server.registrar.has_key(destination) and self.checkValidity(destination):
                socket,claddr = self.getSocketInfo(destination)
                self.changeRequestUri()
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                #insert Record-Route
                data.insert(1, self.server.recordroute)
                text = string.join(data,"\r\n")
                self.sendTo(text, claddr, socket)
                self.server.sip_logger.debug("Send to: %s:%d (%d bytes):\n\n%s" % (claddr[0], claddr[1], len(text),text))
            else:
                self.sendResponse("404 Not found")
        else:
            self.sendResponse("500 Server Internal Error")
    
    @is_redirect
    def processCode(self):
        self.server.main_logger.info("SIP: Code received: %s" % self.data[0])
        origin = self.getOrigin()
        if len(origin) > 0:
            self.server.main_logger.debug("SIP: Code: origin %s" % origin)
            if self.server.registrar.has_key(origin):
                socket,claddr = self.getSocketInfo(origin)
                data = self.removeTopVia()
                data = self.removeRouteHeader(data)
                self.server.main_logger.debug("SIP: Code received: %s" % self.data[0])
                text = string.join(data,"\r\n")
                self.sendTo(text,claddr, socket)
                self.server.sip_logger.debug("Send to: %s:%d (%d bytes):\n\n%s" % (claddr[0], claddr[1], len(text),text))
                
    def processRequest(self):
        if len(self.data) > 0:
            request_uri = self.data[0]
            if rx_register.search(request_uri):
                self.processRegister()
            elif rx_invite.search(request_uri):
                self.processInvite()
            elif rx_ack.search(request_uri):
                self.processAck()
            elif rx_bye.search(request_uri):
                self.processGenericRequest()
            elif rx_cancel.search(request_uri):
                self.processGenericRequest()
            elif rx_options.search(request_uri):
                self.processGenericRequest()
            elif rx_message.search(request_uri):
                self.processGenericRequest()
            elif rx_refer.search(request_uri):
                self.processGenericRequest()
            elif rx_prack.search(request_uri):
                self.processGenericRequest()
            elif rx_update.search(request_uri):
                self.processGenericRequest()
            elif rx_info.search(request_uri):
                #self.sendResponse("200 0K")
                self.processGenericRequest()
            elif rx_subscribe.search(request_uri):
                self.processGenericRequest()
                #self.sendResponse("200 0K")
            elif rx_publish.search(request_uri):
                self.sendResponse("200 0K")
            elif rx_notify.search(request_uri):
                self.processGenericRequest()
                #self.sendResponse("200 0K")
            elif rx_code.search(request_uri):
                self.processCode()
            else:
                self.server.main_logger.error("SIP: request_uri %s" % request_uri)          
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
                self.server.sip_logger.debug('SIP Hex data:\n' + '\n'.join(mess))
