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
import optparse
import sys
import time
import hashlib
import random
import logging

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
rx_tag = re.compile(";tag")
rx_contact = re.compile("^Contact:")
rx_ccontact = re.compile("^m:")
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
rx_route = re.compile("^Route:")
rx_contentlength = re.compile("^Content-Length:")
rx_ccontentlength = re.compile("^l:")
rx_via = re.compile("^Via:")
rx_cvia = re.compile("^v:")
rx_branch = re.compile(";branch=([^;]*)")
rx_rport = re.compile(";rport$|;rport;")
rx_contact_expires = re.compile("expires=([^;$]*)")
rx_expires = re.compile("^Expires: (.*)$")
rx_authorization = re.compile("^Authorization: +\S{6} (.*)")
rx_kv= re.compile("([^=]*)=(.*)")

# global dictionnary
recordroute = ""
topvia = ""
registrar = {}
auth = {}

def setup_logger(logger_name, log_file=None, level=logging.INFO, str_format='%(asctime)s %(levelname)s %(message)s'):
    l = logging.getLogger(logger_name)
    l.setLevel(level)
    formatter = logging.Formatter(str_format)
    if log_file:
        fileHandler = logging.FileHandler(log_file, mode='w')
        fileHandler.setFormatter(formatter)
        l.addHandler(fileHandler)
    else: 
        streamHandler = logging.StreamHandler()
        streamHandler.setFormatter(formatter)
        l.addHandler(streamHandler)

def hexdump( chars, sep, width ):
    while chars:
        line = chars[:width]
        chars = chars[width:]
        line = line.ljust( width, '\000' )
        sip_logger.debug("%s%s%s" % ( sep.join( "%02x" % ord(c) for c in line ),sep, quotechars( line )))

def quotechars( chars ):
	return ''.join( ['.', c][c.isalnum()] for c in chars )

def showtime():
    main_logger.debug(time.strftime("(%H:%M:%S)", time.localtime()))
    
def generateNonce(n):
    str = "0123456789abcdef"
    length = len(str)
    nonce = ""
    for i in range(n):
        a = int(random.uniform(0,length))
        nonce += str[a]
    return nonce
    
def checkAuthorization(authorization, password, nonce):
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
        main_logger.warning("Authentication: Incorrect nonce")
        return False

    a1="%s:%s:%s" % (hash["username"],hash["realm"], password)
    a2="REGISTER:%s" % hash["uri"]
    ha1 = hashlib.md5(a1).hexdigest()
    ha2 = hashlib.md5(a2).hexdigest()
    b = "%s:%s:%s" % (ha1,nonce,ha2)
    expected = hashlib.md5(b).hexdigest()
    if expected == hash["response"]:
        main_logger.debug("Authentication: succeeded")
        return True
    main_logger.warning("Authentication: expected= %s" % expected)
    main_logger.warning("Authentication: response= %s" % hash["response"])
    return False

class UDPHandler(SocketServer.BaseRequestHandler):   
    
    def debugRegister(self):
        main_logger.debug("*** REGISTRAR ***")
        main_logger.debug("*****************")
        for key in registrar.keys():
            main_logger.debug("%s -> %s" % (key,registrar[key][0]))
        main_logger.debug("*****************")
    
    def changeRequestUri(self):
        # change request uri
        md = rx_request_uri.search(self.data[0])
        if md:
            method = md.group(1)
            uri = md.group(2)
            if registrar.has_key(uri):
                uri = "sip:%s" % registrar[uri][0]
                main_logger.debug("changeRequestUri: %s -> %s" % ( self.data[0] , "%s %s SIP/2.0" % (method,uri)))
                self.data[0] = "%s %s SIP/2.0" % (method,uri)
            else:
                main_logger.debug("URI not found in Registrar: %s leaving the URI unchanged" % uri)

    def removeRouteHeader(self):
        # delete Route
        data = []
        for line in self.data:
            if not rx_route.search(line):
                data.append(line)
        return data
    
    def addTopVia(self):
        branch= ""
        data = []
        for line in self.data:
            if rx_via.search(line) or rx_cvia.search(line):
                md = rx_branch.search(line)
                if md:
                    branch=md.group(1)
                    via = "%s;branch=%sm" % (topvia, branch)
                    data.append(via)
                # rport processing
                if rx_rport.search(line):
                    text = "received=%s;rport=%d" % self.client_address
                    via = line.replace("rport",text)   
                else:
                    text = "received=%s" % self.client_address[0]
                    via = "%s;%s" % (line,text)
                data.append(via)
            else:
                data.append(line)
        return data
                
    def removeTopVia(self):
        data = []
        for line in self.data:
            if rx_via.search(line) or rx_cvia.search(line):
                if not line.startswith(topvia):
                    data.append(line)
            else:
                data.append(line)
        return data
        
    def checkValidity(self,uri):
        addrport, socket, client_addr, validity = registrar[uri]
        now = int(time.time())
        if validity > now:
            return True
        else:
            del registrar[uri]
            main_logger.warning("Registration for %s has expired" % uri)
            return False
    
    def getSocketInfo(self,uri):
        addrport, socket, client_addr, validity = registrar[uri]
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
        request_uri = "SIP/2.0 " + code
        self.data[0]= request_uri
        index = 0
        data = []
        for line in self.data:
            data.append(line)
            if rx_to.search(line) or rx_cto.search(line):
                if not rx_tag.search(line):
                    data[index] = "%s%s" % (line,";tag=123456")
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
        self.socket.sendto(text,self.client_address)
        #showtime()
        sip_logger.debug("Send to: %s:%d ([%d] bytes):\n%s" % (self.client_address[0], self.client_address[1], len(text),text))
        
    def processRegister(self):
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
                    main_logger.debug("Registration: Contact from rx_uri regex: %s" % contact)
                else:
                    md = rx_addr.search(line)
                    if md:
                        contact = md.group(1)
                        main_logger.debug("Registration: Contact from rx_addr regex: %s" % contact)
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

        #if rx_invalid.search(contact) or rx_invalid2.search(contact):
        #    if registrar.has_key(fromm):
        #        del registrar[fromm]
        #    self.sendResponse("488 Not Acceptable Here")    
        #    return
            
        # remove Authorization header for response
        if auth_index > 0:
            self.data.pop(auth_index)
           
                
        if len(authorization)> 0 and auth.has_key(fromm):
            nonce = auth[fromm]
            if not checkAuthorization(authorization,options.password,nonce):
                self.sendResponse("403 Forbidden")
                return
        else:
            nonce = generateNonce(32)
            auth[fromm]=nonce
            header = "WWW-Authenticate: Digest realm=\"%s\", nonce=\"%s\"" % ("dummy",nonce)
            self.data.insert(6,header)
            self.sendResponse("401 Unauthorized")
            return
        
        if len(contact_expires) > 0:
            expires = int(contact_expires)
        elif len(header_expires) > 0:
            expires = int(header_expires)
        
        if expires == 0:
            if registrar.has_key(fromm):
                del registrar[fromm]
                self.sendResponse("200 0K")
                return
        elif expires == None:
            expires = options.expires
            header = "Expires: %s" % expires
            self.data.insert(6, header)
        
        if expires != 0:
            now = int(time.time())
            validity = now + expires
            
    
        main_logger.info("Registration: From: %s - Contact: %s" % (fromm,contact))
        main_logger.debug("Registration: Client address: %s:%s" % self.client_address)
        main_logger.debug("Registration: Expires= %d" % expires)
        registrar[fromm]=[contact,self.socket,self.client_address,validity]
        self.debugRegister()
        self.sendResponse("200 0K")
        
    def processInvite(self):
        main_logger.debug("INVITE received")
        origin = self.getOrigin()
        if len(origin) == 0 or not registrar.has_key(origin):
            main_logger.debug("Invite: Origin not found: %s" % origin)
            self.sendResponse("400 Bad Request")
            return
        destination = self.getDestination(with_params=True)
        if len(destination) > 0:
            main_logger.info("Invite: destination %s" % destination)
            if registrar.has_key(destination) and self.checkValidity(destination):
                socket,claddr = self.getSocketInfo(destination)
                self.changeRequestUri()
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                #insert Record-Route
                data.insert(1,recordroute)
                text = string.join(data,"\r\n")
                socket.sendto(text , claddr)
                #showtime()
                main_logger.debug("Forwarding INVITE to %s:%d" % (claddr[0], claddr[1]))
                sip_logger.debug("Send to: %s:%d ([%d] bytes):\n%s" % (claddr[0], claddr[1], len(text),text))
                #sip_logger.info("<<< %s" % data[0])
                #sip_logger.debug("---\n<< server send [%d]:\n%s\n---" % (len(text),text))
            else:
                self.sendResponse("480 Temporarily Unavailable")
        else:
            self.sendResponse("500 Server Internal Error")
                
    def processAck(self):
        main_logger.debug("ACK received")
        destination = self.getDestination()
        if len(destination) > 0:
            main_logger.info("Ack: destination %s" % destination)
            if registrar.has_key(destination):
                socket,claddr = self.getSocketInfo(destination)
                #self.changeRequestUri()
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                #insert Record-Route
                data.insert(1,recordroute)
                text = string.join(data,"\r\n")
                socket.sendto(text,claddr)
                #showtime()
                sip_logger.debug("Send to: %s:%d ([%d] bytes):\n%s" % (claddr[0], claddr[1], len(text),text))
                #main_logger.info("<<< %s" % data[0])
                #main_logger.debug( "---\n<< server send [%d]:\n%s\n---" % (len(text),text))
                
    def processNonInvite(self):
        main_logger.debug("NonInvite received: %s" % self.data[0])
        origin = self.getOrigin()
        if len(origin) == 0 or not registrar.has_key(origin):
            main_logger.debug("NonInvite: Origin not found: %s" % origin)
            self.sendResponse("400 Bad Request")
            return
        destination = self.getDestination()
        if len(destination) > 0:
            main_logger.info("NonInvite: destination %s" % destination)
            if registrar.has_key(destination) and self.checkValidity(destination):
                socket,claddr = self.getSocketInfo(destination)
                self.changeRequestUri()
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                #insert Record-Route
                data.insert(1,recordroute)
                text = string.join(data,"\r\n")
                socket.sendto(text , claddr)
                #showtime()
                sip_logger.debug("Send to: %s:%d ([%d] bytes):\n%s" % (claddr[0], claddr[1], len(text),text))
                #sip_logger.info("<<< %s" % data[0])
                #sip_logger.debug("---\n<< server send [%d]:\n%s\n---" % (len(text),text))    
            else:
                self.sendResponse("406 Not Acceptable")
        else:
            self.sendResponse("500 Server Internal Error")
    
    def processCode(self):
        origin = self.getOrigin()
        if len(origin) > 0:
            main_logger.debug("Code: origin %s" % origin)
            if registrar.has_key(origin):
                socket,claddr = self.getSocketInfo(origin)
                self.data = self.removeRouteHeader()
                main_logger.debug("Code received: %s" % self.data[0])
                data = self.removeTopVia()
                text = string.join(data,"\r\n")
                socket.sendto(text,claddr)
                #showtime()
                #sip_logger.info("<<< %s" % data[0])
                #sip_logger.debug("---\n<< server send [%d]:\n%s\n---" % (len(text),text))
                sip_logger.debug("Send to: %s:%d ([%d] bytes):\n%s" % (claddr[0], claddr[1], len(text),text))
                
                
    def processRequest(self):
        #print "processRequest"
        if len(self.data) > 0:
            request_uri = self.data[0]
            if rx_register.search(request_uri):
                self.processRegister()
            elif rx_invite.search(request_uri):
                self.processInvite()
            elif rx_ack.search(request_uri):
                self.processAck()
            elif rx_bye.search(request_uri):
                self.processNonInvite()
            elif rx_cancel.search(request_uri):
                self.processNonInvite()
            elif rx_options.search(request_uri):
                self.processNonInvite()
            elif rx_message.search(request_uri):
                self.processNonInvite()
            elif rx_refer.search(request_uri):
                self.processNonInvite()
            elif rx_prack.search(request_uri):
                self.processNonInvite()
            elif rx_update.search(request_uri):
                self.processNonInvite()
            elif rx_info.search(request_uri):
                self.sendResponse("200 0K")
                #self.processNonInvite()
            elif rx_subscribe.search(request_uri):
                self.sendResponse("200 0K")
            elif rx_publish.search(request_uri):
                self.sendResponse("200 0K")
            elif rx_notify.search(request_uri):
                self.processNonInvite()
                #self.sendResponse("200 0K")
            elif rx_code.search(request_uri):
                self.processCode()
            else:
                main_logger.error("request_uri %s" % request_uri)          
                #print "message %s unknown" % self.data
    
    def handle(self):
        #socket.setdefaulttimeout(120)
        data = self.request[0]
        self.data = data.split("\r\n")
        self.socket = self.request[1]
        request_uri = self.data[0]
        if rx_request_uri.search(request_uri) or rx_code.search(request_uri):
            #showtime()
            #sip_logger.info(">>> %s" % request_uri)
            sip_logger.debug("Received from %s:%d (%d bytes):\n%s" %  (self.client_address[0], self.client_address[1], len(data), data))
            #sip_logger.debug("Received from %s:%d" % self.client_address)
            self.processRequest()
        else:
            if len(data) > 4:
                #showtime()
                sip_logger.warning("Received from %s:%d (%d bytes):\n" %  (self.client_address[0], self.client_address[1], len(data)))
                hexdump(data,' ',16)
                sip_logger.warning("---")

if __name__ == "__main__": 
    usage = """%prog [OPTIONS]"""
    opt = optparse.OptionParser(usage=usage)
    opt.add_option('-d', dest='debug', default=False, action='store_true',
            help='run in debug mode')
    opt.add_option('-i', dest='ip_address', type='string', default="127.0.0.1",
            help='Specify ip address to bind on (default: 127.0.0.1)')
    opt.add_option('-p', dest='port', type='int', default=5060,
            help='Specify the UDP port (default: 5060)')
    opt.add_option('-s', dest='sip_logfile', type='string', default=None,
            help='Specify the SIP messages log file (default: log to stdout)')
    opt.add_option('-l', dest='logfile', type='string', default=None,
            help='Specify the log file (default: log to stdout)')
    opt.add_option('-e', dest='expires', type='int', default=3600,
            help='Default registration expires (default: 3600)')
    opt.add_option('-P', dest='password', type='string', default='protected',
            help='Athentication password (default: protected)')
    
    options, args = opt.parse_args(sys.argv[1:])

    if options.debug == True:
        level=logging.DEBUG
    else:
        level=logging.INFO
    setup_logger('main_logger', options.logfile, level)
    setup_logger('sip_logger', options.sip_logfile, level, str_format='%(asctime)s %(message)s')    
    
    main_logger = logging.getLogger('main_logger')
    sip_logger = logging.getLogger('sip_logger')
    
    main_logger.info(time.strftime("Starting proxy at %a, %d %b %Y %H:%M:%S ", time.localtime()))
    recordroute = "Record-Route: <sip:%s:%d;lr>" % (options.ip_address, options.port)
    topvia = "Via: SIP/2.0/UDP %s:%d" % (options.ip_address, options.port)
    
    main_logger.debug("Using the Record-Route header: %s" % recordroute) 
    main_logger.debug("Using the top Via header: %s" % topvia) 
    main_logger.debug("Writing SIP messages in %s log file" % options.sip_logfile)
    main_logger.debug("Authentication password: %s" % options.password)
    main_logger.debug("Logfile: %s" % options.logfile)
    
    server = SocketServer.UDPServer((options.ip_address, options.port), UDPHandler)
    try:
        main_logger.info("Starting serving SIP requests on %s:%d, press CTRL-C for exit." % (options.ip_address, options.port))
        server.serve_forever()
    except KeyboardInterrupt:
        main_logger.info("Exiting.") 
