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
import threading

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
rx_contenttype = re.compile("^Content-Type:")
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

class WidgetSipLogger(logging.Handler):
    def __init__(self, widget):
        logging.Handler.__init__(self)
        self.widget = widget
        self.widget.config(state='disabled')

    def emit(self, record):
        self.widget.config(state='normal')
        self.widget.insert(END, self.format(record).replace("\r", "").rstrip('\n') + '\n\n')
        self.widget.see(END)  # Scroll to the bottom
        self.widget.config(state='disabled')

class WidgetLogger(logging.Handler):
    def __init__(self, widget):
        logging.Handler.__init__(self)
        self.widget = widget
        self.widget.config(state='disabled')

    def emit(self, record):
        self.widget.config(state='normal')
        self.widget.insert(END, self.format(record) + '\n')
        self.widget.see(END)  # Scroll to the bottom
        self.widget.config(state='disabled')

def setup_logger(logger_name, log_file=None, level=logging.INFO, str_format='%(asctime)s %(levelname)s %(message)s', widget=None):
    l = logging.getLogger(logger_name)
    l.setLevel(level)
    formatter = logging.Formatter(str_format)
    if widget:
        widgetHandler = widget
        widgetHandler.setFormatter(formatter)
        l.addHandler(widgetHandler)
        return
    elif log_file:
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

class SipTracedUDPServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):
    def __init__(self, server_address, RequestHandlerClass, sip_logger):
        SocketServer.UDPServer.__init__(self, server_address, RequestHandlerClass)
        self.sip_logger = sip_logger

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

    def removeHeader(self, regex):
        main_logger.debug("Removing header with regex %s" % regex.pattern)
        data = []
        for line in self.data:
            if not regex.search(line):
                data.append(line)
            else:
                main_logger.debug("Removed %s" % line)
        return data

    def removeRouteHeader(self):
        return self.removeHeader(rx_route)

    def removeContact(self):
        return self.removeHeader(rx_contact)

    def removeContentType(self):
        return self.removeHeader(rx_contenttype)

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
        main_logger.debug("Sending Response %s" % code)
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
        self.server.sip_logger.debug("Send to: %s:%d ([%d] bytes):\n\n%s" % (self.client_address[0], self.client_address[1], len(text),text))
        
    def processRegister(self):
        main_logger.info("Register received: %s" % self.data[0])
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
    
    def is_redirect(function):
        def _is_redirect(self, *args, **kwargs):
            if options.redirect:
                main_logger.debug("Acting as a redirect server")
                
                md = rx_request_uri.search(self.data[0])
                if md:
                    method = md.group(1)
                    uri = md.group(2)
                else:
                    if rx_code.search(self.data[0]):
                        main_logger.debug("Received code, ignoring")
                    return
                if method.upper() == "ACK":
                    main_logger.debug("Received ACK, ignoring")
                    return
                if method.upper() != "INVITE":
                    self.sendResponse("405 Method Not Allowed")
                    return

                origin = self.getOrigin()
                if len(origin) == 0 or not registrar.has_key(origin):
                    main_logger.debug("Invite: Origin not found: %s" % origin)
                    self.sendResponse("400 Bad Request")
                    return
                destination = self.getDestination(with_params=True)
                if len(destination) > 0:
                    main_logger.debug("Destination: %s" % destination)
                    if registrar.has_key(destination) and self.checkValidity(destination):
                        contact = registrar[destination][0]
                        header = "Contact: <sip:%s>" % contact
                        self.data = self.removeContact()
                        self.data = self.removeContentType()
                        main_logger.debug("Destination %s" % header)
                        self.data.insert(6,header)
                        self.sendResponse("302 Moved temporarily")
                        main_logger.debug("Destination Contact: %s" % contact)
                    else:
                        main_logger.info("Destination not found in registrar")
                        self.sendResponse("404 Not Found")
            else:
                main_logger.debug("Running in proxy mode")
            return function(self)
        return _is_redirect

    @is_redirect
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
                data = self.addTopVia()
                data = self.removeRouteHeader()
                data.insert(1,recordroute)
                text = string.join(data,"\r\n")
                socket.sendto(text , claddr)
                main_logger.debug("Forwarding INVITE to %s:%d" % (claddr[0], claddr[1]))
                self.server.sip_logger.debug("Send to: %s:%d ([%d] bytes):\n\n%s" % (claddr[0], claddr[1], len(text),text))
            else:
                self.sendResponse("480 Temporarily Unavailable")
        else:
            self.sendResponse("500 Server Internal Error")
                
    @is_redirect
    def processAck(self):
        main_logger.info("ACK received: %s" % self.data[0])
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
                self.server.sip_logger.debug("Send to: %s:%d ([%d] bytes):\n\n%s" % (claddr[0], claddr[1], len(text),text))
                #main_logger.info("<<< %s" % data[0])
                #main_logger.debug( "---\n<< server send [%d]:\n%s\n---" % (len(text),text))
                
    @is_redirect
    def processNonInvite(self):
        main_logger.info("NonInvite received: %s" % self.data[0])
        origin = self.getOrigin()
        if len(origin) == 0 or not registrar.has_key(origin):
            main_logger.debug("Origin not found: %s" % origin)
            self.sendResponse("400 Bad Request")
            return
        destination = self.getDestination()
        if len(destination) > 0:
            main_logger.info("Destination %s" % destination)
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
                self.server.sip_logger.debug("Send to: %s:%d ([%d] bytes):\n\n%s" % (claddr[0], claddr[1], len(text),text))
            else:
                self.sendResponse("404 Not found")
        else:
            self.sendResponse("500 Server Internal Error")
    
    @is_redirect
    def processCode(self):
        main_logger.info("Code received: %s" % self.data[0])
        origin = self.getOrigin()
        if len(origin) > 0:
            main_logger.debug("Code: origin %s" % origin)
            if registrar.has_key(origin):
                socket,claddr = self.getSocketInfo(origin)
                data = self.removeRouteHeader()
                main_logger.debug("Code received: %s" % self.data[0])
                data = self.removeTopVia()
                text = string.join(data,"\r\n")
                socket.sendto(text,claddr)
                #showtime()
                #sip_logger.info("<<< %s" % data[0])
                #sip_logger.debug("---\n<< server send [%d]:\n%s\n---" % (len(text),text))
                self.server.sip_logger.debug("Send to: %s:%d ([%d] bytes):\n\n%s" % (claddr[0], claddr[1], len(text),text))
                
                
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
                self.processNonInvite()
                #self.sendResponse("200 0K")
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
            self.server.sip_logger.debug("Received from %s:%d (%d bytes):\n\n%s" %  (self.client_address[0], self.client_address[1], len(data), data))
            #sip_logger.debug("Received from %s:%d" % self.client_address)
            self.processRequest()
        else:
            if len(data) > 4:
                #showtime()
                self.server.sip_logger.warning("Received from %s:%d (%d bytes):\n\n" %  (self.client_address[0], self.client_address[1], len(data)))
                hexdump(data,' ',16)

class MainApplication:
    
    def __init__(self, root, options, server=None):
        self.root = root
        # bring in fron hack
        self.root.lift()
        self.root.call('wm', 'attributes', '.', '-topmost', True)
        self.root.after_idle(self.root.call, 'wm', 'attributes', '.', '-topmost', False)
        
        self.server = server
        self.options = options
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        self.notebook = Notebook(self.root)

        # Main Tab with 2 rows: firts with settings, second with registrar data
        self.main_frame = Frame(self.notebook)
        self.main_frame.columnconfigure(0, weight=1)
        # Settings row doesn't expands
        self.main_frame.rowconfigure(0, weight=0)
        # Registrar row will grow
        self.main_frame.rowconfigure(1, weight=1)
        
        # SIP Trace tab with 2 rows: first with controls, second with SIP trace
        self.sip_frame = Frame(self.notebook)
        self.sip_frame.columnconfigure(0, weight=1)
        # first row doesn't expoands
        self.sip_frame.rowconfigure(0, weight=0)
        # let the second row grow
        self.sip_frame.rowconfigure(1, weight=1)

        # Logs tab with 2 rows: first with controls, second with Logs
        self.log_frame = Frame(self.notebook)
        self.log_frame.columnconfigure(0, weight=1)
        # first row doesn't expoands
        self.log_frame.rowconfigure(0, weight=0)
        # let the second row grow
        self.log_frame.rowconfigure(1, weight=1)


        self.settings_frame = Frame(self.main_frame)
        self.settings_frame.grid(row=0, column=0, sticky=N, padx=5, pady=5)
        
        self.registrar_frame = Frame(self.main_frame)
        self.registrar_frame.rowconfigure(0, weight=1)

        self.sip_commands_frame = Frame(self.sip_frame)
        self.sip_commands_frame.grid(row=0, column=0, sticky=N, padx=4, pady=5)
        
        self.log_commands_frame = Frame(self.log_frame)
        self.log_commands_frame.grid(row=0, column=0, sticky=N, padx=4, pady=5)

        self.sip_trace_frame = Frame(self.sip_frame)
        self.sip_trace_frame.grid(row=1, column=0, sticky=NSEW)
        # let the SIP trace growing
        self.sip_trace_frame.columnconfigure(0, weight=1)
        self.sip_trace_frame.rowconfigure(0, weight=1)
        
        self.log_messages_frame = Frame(self.log_frame)
        self.log_messages_frame.grid(row=1, column=0, sticky=NSEW)
        # let the SIP trace growing
        self.log_messages_frame.columnconfigure(0, weight=1)
        self.log_messages_frame.rowconfigure(0, weight=1)


        #self.main_frame.rowconfigure(0, weight=1)
        #self.sip_frame.rowconfigure(0, weight=1)

        self.notebook.add(self.main_frame, text='Main', padding=0)
        self.notebook.add(self.sip_frame, text='SIP Trace', padding=0)
        self.notebook.add(self.log_frame, text='Log', padding=0)
        self.notebook.grid(row=0, column=0, sticky=NSEW)       

        self.sip_trace = ScrolledText(self.sip_trace_frame)
        self.sip_trace.grid(row=0, column=0, sticky=NSEW)
        
        self.log_messages = ScrolledText(self.log_messages_frame)
        self.log_messages.grid(row=0, column=0, sticky=NSEW)

        setup_logger('sip_widget_logger', log_file=None, level=logging.DEBUG, str_format='%(asctime)s %(message)s', widget=WidgetSipLogger(self.sip_trace))
        self.sip_trace_logger = logging.getLogger('sip_widget_logger')
        sip_logger = self.sip_trace_logger 
        
        #setup_logger('main_logger', options.logfile, level)
        #self.main_logger = logging.getLogger('main_logger')
        setup_logger('main_logger', options.logfile, level, widget=WidgetLogger(self.log_messages))
        #main_logger.addHandler(WidgetLogger(self.log_messages))

        row = 0
        self.gui_debug = BooleanVar()
        self.gui_debug.set(self.options.debug)
        Label(self.settings_frame, text="Debug:").grid(row=row, column=0, sticky=W)
        Checkbutton(self.settings_frame, variable=self.gui_debug, command=self.gui_debug_action).grid(row=row, column=1, sticky=W)
        row = row + 1

        self.gui_redirect = BooleanVar()
        self.gui_redirect.set(self.options.redirect)
        Label(self.settings_frame, text="Redirect server:").grid(row=row, column=0, sticky=W)
        Checkbutton(self.settings_frame, variable=self.gui_redirect, command=self.gui_redirect_action).grid(row=row, column=1, sticky=W)
        row = row + 1
        
        self.gui_ip_address = StringVar()
        self.gui_ip_address.set(self.options.ip_address)
        Label(self.settings_frame, text="IP Address:").grid(row=row, column=0, sticky=W)
        Entry(self.settings_frame, textvariable=self.gui_ip_address, width=15).grid(row=row, column=1, sticky=W)
        row = row + 1
   
        self.gui_port = IntVar()
        self.gui_port.set(self.options.port)
        Label(self.settings_frame, text="Port:").grid(row=row, column=0, sticky=W)
        Entry(self.settings_frame, textvariable=self.gui_port, width=5).grid(row=row, column=1, sticky=W)
        row = row + 1
 
        self.gui_password = StringVar()
        self.gui_password.set(self.options.password)
        Label(self.settings_frame, text="Password:").grid(row=row, column=0, sticky=W)
        Entry(self.settings_frame, textvariable=self.gui_password, width=15).grid(row=row, column=1, sticky=W)
        row = row + 1
 
        self.control_button = Button(self.settings_frame, text="Run", command=self.run_server)
        self.control_button.grid(row=row, column=0, sticky=N)
        self.registrar_button = Button(self.settings_frame, text="Reload registered", command=self.load_registrar)
        self.registrar_button.grid(row=row, column=1, sticky=N)
        row = row + 1
        
        self.registrar_frame.grid(row=1, column=0, sticky=NS)
        
        self.registrar_text = ScrolledText(self.registrar_frame)
        self.registrar_text.grid(row=0, column=0, sticky=NS)
        self.registrar_text.config(state='disabled') 
        
        # SIP Trace frame
        row = 0
        self.sip_trace_clear_button = Button(self.sip_commands_frame, text="Clear", command=self.clear_sip_trace)
        self.sip_trace_clear_button.grid(row=row, column=0, sticky=N)
        row = row + 1
        
        # Log Messages frame
        row = 0
        self.log_messages_clear_button = Button(self.log_commands_frame, text="Clear", command=self.clear_log_messages)
        self.log_messages_clear_button.grid(row=row, column=0, sticky=N)
        row = row + 1
    

        #self.load_registrar(self.registrar)

        self.notebook.grid(row=0, sticky=NSEW)
        self.root.wm_protocol("WM_DELETE_WINDOW", self.cleanup_on_exit)
    
    def gui_debug_action(self):
        if self.gui_debug.get():
            main_logger.debug("Activating Debug")
            main_logger.setLevel(logging.DEBUG)
        else:
            main_logger.debug("Deactivating Debug")
            main_logger.setLevel(logging.INFO)
        self.options.debug = self.gui_debug.get()

    def gui_redirect_action(self):
        if self.gui_redirect.get():
            main_logger.debug("Activating Redirect server")
        else:
            main_logger.debug("Deactivating Redirect Server")
        self.options.redirect = self.gui_redirect.get()


    def cleanup_on_exit(self):
        self.root.quit() 
    
    def clear_log_messages(self):
        self.log_messages.config(state='normal')
        self.log_messages.delete(0.0, END)
        self.log_messages.config(state='disabled')

    def clear_sip_trace(self):
        self.sip_trace.config(state='normal')
        self.sip_trace.delete(0.0, END)
        self.sip_trace.config(state='disabled')

    def load_registrar(self):
        self.registrar_text.config(state='normal')
        self.registrar_text.delete(0.0,END)
        if len(registrar) > 0:

            for regname in registrar:
                self.registrar_text.insert(END, "\n%s:\n" % regname)
                self.registrar_text.insert(END, "\t Contact: %s\n" % registrar[regname][0])
                self.registrar_text.insert(END, "\t IP: %s:%s\n" % (registrar[regname][2][0], registrar[regname][2][1]) )
                self.registrar_text.insert(END, "\t Expires: %d\n" % registrar[regname][3])
        else:
            self.registrar_text.insert(END, "No User Agent registered yet\n")
            
        self.registrar_text.see(END)
        self.registrar_text.config(state='disabled')

    def run_server(self):
        global recordroute
        global topvia
        main_logger.debug("Starting thread")
        self.options.ip_address = self.gui_ip_address.get()
        self.options.port = self.gui_port.get()
        self.options.password = self.gui_password.get()
        main_logger.info(time.strftime("Starting proxy at %a, %d %b %Y %H:%M:%S ", time.localtime()))
        recordroute = "Record-Route: <sip:%s:%d;lr>" % (self.options.ip_address, self.options.port)
        topvia = "Via: SIP/2.0/UDP %s:%d" % (self.options.ip_address, self.options.port)
    
        if options.redirect:
            main_logger.debug("Working in redirect server mode")
        else:
            main_logger.debug("Using the Record-Route header: %s" % recordroute) 
        main_logger.debug("Using the top Via header: %s" % topvia) 
        main_logger.debug("Writing SIP messages in %s log file" % self.options.sip_logfile)
        main_logger.debug("Authentication password: %s" % self.options.password)
        main_logger.debug("Logfile: %s" % self.options.logfile)
 
        try:
            self.server = SipTracedUDPServer((self.options.ip_address, self.options.port), UDPHandler, self.sip_trace_logger)
            self.server_thread = threading.Thread(name='sip', target=self.server.serve_forever)
            self.server_thread.daemon = True
            self.server_thread.start()
            self.control_button.configure(text="Stop", command=self.stop_server)
        except Exception, e:
            main_logger.error("Cannot start the server: %s" % e)
            raise e
        
    def stop_server(self):
        main_logger.debug("Stopping thread")
        self.server.shutdown()
        self.server.socket.close()
        main_logger.debug("Stopped thread")
        self.control_button.configure(text="Run", command=self.run_server)

if __name__ == "__main__": 
    usage = """%prog [OPTIONS]"""
    
    opt = optparse.OptionParser(usage=usage)
    
    opt.add_option('-t', dest='terminal', default=False, action='store_true',
            help='Run in terminal mode (no GUI)')
    opt.add_option('-d', dest='debug', default=False, action='store_true',
            help='Run in debug mode')
    opt.add_option('-r', dest='redirect', default=False, action='store_true',
            help='Act as a redirect server')
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
    
    if options.redirect:
        main_logger.debug("Working in redirect server mode")
    else:
        main_logger.debug("Using the Record-Route header: %s" % recordroute) 
    main_logger.debug("Using the top Via header: %s" % topvia) 
    main_logger.debug("Writing SIP messages in %s log file" % options.sip_logfile)
    main_logger.debug("Authentication password: %s" % options.password)
    main_logger.debug("Logfile: %s" % options.logfile)
    
    if not options.terminal:
        from Tkinter import *
        from ttk import *
        from ScrolledText import *

        root = Tk()
        app = MainApplication(root, options)
        root.title(sys.argv[0])
        root.mainloop()
    else:
        try:
            server = SipTracedUDPServer((options.ip_address, options.port), UDPHandler, sip_logger)
        except Exception, e:
            main_logger.error("Cannot start the server: %s" % e)
            raise e
        try:
            main_logger.info("Starting serving SIP requests on %s:%d, press CTRL-C for exit." % (options.ip_address, options.port))
            server.serve_forever()
        except KeyboardInterrupt:
            main_logger.info("Exiting.") 
