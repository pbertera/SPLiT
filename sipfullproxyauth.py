
#    Copyright 2014 Philippe THIRION
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import SocketServer
import re
import string
import socket
#import threading
import sys
import time
import hashlib
import random
import logging

HOST, PORT = '0.0.0.0', 5060
PASSWORD = "protected"
DEF_EXPIRES = 3600

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
rx_invalid = re.compile("^192\.168")
rx_invalid2 = re.compile("^10\.")
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

def hexdump( chars, sep, width ):
    while chars:
        line = chars[:width]
        chars = chars[width:]
        line = line.ljust( width, '\000' )
        logging.debug("%s%s%s" % ( sep.join( "%02x" % ord(c) for c in line ),sep, quotechars( line )))

def quotechars( chars ):
	return ''.join( ['.', c][c.isalnum()] for c in chars )

def showtime():
    logging.debug(time.strftime("(%H:%M:%S)", time.localtime()))
    
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
        logging.warning("Incorrect nonce")
        return False
    a1="%s:%s:%s" % (hash["username"],hash["realm"],password)
    a2="REGISTER:%s" % hash["uri"]
    ha1 = hashlib.md5(a1).hexdigest()
    ha2 = hashlib.md5(a2).hexdigest()
    b = "%s:%s:%s" % (ha1,nonce,ha2)
    expected = hashlib.md5(b).hexdigest()
    if expected == hash["response"]:
        logging.debug("Authentication succeeded")
        return True
    logging.warning("expected= %s" % expected)
    logging.warning("response= %s" % hash["response"])
    return False

class UDPHandler(SocketServer.BaseRequestHandler):   
    
    def debugRegister(self):
        logging.debug("*** REGISTRAR ***")
        logging.debug("*****************")
        for key in registrar.keys():
            logging.debug("%s -> %s" % (key,registrar[key][0]))
        logging.debug("*****************")
    
    def changeRequestUri(self):
        # change request uri
        md = rx_request_uri.search(self.data[0])
        if md:
            method = md.group(1)
            uri = md.group(2)
            if registrar.has_key(uri):
                uri = "sip:%s" % registrar[uri][0]
                self.data[0] = "%s %s SIP/2.0" % (method,uri)
            else:
                logging.debug("URI not found in Registrar: %s" % uri)
                logging.debug("Registrar: %s" % registrar)

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
            logging.warning("registration for %s has expired" % uri)
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
        showtime()
        logging.info("<<< %s" % data[0])
        logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text),text))
        
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
                    contact = md.group(2)
                else:
                    md = rx_addr.search(line)
                    if md:
                        contact = md.group(1)
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

        if rx_invalid.search(contact) or rx_invalid2.search(contact):
            if registrar.has_key(fromm):
                del registrar[fromm]
            self.sendResponse("488 Not Acceptable Here")    
            return
            
        # remove Authorization header for response
        if auth_index > 0:
            self.data.pop(auth_index)
           
                
        if len(authorization)> 0 and auth.has_key(fromm):
            nonce = auth[fromm]
            if not checkAuthorization(authorization,PASSWORD,nonce):
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
            expires = DEF_EXPIRES
            header = "Expires: %s" % expires
            self.data.insert(6, header)
        
        if expires != 0:
            now = int(time.time())
            validity = now + expires
            
    
        logging.info("From: %s - Contact: %s" % (fromm,contact))
        logging.debug("Client address: %s:%s" % self.client_address)
        logging.debug("Expires= %d" % expires)
        registrar[fromm]=[contact,self.socket,self.client_address,validity]
        self.debugRegister()
        self.sendResponse("200 0K")
        
    def processInvite(self):
        logging.debug("-----------------")
        logging.debug(" INVITE received ")
        logging.debug("-----------------")
        origin = self.getOrigin()
        if len(origin) == 0 or not registrar.has_key(origin):
            logging.debug("Origin not found: %s" % origin)
            self.sendResponse("400 Bad Request")
            return
        destination = self.getDestination(with_params=True)
        if len(destination) > 0:
            logging.info("destination %s" % destination)
            if registrar.has_key(destination) and self.checkValidity(destination):
                socket,claddr = self.getSocketInfo(destination)
                self.changeRequestUri()
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                #insert Record-Route
                data.insert(1,recordroute)
                text = string.join(data,"\r\n")
                socket.sendto(text , claddr)
                showtime()
                logging.info("<<< %s" % data[0])
                logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text),text))
            else:
                self.sendResponse("480 Temporarily Unavailable")
        else:
            self.sendResponse("500 Server Internal Error")
                
    def processAck(self):
        logging.debug("--------------")
        logging.debug(" ACK received ")
        logging.debug("--------------")
        destination = self.getDestination()
        if len(destination) > 0:
            logging.info("destination %s" % destination)
            if registrar.has_key(destination):
                socket,claddr = self.getSocketInfo(destination)
                #self.changeRequestUri()
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                #insert Record-Route
                data.insert(1,recordroute)
                text = string.join(data,"\r\n")
                socket.sendto(text,claddr)
                showtime()
                logging.info("<<< %s" % data[0])
                logging.debug( "---\n<< server send [%d]:\n%s\n---" % (len(text),text))
                
    def processNonInvite(self):
        logging.debug("----------------------")
        logging.debug(" NonInvite received   ")
        logging.debug("----------------------")
        origin = self.getOrigin()
        if len(origin) == 0 or not registrar.has_key(origin):
            logging.debug("Origin not found: %s" % origin)
            self.sendResponse("400 Bad Request")
            return
        destination = self.getDestination()
        if len(destination) > 0:
            logging.info("destination %s" % destination)
            if registrar.has_key(destination) and self.checkValidity(destination):
                socket,claddr = self.getSocketInfo(destination)
                #self.changeRequestUri()
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                #insert Record-Route
                data.insert(1,recordroute)
                text = string.join(data,"\r\n")
                socket.sendto(text , claddr)
                showtime()
                logging.info("<<< %s" % data[0])
                logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text),text))    
            else:
                self.sendResponse("406 Not Acceptable")
        else:
            self.sendResponse("500 Server Internal Error")
    
    def processCode(self):
        origin = self.getOrigin()
        if len(origin) > 0:
            logging.debug("origin %s" % origin)
            if registrar.has_key(origin):
                socket,claddr = self.getSocketInfo(origin)
                self.data = self.removeRouteHeader()
                data = self.removeTopVia()
                text = string.join(data,"\r\n")
                socket.sendto(text,claddr)
                showtime()
                logging.info("<<< %s" % data[0])
                logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text),text))
                
                
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
                logging.error("request_uri %s" % request_uri)          
                #print "message %s unknown" % self.data
    
    def handle(self):
        #socket.setdefaulttimeout(120)
        data = self.request[0]
        self.data = data.split("\r\n")
        self.socket = self.request[1]
        request_uri = self.data[0]
        if rx_request_uri.search(request_uri) or rx_code.search(request_uri):
            showtime()
            logging.info(">>> %s" % request_uri)
            logging.debug("---\n>> server received [%d]:\n%s\n---" %  (len(data),data))
            logging.debug("Received from %s:%d" % self.client_address)
            self.processRequest()
        else:
            if len(data) > 4:
                showtime()
                logging.warning("---\n>> server received [%d]:" % len(data))
                hexdump(data,' ',16)
                logging.warning("---")

if __name__ == "__main__": 
    logging.basicConfig(format='%(asctime)s:%(levelname)s:%(message)s',filename='proxy.log',level=logging.DEBUG,datefmt='%H:%M:%S')
    logging.info(time.strftime("%a, %d %b %Y %H:%M:%S ", time.localtime()))
    hostname = socket.gethostname()
    logging.info(hostname)
    ipaddress = socket.gethostbyname(hostname)
    if ipaddress == "127.0.0.1":
        ipaddress = sys.argv[1]
    logging.info(ipaddress)
    recordroute = "Record-Route: <sip:%s:%d;lr>" % (ipaddress,PORT)
    topvia = "Via: SIP/2.0/UDP %s:%d" % (ipaddress,PORT)
    server = SocketServer.UDPServer((HOST, PORT), UDPHandler)
    server.serve_forever()
