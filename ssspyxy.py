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

import optparse
import threading
import sys
import time

import gui
import utils
import proxy

from pypxe import tftp #PyPXE TFTP service
from pypxe import dhcp #PyPXE DHCP service
from pypxe import http #PyPXE HTTP service

if __name__ == "__main__": 
    usage = """%prog [OPTIONS]"""
    
    opt = optparse.OptionParser(usage=usage)
    
    opt.add_option('-t', dest='terminal', default=False, action='store_true',
            help='Run in terminal mode (no GUI)')
    opt.add_option('-d', dest='debug', default=False, action='store_true',
            help='Run in debug mode')
    opt.add_option('-i', dest='ip_address', type='string', default="127.0.0.1",
            help='Specify ip address to bind on (default: 127.0.0.1)')
    opt.add_option('-l', dest='logfile', type='string', default=None,
            help='Specify the log file (default: log to stdout)')
    
    opt.add_option('--sip-redirect', dest='sip_redirect', default=False, action='store_true',
            help='Act as a redirect server')
    opt.add_option('--sip-port', dest='sip_port', type='int', default=5060,
            help='Specify the UDP port (default: 5060)')
    opt.add_option('--sip-log', dest='sip_logfile', type='string', default=None,
            help='Specify the SIP messages log file (default: log to stdout)')
    opt.add_option('--sip-expires', dest='sip_expires', type='int', default=3600,
            help='Default registration expires (default: 3600)')
    opt.add_option('--sip-password', dest='sip_password', type='string', default='protected',
            help='Athentication password (default: protected)')
    
    opt.add_option('--tftp', dest='tftp', default=False, action='store_true',
            help='Enable the TFTP server')
    opt.add_option('--tftp-root', dest='tftp_root', type='string', default='tftp', action='store',
            help='TFTP server root directory (default: tftp)')
    opt.add_option('--tftp-port', dest='tftp_port', type='int', default=69, action='store',
            help='TFTP server port (default: 69)')
    
    opt.add_option('--http', dest='http', default=False, action='store_true',
            help='Enable the HTTP server')
    opt.add_option('--http-root', dest='http_root', default='http', action='store',
            help='HTTP server root directory (default: http)')
    opt.add_option('--http-port', dest='http_port', default=80, action='store',
            help='HTTP server port (default: 80)')

    opt.add_option('--dhcp', dest='dhcp', default=False, action='store_true',
            help='Enable the DHCP server')
    opt.add_option('--dhcp-begin', dest='dhcp_begin', default=None, action='store',
            help='DHCP lease range start')
    opt.add_option('--dhcp-end', dest='dhcp_end', default=None, action='store',
            help='DHCP lease range end')
    opt.add_option('--dhcp-subnet', dest='dhcp_subnet', default=None, action='store',
            help='DHCP lease subnet')
    opt.add_option('--dhcp-gateway', dest='dhcp_gateway', default=None, action='store',
            help='DHCP lease gateway')
    opt.add_option('--dhcp-dns', dest='dhcp_dns', default=None, action='store',
            help='DHCP lease DNS')
    opt.add_option('--dhcp-bcast', dest='dhcp_bcast', default=None, action='store',
            help='DHCP lease broadcast')
    opt.add_option('--dhcp-fileserver', dest='dhcp_fileserver', default=None, action='store',
            help='DHCP lease fileserver IP (option 66)')
    opt.add_option('--dhcp-filename', dest='dhcp_filename', default='', action='store',
            help='DHCP lease filename (option 67)')


    options, args = opt.parse_args(sys.argv[1:])

    main_logger = utils.setup_logger('main_logger', options.logfile, options.debug)
    sip_logger = utils.setup_logger('sip_logger', options.sip_logfile, options.debug, str_format='%(asctime)s %(message)s')    
    
    main_logger.info("Starting application")
    
    main_logger.debug("SIP: Writing SIP messages in %s log file" % options.sip_logfile)
    main_logger.debug("SIP: Authentication password: %s" % options.sip_password)
    main_logger.debug("Logfile: %s" % options.logfile)
    
    if not options.terminal:
        import Tkinter as tk

        root = tk.Tk()
        app = gui.MainApplication(root, options, main_logger)
        root.title(sys.argv[0])
        try:
            root.mainloop()
        except KeyboardInterrupt:
            main_logger.info("Exiting.") 
    else:
        running_services = []
        try:
            sip_proxy = proxy.SipTracedUDPServer((options.ip_address, options.sip_port), proxy.UDPHandler, sip_logger, main_logger, options)
            sip_proxy_thread = threading.Thread(name='sip', target=sip_proxy.serve_forever)
            sip_proxy_thread.daemon = True
        except Exception, e:
            main_logger.error("SIP: Cannot start the proxy: %s" % e)
            raise e
        try:
            if options.sip_redirect:
                main_logger.debug("SIP: Working in redirect server mode")
            else:
                main_logger.debug("SIP: Using the Record-Route header: %s" % sip_proxy.recordroute) 
                main_logger.debug("SIP: Using the top Via header: %s" % sip_proxy.topvia) 
        
            main_logger.info("SIP: Starting serving SIP requests on %s:%d, press CTRL-C for exit." % (options.ip_address, options.sip_port))
            sip_proxy_thread.start()
            running_services.append(sip_proxy_thread)
            
            if options.tftp:
                main_logger.info("TFTP: Starting server thread")
                tftp_server = tftp.TFTPD(ip = options.ip_address, mode_debug = options.debug, logger = main_logger, netbootDirectory = options.tftp_root)
                tftp_server_thread = threading.Thread(name='tftp', target=tftp_server.listen)
                tftp_server_thread.daemon = True
                tftp_server_thread.start()
                running_services.append(tftp_server_thread)
            
            if options.http:
                main_logger.info("HTTP: Starting server thread")
                http_server = http.HTTPD(ip = options.ip_address, mode_debug = options.debug, logger = main_logger, netbootDirectory = options.http_root)
                http_server_thread = threading.Thread(name='http', target=http_server.listen)
                http_server_thread.daemon = True
                http_server_thread.start()
                running_services.append(http_server_thread)
            
            if options.dhcp:
                main_logger.info("DHCP: Starting server thread")
                dhcp_server = dhcp.DHCPD(ip = options.ip_address, mode_debug = options.debug, logger = main_logger,
                        offerfrom = options.dhcp_begin,
                        offerto = options.dhcp_end,
                        subnet = options.dhcp_subnet,
                        router = options.dhcp_gateway,
                        dnsserver = options.dhcp_dns,
                        broadcast = options.dhcp_bcast,
                        fileserver = options.dhcp_fileserver,
                        filename = options.dhcp_filename)
                dhcp_server_thread = threading.Thread(name='dhcp', target=dhcp_server.listen)
                dhcp_server_thread.daemon = True
                dhcp_server_thread.start()
                running_services.append(dhcp_server_thread)

        except KeyboardInterrupt:
            main_logger.info("Exiting.")
        
        while map(lambda x: x.isAlive(), running_services):
            time.sleep(1)
