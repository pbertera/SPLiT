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
import sys

import gui
import utils
import proxy

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
        try:
            sip_proxy = proxy.SipTracedUDPServer((options.ip_address, options.sip_port), proxy.UDPHandler, sip_logger, main_logger, options)
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
            sip_proxy.serve_forever()
        except KeyboardInterrupt:
            main_logger.info("Exiting.") 
