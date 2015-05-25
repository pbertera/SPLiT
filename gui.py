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


import Queue
import logging
import time
import threading
import Tkinter as tk
import ttk
from ScrolledText import ScrolledText

import utils
import proxy
import pnp
import http

from pypxe import tftp
from pypxe import dhcp

class QueueLogger(logging.Handler):
    def __init__(self, queue):
        logging.Handler.__init__(self)
        self.queue = queue

    def emit(self, record):
        record = self.adjust_record(self.format(record))
        self.queue.put(record)

class SipTraceQueueLogger(QueueLogger):
    def adjust_record(self, record):
        return record.replace("\r", "").rstrip('\n') + '\n\n'

class MessagesQueueLogger(QueueLogger):
    def adjust_record(self, record):
        return record + '\n'

class MainFrame:
    def __init__(self, root, options, main_logger):
        self.root = root
        self.options = options
        self.frame = tk.Frame(root)
        self.main_logger = main_logger
        self.sip_proxy = None
        self.tftp_server = None
        self.http_server = None

        # can enlarge
        self.frame.columnconfigure(0, weight=1)
        # first row: setting, cannot vertical enlarge:
        self.frame.rowconfigure(0, weight=0)
        # second row: registrar, can vertical enlarge:
        self.frame.rowconfigure(1, weight=1)
        
        # Settings control frame
        self.settings_frame = tk.LabelFrame(self.frame, text="Settings", padx=5, pady=5)
        self.settings_frame.grid(row=0, column=0, sticky=tk.N, padx=5, pady=5)
        
        # Registrar frame 
        #self.registrar_frame = tk.Frame(self.frame)
        #self.registrar_frame.rowconfigure(0, weight=1)

        row = 0
        tk.Label(self.settings_frame, text="General settings:", font = "-weight bold").grid(row=row, column=0, sticky=tk.W)
        row = row + 1
        
        self.gui_debug = tk.BooleanVar()
        self.gui_debug.set(self.options.debug)
        tk.Label(self.settings_frame, text="Debug:").grid(row=row, column=0, sticky=tk.W)
        tk.Checkbutton(self.settings_frame, variable=self.gui_debug, command=self.gui_debug_action).grid(row=row, column=1, sticky=tk.W)
        #row = row + 1

        self.gui_sip_ip_address = tk.StringVar()
        self.gui_sip_ip_address.set(self.options.ip_address)
        tk.Label(self.settings_frame, text="IP Address:").grid(row=row, column=2, sticky=tk.W)
        tk.Entry(self.settings_frame, textvariable=self.gui_sip_ip_address, width=15).grid(row=row, column=3, sticky=tk.W)
        row = row + 1
       
        tk.Label(self.settings_frame, text="TFTP Server:", font = "-weight bold").grid(row=row, column=0, sticky=tk.W)
        row = row + 1

        self.gui_tftp_port = tk.IntVar()
        self.gui_tftp_port.set(self.options.tftp_port)
        tk.Label(self.settings_frame, text="TFTP Port:").grid(row=row, column=0, sticky=tk.W)
        tk.Entry(self.settings_frame, textvariable=self.gui_tftp_port, width=5).grid(row=row, column=1, sticky=tk.W)
        #row = row + 1
        
        self.gui_tftp_root = tk.StringVar()
        self.gui_tftp_root.set(self.options.tftp_root)
        tk.Label(self.settings_frame, text="TFTP Directory:").grid(row=row, column=2, sticky=tk.W)
        tk.Entry(self.settings_frame, textvariable=self.gui_tftp_root, width=15).grid(row=row, column=3, sticky=tk.W)
        row = row + 1


        tk.Label(self.settings_frame, text="HTTP Server:", font = "-weight bold").grid(row=row, column=0, sticky=tk.W)
        row = row + 1
        
        self.gui_http_port = tk.IntVar()
        self.gui_http_port.set(self.options.http_port)
        tk.Label(self.settings_frame, text="HTTP Port:").grid(row=row, column=0, sticky=tk.W)
        tk.Entry(self.settings_frame, textvariable=self.gui_http_port, width=5).grid(row=row, column=1, sticky=tk.W)
        #row = row + 1
        
        self.gui_http_root = tk.StringVar()
        self.gui_http_root.set(self.options.http_root)
        tk.Label(self.settings_frame, text="HTTP Directory:").grid(row=row, column=2, sticky=tk.W)
        tk.Entry(self.settings_frame, textvariable=self.gui_http_root, width=15).grid(row=row, column=3, sticky=tk.W)
        row = row + 1

        
        tk.Label(self.settings_frame, text="DHCP Server:", font = "-weight bold").grid(row=row, column=0, sticky=tk.W)
        row = row + 1
        
        self.gui_dhcp_begin = tk.StringVar()
        self.gui_dhcp_begin.set(self.options.dhcp_begin)
        tk.Label(self.settings_frame, text="DHCP Pool start:").grid(row=row, column=0, sticky=tk.W)
        tk.Entry(self.settings_frame, textvariable=self.gui_dhcp_begin, width=15).grid(row=row, column=1, sticky=tk.W)
        #row = row + 1
        
        self.gui_dhcp_end = tk.StringVar()
        self.gui_dhcp_end.set(self.options.dhcp_end)
        tk.Label(self.settings_frame, text="DHCP Pool end:").grid(row=row, column=2, sticky=tk.W)
        tk.Entry(self.settings_frame, textvariable=self.gui_dhcp_end, width=15).grid(row=row, column=3, sticky=tk.W)
        row = row + 1

        self.gui_dhcp_subnetmask = tk.StringVar()
        self.gui_dhcp_subnetmask.set(self.options.dhcp_subnetmask)
        tk.Label(self.settings_frame, text="DHCP Subnet mask:").grid(row=row, column=0, sticky=tk.W)
        tk.Entry(self.settings_frame, textvariable=self.gui_dhcp_subnetmask, width=15).grid(row=row, column=1, sticky=tk.W)
        #row = row + 1

        self.gui_dhcp_gateway = tk.StringVar()
        self.gui_dhcp_gateway.set(self.options.dhcp_gateway)
        tk.Label(self.settings_frame, text="DHCP Gateway:").grid(row=row, column=2, sticky=tk.W)
        tk.Entry(self.settings_frame, textvariable=self.gui_dhcp_gateway, width=15).grid(row=row, column=3, sticky=tk.W)
        row = row + 1

        self.gui_dhcp_bcast = tk.StringVar()
        self.gui_dhcp_bcast.set(self.options.dhcp_bcast)
        tk.Label(self.settings_frame, text="DHCP Broadcast:").grid(row=row, column=0, sticky=tk.W)
        tk.Entry(self.settings_frame, textvariable=self.gui_dhcp_bcast, width=15).grid(row=row, column=1, sticky=tk.W)
        #row = row + 1

        self.gui_dhcp_dns = tk.StringVar()
        self.gui_dhcp_dns.set(self.options.dhcp_dns)
        tk.Label(self.settings_frame, text="DHCP DNS:").grid(row=row, column=2, sticky=tk.W)
        tk.Entry(self.settings_frame, textvariable=self.gui_dhcp_dns, width=15).grid(row=row, column=3, sticky=tk.W)
        row = row + 1

        self.gui_dhcp_fileserver = tk.StringVar()
        self.gui_dhcp_fileserver.set(self.options.dhcp_fileserver)
        tk.Label(self.settings_frame, text="DHCP Fileserver (opt. 66):").grid(row=row, column=0, sticky=tk.W)
        tk.Entry(self.settings_frame, textvariable=self.gui_dhcp_fileserver, width=25).grid(row=row, column=1, sticky=tk.W)
        #row = row + 1

        self.gui_dhcp_filename = tk.StringVar()
        self.gui_dhcp_filename.set(self.options.dhcp_filename)
        tk.Label(self.settings_frame, text="DHCP Filename (opt. 67):").grid(row=row, column=2, sticky=tk.W)
        tk.Entry(self.settings_frame, textvariable=self.gui_dhcp_filename, width=25).grid(row=row, column=3, sticky=tk.W)
        row = row + 1

        tk.Label(self.settings_frame, text="SIP Plug&Play:", font = "-weight bold").grid(row=row, column=0, sticky=tk.W)
        row = row + 1
        
        self.gui_pnp_uri = tk.StringVar()
        self.gui_pnp_uri.set(self.options.pnp_uri)
        tk.Label(self.settings_frame, text="PnP URI:").grid(row=row, column=0, sticky=tk.W)
        tk.Entry(self.settings_frame, textvariable=self.gui_pnp_uri, width=60).grid(row=row, column=1, columnspan=3, sticky=tk.W)
        row = row + 1
        
        tk.Label(self.settings_frame, text="SIP Proxy:", font = "-weight bold").grid(row=row, column=0, sticky=tk.W)
        row = row + 1
        
        self.gui_sip_redirect = tk.BooleanVar()
        self.gui_sip_redirect.set(self.options.sip_redirect)
        tk.Label(self.settings_frame, text="SIP Redirect server:").grid(row=row, column=0, sticky=tk.W)
        tk.Checkbutton(self.settings_frame, variable=self.gui_sip_redirect, command=self.gui_sip_redirect_action).grid(row=row, column=1, sticky=tk.W)
        #row = row + 1
        
        self.gui_sip_port = tk.IntVar()
        self.gui_sip_port.set(self.options.sip_port)
        tk.Label(self.settings_frame, text="SIP Port:").grid(row=row, column=2, sticky=tk.W)
        tk.Entry(self.settings_frame, textvariable=self.gui_sip_port, width=5).grid(row=row, column=3, sticky=tk.W)
        row = row + 1
 
        self.gui_sip_password = tk.StringVar()
        self.gui_sip_password.set(self.options.sip_password)
        tk.Label(self.settings_frame, text="Password:").grid(row=row, column=0, sticky=tk.W)
        tk.Entry(self.settings_frame, textvariable=self.gui_sip_password, width=15).grid(row=row, column=1, sticky=tk.W)
        row = row + 1
 
        self.sip_control_button = tk.Button(self.settings_frame, text="Start SIP Proxy", command=self.start_sip_proxy)
        self.sip_control_button.grid(row=row, column=0, sticky=tk.N)
        
        self.tftp_control_button = tk.Button(self.settings_frame, text="Start TFTP Server", command=self.start_tftp_server)
        self.tftp_control_button.grid(row=row, column=1, sticky=tk.N)
        
        self.http_control_button = tk.Button(self.settings_frame, text="Start HTTP Server", command=self.start_http_server)
        self.http_control_button.grid(row=row, column=2, sticky=tk.N)
        
        self.dhcp_control_button = tk.Button(self.settings_frame, text="Start DHCP Server", command=self.start_dhcp_server)
        self.dhcp_control_button.grid(row=row, column=3, sticky=tk.N)
        
        self.pnp_control_button = tk.Button(self.settings_frame, text="Start PnP Server", command=self.start_pnp_server)
        self.pnp_control_button.grid(row=row, column=4, sticky=tk.N)
        
        #self.registrar_button = tk.Button(self.settings_frame, text="Reload registered", command=self.load_registrar)
        #self.registrar_button.grid(row=row, column=4, sticky=tk.N)
        #row = row + 1
        
        #self.registrar_frame.grid(row=1, column=0, sticky=tk.NS)
        
        #self.registrar_text = ScrolledText(self.registrar_frame)
        #self.registrar_text.grid(row=0, column=0, sticky=tk.NS)
        #self.registrar_text.config(state='disabled') 
    
        self.sip_queue = Queue.Queue()
        self.sip_trace_logger = utils.setup_logger('sip_widget_logger', log_file=None, debug=True, str_format='%(asctime)s %(message)s', handler=SipTraceQueueLogger(queue=self.sip_queue))
    
        self.log_queue = Queue.Queue()
        utils.setup_logger('main_logger', options.logfile, self.options.debug, handler=MessagesQueueLogger(queue=self.log_queue))
    
    def get_frame(self): 
        return self.frame

    def get_sip_queue(self):
        return self.sip_queue
    
    def get_log_queue(self):
        return self.log_queue

    def load_registrar(self):
        self.registrar_text.config(state='normal')
        self.registrar_text.delete(0.0, tk.END)
        
        if self.sip_proxy == None:
            self.registrar_text.insert(tk.END, "Server not running\n")
            self.registrar_text.see(tk.END)
            self.registrar_text.config(state='disabled')
            return

        if len(self.sip_proxy.registrar) > 0:
            for regname in self.sip_proxy.registrar:
                self.registrar_text.insert(tk.END, "\n%s:\n" % regname)
                self.registrar_text.insert(tk.END, "\t Contact: %s\n" % self.sip_proxy.registrar[regname][0])
                self.registrar_text.insert(tk.END, "\t IP: %s:%s\n" % (self.sip_proxy.registrar[regname][2][0], self.sip_proxy.registrar[regname][2][1]) )
                self.registrar_text.insert(tk.END, "\t Expires: %s\n" % time.ctime(self.sip_proxy.registrar[regname][3]))
        else:
            self.registrar_text.insert(tk.END, "No User Agent registered yet\n")
            
        self.registrar_text.see(tk.END)
        self.registrar_text.config(state='disabled')

    def start_sip_proxy(self):
        self.main_logger.debug("SIP Proxy: Starting thread")
        self.options.ip_address = self.gui_sip_ip_address.get()
        self.options.sip_port = self.gui_sip_port.get()
        self.options.sip_password = self.gui_sip_password.get()
        self.options.sip_redirect = self.gui_sip_redirect.get()
    
        self.main_logger.debug("Writing SIP messages in %s log file" % self.options.sip_logfile)
        self.main_logger.debug("Authentication password: %s" % self.options.sip_password)
        self.main_logger.debug("Logfile: %s" % self.options.logfile)
 
        try:
            self.sip_proxy = proxy.SipTracedUDPServer((self.options.ip_address, self.options.sip_port), proxy.UDPHandler, self.sip_trace_logger, self.main_logger, self.options)
            self.sip_server_thread = threading.Thread(name='sip', target=self.sip_proxy.serve_forever)
            self.sip_server_thread.daemon = True
            self.sip_server_thread.start()
            self.sip_control_button.configure(text="Stop SIP Proxy", command=self.stop_sip_proxy)
        except Exception, e:
            self.main_logger.error("Cannot start the server: %s" % e)
            raise e
        
        self.main_logger.debug("Using the top Via header: %s" % self.sip_proxy.topvia) 
        
        if self.options.sip_redirect:
            self.main_logger.debug("Working in redirect server mode")
        else:
            self.main_logger.debug("Using the Record-Route header: %s" % self.sip_proxy.recordroute) 
 
    def stop_sip_proxy(self):
        self.main_logger.debug("SIP: Stopping thread")
        self.sip_proxy.shutdown()
        self.sip_proxy.socket.close()
        self.sip_proxy = None
        self.main_logger.debug("SIP: Stopped thread")
        self.sip_control_button.configure(text="Start SIP Proxy", command=self.start_sip_proxy)
    
    def start_tftp_server(self):
        self.main_logger.debug("TFTP Server: Starting thread")
        self.options.ip_address = self.gui_sip_ip_address.get()
        self.options.tftp_port = self.gui_tftp_port.get()
        self.options.tftp_root = self.gui_tftp_root.get()
        
        self.main_logger.debug("TFTP Server port: %s", self.options.tftp_port)
        try:
            self.tftp_server = tftp.TFTPD(ip = self.options.ip_address, mode_debug = self.options.debug, logger = self.main_logger, netboot_directory = self.options.tftp_root)
            self.tftp_server_thread = threading.Thread(name='tftp', target=self.tftp_server.listen)
            self.tftp_server_thread.daemon = True
            self.tftp_server_thread.start()           
            self.tftp_control_button.configure(text="Stop TFTP Server", command=self.stop_tftp_server)
        except Exception, e:
            self.main_logger.error("Cannot start the server: %s", e)
            raise e

    def stop_tftp_server(self):
        self.main_logger.debug("TFTP: Stopping thread")
        self.tftp_server.shutdown()
        self.tftp_server = None
        self.main_logger.debug("TFTP: Stopped thread")
        self.tftp_control_button.configure(text="Start TFTP Server", command=self.start_tftp_server)

    def start_dhcp_server(self):
        self.main_logger.debug("DHCP Server: Starting thread")
        self.options.ip_address = self.gui_sip_ip_address.get()
        self.options.dhcp_begin = self.gui_dhcp_begin.get()
        self.options.dhcp_end = self.gui_dhcp_end.get()
        self.options.dhcp_gateway = self.gui_dhcp_gateway.get()
        self.options.dhcp_dns = self.gui_dhcp_dns.get()
        self.options.dhcp_subnetmask = self.gui_dhcp_subnetmask.get()
        self.options.dhcp_bcast = self.gui_dhcp_bcast.get()
        self.options.dhcp_fileserver = self.gui_dhcp_fileserver.get()
        self.options.dhcp_filename = self.gui_dhcp_filename.get()
        try:
            self.dhcp_server = dhcp.DHCPD(ip = self.options.ip_address, mode_debug = self.options.debug, logger = self.main_logger,
                        offerfrom = self.options.dhcp_begin,
                        offerto = self.options.dhcp_end,
                        subnetmask = self.options.dhcp_subnetmask,
                        router = self.options.dhcp_gateway,
                        dnsserver = self.options.dhcp_dns,
                        broadcast = self.options.dhcp_bcast,
                        fileserver = self.options.dhcp_fileserver,
                        filename = self.options.dhcp_filename)
            self.dhcp_server_thread = threading.Thread(name='dhcp', target=self.dhcp_server.listen)
            self.dhcp_server_thread.daemon = True
            self.dhcp_server_thread.start()
            self.dhcp_control_button.configure(text="Stop DHCP Server", command=self.stop_dhcp_server)
        except Exception, e:
            self.main_logger.error("Cannot start the server: %s", e)
            raise e

    def stop_dhcp_server(self):
        self.main_logger.debug("DHCP: Stopping thread")
        self.dhcp_server.shutdown()
        self.dhcp_server = None
        self.main_logger.debug("DHCP: Stopped thread")        
        self.dhcp_control_button.configure(text="Start DHCP Server", command=self.start_dhcp_server)
 
    def start_http_server(self):
        self.main_logger.debug("HTTP Server: Starting thread")
        self.options.ip_address = self.gui_sip_ip_address.get()
        self.options.http_port = self.gui_http_port.get()
        self.options.http_root = self.gui_http_root.get()
        
        self.main_logger.debug("HTTP Server port: %s", self.options.http_port)
        try:
            self.http_server = http.HTTPD(ip = self.options.ip_address, mode_debug = self.options.debug, port = self.options.http_port, logger = self.main_logger, work_directory = self.options.http_root)
            self.http_server_thread = threading.Thread(name='http', target=self.http_server.listen)
            self.http_server_thread.daemon = True
            self.http_server_thread.start()           
            self.http_control_button.configure(text="Stop HTTP Server", command=self.stop_http_server)
        except Exception, e:
            self.main_logger.error("HTTP: Cannot start the server: %s", e)
            raise e

    def stop_http_server(self):
        self.main_logger.debug("HTTP: Stopping thread")
        self.http_server.shutdown()
        self.http_server = None
        self.main_logger.debug("HTTP: Stopped thread")
        self.http_control_button.configure(text="Start HTTP Server", command=self.start_http_server)

    def start_pnp_server(self):
        self.main_logger.debug("PnP Server: Starting thread")
    
        self.options.ip_address = self.gui_sip_ip_address.get()
        self.options.pnp_uri = self.gui_pnp_uri.get()
        self.main_logger.debug("Writing SIP messages in %s log file" % self.options.sip_logfile)
        self.main_logger.debug("Logfile: %s" % self.options.logfile)
 
        try:
            self.pnp_server = pnp.SipTracedMcastUDPServer(('224.0.1.75', 5060), pnp.UDPHandler, self.sip_trace_logger, self.main_logger, self.options)
            self.pnp_server_thread = threading.Thread(name='pnp', target=self.pnp_server.serve_forever)
            self.pnp_server_thread.daemon = True
            self.pnp_server_thread.start()
            self.pnp_control_button.configure(text="Stop PnP Server", command=self.stop_pnp_server)
        except Exception, e:
            self.main_logger.error("Cannot start the server: %s" % e)
            raise e
 
    def stop_pnp_server(self):
        self.main_logger.debug("PnP: Stopping thread")
        self.pnp_server.shutdown()
        self.pnp_server.socket.close()
        self.pnp_server = None
        self.main_logger.debug("PnP: Stopped thread")
        self.pnp_control_button.configure(text="Start PnP Proxy", command=self.start_pnp_server)

    def gui_debug_action(self):
        if self.gui_debug.get():
            self.main_logger.debug("Activating Debug")
            self.main_logger.setLevel(logging.DEBUG)
        else:
            self.main_logger.debug("Deactivating Debug")
            self.main_logger.setLevel(logging.INFO)
        self.options.debug = self.gui_debug.get()

    def gui_sip_redirect_action(self):
        if self.gui_sip_redirect.get():
            self.main_logger.debug("Activating Redirect server")
        else:
            self.main_logger.debug("Deactivating Redirect Server")
        self.options.redirect = self.gui_sip_redirect.get()


class SipLogFrame:
    def __init__(self, root, options, main_logger):
        self.root = root
        self.options = options
        self.main_logger = main_logger

        # SIP Trace tab with 2 rows: first with controls, second with SIP trace
        self.frame = tk.Frame(self.root)
        self.frame.columnconfigure(0, weight=1)
        # first row doesn't expoands
        self.frame.rowconfigure(0, weight=0)
        # let the second row grow
        self.frame.rowconfigure(1, weight=1)
        
        self.sip_commands_frame = tk.LabelFrame(self.frame, text="Controls", padx=5, pady=5)
        self.sip_commands_frame.grid(row=0, column=0, sticky=tk.NSEW, padx=4, pady=5)
        
        self.sip_trace_frame = tk.Frame(self.frame)
        self.sip_trace_frame.grid(row=1, column=0, sticky=tk.NSEW)
        # let the SIP trace growing
        self.sip_trace_frame.columnconfigure(0, weight=1)
        self.sip_trace_frame.rowconfigure(0, weight=1)

        self.sip_trace = ScrolledText(self.sip_trace_frame)
        self.sip_trace.grid(row=0, column=0, sticky=tk.NSEW)
        self.sip_trace.config(state='disabled') 
        
        # SIP Trace frame
        row = 0
        self.sip_trace_clear_button = tk.Button(self.sip_commands_frame, text="Clear", command=self.clear_sip_trace)
        self.sip_trace_clear_button.grid(row=row, column=0, sticky=tk.N)
        
        self.sip_trace_pause_button = tk.Button(self.sip_commands_frame, text="Pause", command=self.pause_sip_trace)
        self.sip_trace_pause_button.grid(row=row, column=1, sticky=tk.N)
        
    def get_frame(self): 
        return self.frame
    
    def pause_sip_trace(self):
        if self.sip_trace_alarm is not None:
            self.sip_trace.after_cancel(self.sip_trace_alarm)
            self.sip_trace_pause_button.configure(text="Resume", command=self.start_sip_trace)
            self.sip_trace_alarm = None

    def start_sip_trace(self):
        self.update_sip_trace_widget()
        self.sip_trace_pause_button.configure(text="Pause", command=self.pause_sip_trace)

    def clear_sip_trace(self):
        self.sip_trace.config(state='normal')
        self.sip_trace.delete(0.0, tk.END)
        self.sip_trace.config(state='disabled')

    def update_sip_trace_widget(self):
        self.update_widget(self.sip_trace, self.sip_queue) 
        self.sip_trace_alarm = self.sip_trace.after(20, self.update_sip_trace_widget)
     
    def update_widget(self, widget, queue):
        widget.config(state='normal')
        while not queue.empty():
            #line = queue.get_nowait()
            line = queue.get()
            widget.insert(tk.END, line)
            widget.see(tk.END)  # Scroll to the bottom
            widget.update_idletasks()
        widget.config(state='disabled')
        #widget.after(10, self.update_widget, widget, queue)

class LogFrame:
    def __init__(self, root, options, main_logger):
        self.root = root
        self.options = options
        self.main_logger = main_logger

        self.frame = tk.Frame(self.root)
        self.frame.columnconfigure(0, weight=1)
        # first row doesn't expoands
        self.frame.rowconfigure(0, weight=0)
        # let the second row grow
        self.frame.rowconfigure(1, weight=1)

        self.log_commands_frame = tk.LabelFrame(self.frame, text="Controls", padx=5, pady=5)
        self.log_commands_frame.grid(row=0, column=0, sticky=tk.NSEW, padx=4, pady=5)

        self.log_messages_frame = tk.Frame(self.frame)
        self.log_messages_frame.grid(row=1, column=0, sticky=tk.NSEW)
        # let the SIP trace growing
        self.log_messages_frame.columnconfigure(0, weight=1)
        self.log_messages_frame.rowconfigure(0, weight=1)

        self.log_messages = ScrolledText(self.log_messages_frame)
        self.log_messages.grid(row=0, column=0, sticky=tk.NSEW)

        # Log Messages frame
        row = 0
        self.log_messages_clear_button = tk.Button(self.log_commands_frame, text="Clear", command=self.clear_log_messages)
        self.log_messages_clear_button.grid(row=row, column=0, sticky=tk.N)
        
        self.log_messages_pause_button = tk.Button(self.log_commands_frame, text="Pause", command=self.pause_log_messages)
        self.log_messages_pause_button.grid(row=row, column=1, sticky=tk.N)
        row = row + 1

    def get_frame(self): 
        return self.frame

    def clear_log_messages(self):
        self.log_messages.config(state='normal')
        self.log_messages.delete(0.0, tk.END)
        self.log_messages.config(state='disabled')

    def pause_log_messages(self):
        if self.log_messages_alarm is not None:
            self.log_messages.after_cancel(self.log_messages_alarm)
            self.log_messages_pause_button.configure(text="Resume", command=self.start_log_messages)
            self.log_messages_alarm = None

    def start_log_messages(self):
        self.update_log_messages_widget()
        self.log_messages_pause_button.configure(text="Pause", command=self.pause_log_messages)
        
    def update_log_messages_widget(self):
        self.update_widget(self.log_messages, self.log_queue) 
        self.log_messages_alarm = self.log_messages.after(20, self.update_log_messages_widget)

    def update_widget(self, widget, queue):
        widget.config(state='normal')
        while not queue.empty():
            line = queue.get()
            widget.insert(tk.END, line)
            widget.see(tk.END)  # Scroll to the bottom
            widget.update_idletasks()
        widget.config(state='disabled')

class MainApplication:
    def __init__(self, root, options, main_logger):
        self.root = root
        # bring in fron hack
        self.root.lift()
        self.root.call('wm', 'attributes', '.', '-topmost', True)
        self.root.after_idle(self.root.call, 'wm', 'attributes', '.', '-topmost', False)
        
        self.options = options
        self.main_logger = main_logger
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        self.notebook = ttk.Notebook(self.root)
        
        self.main_handler = MainFrame(self.root, self.options, self.main_logger)
        self.main_frame = self.main_handler.get_frame()

        self.sip_handler = SipLogFrame(self.root, self.options, self.main_logger)
        self.sip_frame = self.sip_handler.get_frame()
        self.sip_handler.sip_queue = self.main_handler.get_sip_queue()
        self.sip_handler.start_sip_trace()

        self.log_handler = LogFrame(self.root, self.options, self.main_logger)
        self.log_frame = self.log_handler.get_frame()
        self.log_handler.log_queue = self.main_handler.get_log_queue()
        self.log_handler.start_log_messages()

        self.notebook.add(self.main_frame, text='Main', padding=0)
        self.notebook.add(self.sip_frame, text='SIP Trace', padding=0)
        self.notebook.add(self.log_frame, text='Log', padding=0)
        
        self.notebook.grid(row=0, column=0, sticky=tk.NSEW)       
        self.notebook.grid(row=0, sticky=tk.NSEW)
        
        self.root.wm_protocol("WM_DELETE_WINDOW", self.cleanup_on_exit)
    
    def cleanup_on_exit(self):
        self.root.quit() 
