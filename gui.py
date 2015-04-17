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


import Queue
import logging
import time
import threading

import utils
import proxy

from Tkinter import *
from ttk import *
from ScrolledText import *

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



class MainApplication:
    def __init__(self, root, options, main_logger, server=None):
        self.root = root
        # bring in fron hack
        self.root.lift()
        self.root.call('wm', 'attributes', '.', '-topmost', True)
        self.root.after_idle(self.root.call, 'wm', 'attributes', '.', '-topmost', False)
        
        self.server = server
        self.options = options
        self.main_logger = main_logger
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

        self.notebook.add(self.main_frame, text='Main', padding=0)
        self.notebook.add(self.sip_frame, text='SIP Trace', padding=0)
        self.notebook.add(self.log_frame, text='Log', padding=0)
        self.notebook.grid(row=0, column=0, sticky=NSEW)       

        self.sip_trace = ScrolledText(self.sip_trace_frame)
        self.sip_trace.grid(row=0, column=0, sticky=NSEW)
        self.sip_trace.config(state='disabled') 
        
        self.log_messages = ScrolledText(self.log_messages_frame)
        self.log_messages.grid(row=0, column=0, sticky=NSEW)

        self.sip_queue = Queue.Queue()
        self.sip_trace_logger = utils.setup_logger('sip_widget_logger', log_file=None, debug=True, str_format='%(asctime)s %(message)s', handler=SipTraceQueueLogger(queue=self.sip_queue))
        
        self.log_queue = Queue.Queue()
        utils.setup_logger('main_logger', options.logfile, self.options.debug, handler=MessagesQueueLogger(queue=self.log_queue))

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
        
        self.sip_trace_pause_button = Button(self.sip_commands_frame, text="Pause", command=self.pause_sip_trace)
        self.sip_trace_pause_button.grid(row=row, column=1, sticky=N)
        
        # Log Messages frame
        row = 0
        self.log_messages_clear_button = Button(self.log_commands_frame, text="Clear", command=self.clear_log_messages)
        self.log_messages_clear_button.grid(row=row, column=0, sticky=N)
        
        self.log_messages_pause_button = Button(self.log_commands_frame, text="PPause", command=self.pause_log_messages)
        self.log_messages_pause_button.grid(row=row, column=1, sticky=N)
        row = row + 1

        self.start_sip_trace()
        self.start_log_messages()
       
        self.notebook.grid(row=0, sticky=NSEW)
        self.root.wm_protocol("WM_DELETE_WINDOW", self.cleanup_on_exit)

    def pause_log_messages(self):
        if self.log_messages_alarm is not None:
            self.log_messages.after_cancel(self.log_messages_alarm)
            self.log_messages_pause_button.configure(text="Resume", command=self.start_log_messages)
            self.log_messages_alarm = None

    def start_log_messages(self):
        self.update_log_messages_widget()
        self.log_messages_pause_button.configure(text="Pause", command=self.pause_log_messages)
        
    def pause_sip_trace(self):
        if self.sip_trace_alarm is not None:
            self.sip_trace.after_cancel(self.sip_trace_alarm)
            self.sip_trace_pause_button.configure(text="Resume", command=self.start_sip_trace)
            self.sip_trace_alarm = None

    def start_sip_trace(self):
        self.update_sip_trace_widget()
        self.sip_trace_pause_button.configure(text="Pause", command=self.pause_sip_trace)

    def update_log_messages_widget(self):
        self.update_widget(self.log_messages, self.log_queue) 
        self.log_messages_alarm = self.log_messages.after(10, self.update_log_messages_widget)

    def update_sip_trace_widget(self):
        self.update_widget(self.sip_trace, self.sip_queue) 
        self.sip_trace_alarm = self.sip_trace.after(10, self.update_sip_trace_widget)
    
    def update_widget(self, widget, queue):
        widget.config(state='normal')
        while not queue.empty():
            #line = queue.get_nowait()
            line = queue.get()
            widget.insert(END, line)
            widget.see(END)  # Scroll to the bottom
            widget.update_idletasks()
        widget.config(state='disabled')
        #widget.after(10, self.update_widget, widget, queue)

    def gui_debug_action(self):
        if self.gui_debug.get():
            self.main_logger.debug("Activating Debug")
            self.main_logger.setLevel(logging.DEBUG)
        else:
            self.main_logger.debug("Deactivating Debug")
            self.main_logger.setLevel(logging.INFO)
        self.options.debug = self.gui_debug.get()

    def gui_redirect_action(self):
        if self.gui_redirect.get():
            self.main_logger.debug("Activating Redirect server")
        else:
            self.main_logger.debug("Deactivating Redirect Server")
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
        
        if self.server == None:
            self.registrar_text.insert(END, "Server not running\n")
            self.registrar_text.see(END)
            self.registrar_text.config(state='disabled')
            return

        if len(self.server.registrar) > 0:
            for regname in self.server.registrar:
                self.registrar_text.insert(END, "\n%s:\n" % regname)
                self.registrar_text.insert(END, "\t Contact: %s\n" % self.server.registrar[regname][0])
                self.registrar_text.insert(END, "\t IP: %s:%s\n" % (self.server.registrar[regname][2][0], self.server.registrar[regname][2][1]) )
                self.registrar_text.insert(END, "\t Expires: %s\n" % time.ctime(self.server.registrar[regname][3]))
        else:
            self.registrar_text.insert(END, "No User Agent registered yet\n")
            
        self.registrar_text.see(END)
        self.registrar_text.config(state='disabled')

    def run_server(self):
        self.main_logger.debug("Starting thread")
        self.options.ip_address = self.gui_ip_address.get()
        self.options.port = self.gui_port.get()
        self.options.password = self.gui_password.get()
        self.main_logger.info(time.strftime("Starting proxy at %a, %d %b %Y %H:%M:%S ", time.localtime()))
    
        self.main_logger.debug("Writing SIP messages in %s log file" % self.options.sip_logfile)
        self.main_logger.debug("Authentication password: %s" % self.options.password)
        self.main_logger.debug("Logfile: %s" % self.options.logfile)
 
        try:
            self.server = proxy.SipTracedUDPServer((self.options.ip_address, self.options.port), proxy.UDPHandler, self.sip_trace_logger, self.main_logger, self.options)
            self.server_thread = threading.Thread(name='sip', target=self.server.serve_forever)
            self.server_thread.daemon = True
            self.server_thread.start()
            self.control_button.configure(text="Stop", command=self.stop_server)
        except Exception, e:
            self.main_logger.error("Cannot start the server: %s" % e)
            raise e
        
        self.main_logger.debug("Using the top Via header: %s" % self.server.topvia) 
        
        if self.options.redirect:
            self.main_logger.debug("Working in redirect server mode")
        else:
            self.main_logger.debug("Using the Record-Route header: %s" % self.server.recordroute) 
        
    def stop_server(self):
        self.main_logger.debug("Stopping thread")
        self.server.shutdown()
        self.server.socket.close()
        self.server = None
        self.main_logger.debug("Stopped thread")
        self.control_button.configure(text="Run", command=self.run_server)


