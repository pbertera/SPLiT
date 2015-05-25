'''

This file contains classes and functions that implement the PyPXE HTTP service

'''

import os
import logging
import threading

try:
    # Python 2.x
    from SocketServer import ThreadingMixIn
    from SimpleHTTPServer import SimpleHTTPRequestHandler
    from BaseHTTPServer import HTTPServer
except ImportError:
    # Python 3.x
    from socketserver import ThreadingMixIn
    from http.server import SimpleHTTPRequestHandler, HTTPServer

class HTTPDThreadedServer(ThreadingMixIn, HTTPServer):

    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass, logger, path):
        self.logger = logger
        self.path = path
        HTTPServer.__init__(self, server_address, RequestHandlerClass)

    def shutdown(self):
        #self.socket.close()
        self.logger.info("HTTPD server thread shutdown")
        HTTPServer.shutdown(self)
    
    def log_message(self, format, *args):
        self.logger.info("%s - - [%s] %s\n" % (self.client_address[0],
            self.log_date_time_string(),
            format%args))

class MySimpleHTTPRequestHandler(SimpleHTTPRequestHandler):

    def translate_path(self, path):
        """Translate a /-separated PATH to the local filename syntax.

        Components that mean special things to the local file system
        (e.g. drive or directory names) are ignored.  (XXX They should
        probably be diagnosed.)

        """
        # abandon query parameters
        path = path.split('?',1)[0]
        path = path.split('#',1)[0]
        # Don't forget explicit trailing slash when normalizing. Issue17324
        trailing_slash = path.rstrip().endswith('/')
        path = posixpath.normpath(urllib.unquote(path))
        words = path.split('/')
        words = filter(None, words)
        path = self.server.path
        for word in words:
            drive, word = os.path.splitdrive(word)
            head, word = os.path.split(word)
            if word in (os.curdir, os.pardir): continue
            path = os.path.join(path, word)
        if trailing_slash:
            path += '/'
        return path

class HTTPD():
    def __init__(self, **serverSettings):
        self.ip = serverSettings.get('ip', '0.0.0.0')
        self.port = serverSettings.get('port', 80)
        self.work_directory = serverSettings.get('work_directory', '.')
        self.mode_debug = serverSettings.get('mode_debug', False) #debug mode
        self.logger =  serverSettings.get('logger', None)
        
        #os.chdir(self.work_directory)
        handler = MySimpleHTTPRequestHandler
        self.server = HTTPDThreadedServer((self.ip, self.port), handler, self.logger, self.work_directory)
 
        # setup logger
        if self.logger == None:
            self.logger = logging.getLogger("HTTP")
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s %(name)s [%(levelname)s] %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

        if self.mode_debug:
            self.logger.setLevel(logging.DEBUG)
        
        self.logger.info("NOTICE: HTTP server starting on %s:%d" % (self.ip, self.port))

    def listen(self):
        self.server.serve_forever()

    def shutdown(self):
        self.server.shutdown()

if __name__ == '__main__':
    import sys
    import time
    httpd = HTTPD(ip=sys.argv[1], port=int(sys.argv[2]), mode_debug=True, logger=None)
    #httpd.listen()
    
    httpd_thread = threading.Thread(name='http', target=httpd.listen)
    httpd_thread.daemon = True
    
    httpd_thread.start()
    while httpd_thread.isAlive():
        time.sleep(1)
