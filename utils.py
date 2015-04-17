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

import logging

def setup_logger(logger_name, log_file=None, debug=False, str_format='%(asctime)s %(levelname)s %(message)s', handler=None):
    """Register a logging instance with name `logger_name`

    Args:
        logger_name (str): the logger instance name, you can retreive the instance using `logging.getLogger("logger_name")`
        log_file (str, optional): if defined a `logging.FileHandler` will be used, default `None`
        debug (bool, optional): if `True` the logger level will be `logging.DEBUG` else `logging.INFO`
        str_format (str, optional): the logger format string, default is '%(asctime)s %(levelname)s %(message)s'
        handler (logging.Handler, optional): if present the handler will be added to the logger

    Returns: the ``logging.Logger` instance
    """
    l = logging.getLogger(logger_name)
    
    if debug == True:
        l.setLevel(logging.DEBUG)
    else:
        l.setLevel(logging.INFO)

    formatter = logging.Formatter(str_format)
    if handler:
        handler.setFormatter(formatter)
        l.addHandler(handler)
        return l
    elif log_file:
        fileHandler = logging.FileHandler(log_file, mode='w')
        fileHandler.setFormatter(formatter)
        l.addHandler(fileHandler)
    else: 
        streamHandler = logging.StreamHandler()
        streamHandler.setFormatter(formatter)
        l.addHandler(streamHandler)

    return l
