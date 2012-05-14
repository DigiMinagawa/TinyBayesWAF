#!/bin/sh -
# -*- coding: utf-8 -*-
"exec" "python" "-O" "$0" "$@"

__doc__ = """Tiny NaiveBayes WAF.
Tiny NaiveBayes WAF$B$O8&5fMQ$N(BWAF$B%W%m%0%i%`$G$9!#(B
SUZUKI Hisao$B;a$N(B Tiny HTTP Proxy$B$r2~NI$7$?%W%m%0%i%`$G$9!#(B
naivebayes$B$G%U%#%k%?%j%s%0$r9T$J$&(BWAF$B$G$9!#(B    Murata Souichiro

"""
__version__ = "0.0.2"
count_q = 0
#$B7Q>5!!(BBaseHTTPRequestHandler
import BaseHTTPServer, select, socket, SocketServer, urlparse
from pprint import pprint
#NaiveBayes$B%/%i%9FI$_9~$_(B
from naivebayes import *
#train$B4X?t$r<B9T$9$k(B
from traingdata import train_data  


"""
ProxyHandler$B%/%i%9(B
BaseHTTPServer.BaseHTTPRequestHandler$B$r7Q>5$7$?(BProxyServer
$B=hM}$NFbMF$O(BBaseHTTPServer.py$B$r8+$h(B
"""
class ProxyHandler (BaseHTTPServer.BaseHTTPRequestHandler):
    __base = BaseHTTPServer.BaseHTTPRequestHandler
    __base_handle = __base.handle
    __base_send_response = __base.send_response
    server_version = "TinyNaiveBayesWAF/" + __version__
    rbufsize = 0                        # self.rfile Be unbuffered
    request_flag = 0                    # request_flag $B%j%/%(%9%H$G$"$k$+$I$&$+(B

    """
    handle_one_request
    Handle a single HTTP request.
    HTTP$B%j%/%(%9%H$r=hM}$9$k(B
    """
    def handle_one_request(self):
        """Handle a single HTTP request.

        You normally don't need to override this method; see the class
        __doc__ string for inform"ation on how to handle specific HTTP
        commands such as GET and POST.

        """
        #############################
        self.raw_requestline = self.rfile.readline()
        
        raw_requestline = self.raw_requestline

        
        if not self.raw_requestline:
            self.close_connection = 1
            return
        if not self.parse_request(): # An error code has been sent, just exit
            return
        mname = 'do_' + self.command
        if not hasattr(self, mname):
            self.send_error(501, "Unsupported method (%r)" % self.command)
            return
        method = getattr(self, mname)
        method()

    """
    handle
    $BI,MW$K1~$8$FJ#?t$N(BHTTP$B$N1~Ez$r=hM}$9$k(B
    """
    def handle(self):
        (ip, port) =  self.client_address
        if hasattr(self, 'allowed_clients') and ip not in self.allowed_clients:
            self.raw_requestline = self.rfile.readline()
            if self.parse_request(): self.send_error(403)
        else:
            self.__base_handle()
    
    """
    parse_request
    $B%j%/%(%9%H$r%Q!<%9$9$k(B    
    """
    def parse_request(self):
        """Parse a request (internal).

        The request should be stored in self.raw_requestline; the results
        are in self.command, self.path, self.request_version and
        self.headers.

        Return True for success, False for failure; on failure, an
        error is sent back.

        """
        self.command = None  # set in case of error on the first line
        self.request_version = version = self.default_request_version
        self.close_connection = 1
        requestline = self.raw_requestline
        if requestline[-2:] == '\r\n':
            requestline = requestline[:-2]
        elif requestline[-1:] == '\n':
            requestline = requestline[:-1]
        self.requestline = requestline
        words = requestline.split()
        if len(words) == 3:
            [command, path, version] = words
            if version[:5] != 'HTTP/':
                self.send_error(400, "Bad request version (%r)" % version)
                return False
            try:
                base_version_number = version.split('/', 1)[1]
                version_number = base_version_number.split(".")
                # RFC 2145 section 3.1 says there can be only one "." and
                #   - major and minor numbers MUST be treated as
                #      separate integers;
                #   - HTTP/2.4 is a lower version than HTTP/2.13, which in
                #      turn is lower than HTTP/12.3;
                #   - Leading zeros MUST be ignored by recipients.
                if len(version_number) != 2:
                    raise ValueError
                version_number = int(version_number[0]), int(version_number[1])
            except (ValueError, IndexError):
                self.send_error(400, "Bad request version (%r)" % version)
                return False
            if version_number >= (1, 1) and self.protocol_version >= "HTTP/1.1":
                self.close_connection = 0
            if version_number >= (2, 0):
                self.send_error(505,
                          "Invalid HTTP Version (%s)" % base_version_number)
                return False
        elif len(words) == 2:
            [command, path] = words
            self.close_connection = 1
            if command != 'GET':
                self.send_error(400,
                                "Bad HTTP/0.9 request type (%r)" % command)
                return False
        elif not words:
            return False
        else:
            self.send_error(400, "Bad request syntax (%r)" % requestline)
            return False

        
        
        self.command, self.path, self.request_version = command, path, version

        # Examine the headers and look for a Connection directive
        self.headers = self.MessageClass(self.rfile, 0)
                
        
        conntype = self.headers.get('Connection', "")
        if conntype.lower() == 'close':
            self.close_connection = 1
        elif (conntype.lower() == 'keep-alive' and
              self.protocol_version >= "HTTP/1.1"):
            self.close_connection = 0
        return True

    
    """
    send_response
    $B%l%9%]%s%9$rJV$9(B
    $BCf?H$O2?$b=q$-49$($F$$$J$$(B
    todo:Response$B$G%U%#%k%?%j%s%0$7$F$_$k(B
    """
    def send_response(self, code, message=None):
        """Send the response header and log the response code.

        Also send two standard headers with the server software
        version and the current date.

        """
        self.log_request(code)
        if message is None:
            if code in self.responses:
                message = self.responses[code][0]
            else:
                message = ''
        if self.request_version != 'HTTP/0.9':
            self.wfile.write("%s %d %s\r\n" %
                             (self.protocol_version, code, message))
            #print (self.protocol_version, code, message)
        self.send_header('Server', self.version_string())
        self.send_header('Date', self.date_time_string())

    #$B%a%=%C%I$N:F<BAu$O$3$3$^$G(B
    ###################################
    
    
    """
    _connect_to
    $B%=%1%C%H$H(BIP$B%"%I%l%9$r;H$C$F%3%M%/%7%g%s$r$O$k(B
    do_GET$B$+$i8F$P$l$k%a%=%C%I(B
    """
    def _connect_to(self, netloc, soc):

        i = netloc.find(':')
        if i >= 0:
            host_port = netloc[:i], int(netloc[i+1:])
        else:
            host_port = netloc, 80
        #print "\t" "connect to %s:%d" % host_port
        try: soc.connect(host_port)
        except socket.error, arg:
            try: msg = arg[1]
            except: msg = arg
            self.send_error(404, msg)
            return 0
        return 1

    """
    do_CONNECT
    HTTPS$BMQ$N1~Ez%a%=%C%I(B
    $BL$<BAu(B
    $B8=>u$O%(%i!<$GJV$9(B
    """
    def do_CONNECT(self):
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if self._connect_to(self.path, soc):
                self.log_request(200)
                self.wfile.write(self.protocol_version +
                                 " 200 Connection established\r\n")
                self.wfile.write("Proxy-agent: %s\r\n" % self.version_string())
                self.wfile.write("\r\n")
                self._read_write(soc, 300)
        finally:
            #print "\t" "bye"
            soc.close()
            self.connection.close()
    
    """
    do_GET
    $B%=%1%C%HDL?.$K$h$k%5!<%P@\B3(B
    todo:netloc$B$r%/%i%9$N%W%m%Q%F%#$+$i<hF@$9$k(B
    todo:netloc$B0J30$N%"%/%;%9$,$"$C$?$i<WCG$9$k(B
    """
    def do_GET(self):
        (scm, netloc, path, params, query, fragment) = urlparse.urlparse(
            self.path, 'http')
        #netloc destination address
        #$BE>Aw@h(B
        netloc = '172.16.137.131'
        global count_q

        if scm != 'http' or fragment or not netloc:
            self.send_error(400, "bad url %s" % self.path)
            return
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if self._connect_to(netloc, soc):
                self.log_request()
                soc.send("%s %s %s\r\n" % (
                    self.command,
                    urlparse.urlunparse(('', '', path, params, query, '')),
                    self.request_version))
                self.headers['Connection'] = 'close'
                del self.headers['Proxy-Connection']
                for key_val in self.headers.items():
                    soc.send("%s: %s\r\n" % key_val)
                soc.send("\r\n")
                self._read_write(soc, 20, 1)
        finally:
            print "\t" "bye"
            soc.close()
            self.connection.close()

    """
    _read_write
    $BAw<u?.$r9T$&(B
    do_GET$B$+$i8F$P$l$k%a%=%C%I(B
    """
    def _read_write(self, soc ,max_idling=20, flag=0):
        iw = [self.connection, soc]
        ow = []
        global count_q
        count = 0
        while 1:
            count += 1
            (ins, _, exs) = select.select(iw, ow, iw, 3)
            if exs:
                break
            if ins:
                for i in ins:
                    if i is soc:
                        out = self.connection
                    else:
                        out = soc
                        #$B%j%/%(%9%H$N>l9g$@$1%U%i%0$rN)$F$k(B
                        self.request_flag = 1
                    data = i.recv(8192)
                    if data:
                        if self.request_flag == 1:
                            print data
                        out.send(data)
                    self.request_flag = 0
            else:
                print "\t" "idle", count
            if count == max_idling: break

    #$B$9$Y$F(Bdo_GET$B$G=hM}(B
    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT  = do_GET
    do_DELETE=do_GET
    

'''
ThreadingHTTPServer
'''
class ThreadingHTTPServer (SocketServer.ThreadingMixIn,
                           BaseHTTPServer.HTTPServer): pass

if __name__ == '__main__':
    from sys import argv
    if argv[1:] and argv[1] in ('-h', '--help'):
        dummy = 0
        print argv[0], "[port] [Destination address]"
        print argv[0], "--sample -s naivebayes Sample"
        print argv[0], "-t --training training naivebayes"
        print argv[0], "-f --fileload NaiveBayesWAF todo trainnngdataimport"
    
    elif argv [1:] and argv[1] in ('-t','--training'):
        #$B%H%l!<%K%s%0%G!<%?:n@.(B
        #$B0JA0$O%H%l!<%K%s%08e$N%G!<%?$r(BPickle$B%G!<%?$H$7$FJ]B8$7$F$$$?$,(B
        #$B%3!<%I$,$a$A$c$/$A$c$@$C$?0Y!":o=|(B
        #$B<B9T$^$G;~4V$,$+$+$k$+$iDI2C4hD%$C$F2<$5$$(B
        dummy = 0

    elif argv [1:] and argv[1] in ('-s','--sample'):
        #$B%5%s%W%k%G!<%?<B9T(B
        naive_test()
    elif argv [1:] and argv[1] in ('-f','--fileload'):
        #$B%H%l!<%K%s%0%G!<%?$rFI$_9~$s$G%U%#%k%?%j%s%03+;O(B
        #$B%H%l!<%K%s%0%G!<%?FI$_9~$_$r:o=|(B
        #$B%H%l!<%K%s%0%G!<%?$r<hF@!"<B9T(B
        train_data()
 
        if argv[2:]:
            for name in argv[2:]:
                client = socket.gethostbyname(name)
            del argv[2:]
        else:
            print "Any clients will be served..."
        BaseHTTPServer.test(ProxyHandler, ThreadingHTTPServer)

        
    else:
        if argv[2:]:
            for name in argv[2:]:
                client = socket.gethostbyname(name)
            del argv[2:]
        else:
            print "Any clients will be served..."
        BaseHTTPServer.test(ProxyHandler, ThreadingHTTPServer)
