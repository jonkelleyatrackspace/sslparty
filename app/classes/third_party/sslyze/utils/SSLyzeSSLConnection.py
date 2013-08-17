#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         SSLyzeSSLConnection.py
# Purpose:      The SSL connection class that all SSLyze Plugins should be 
#               using. It takes care of creating the right connections based
#               on the command line arguments supplied by the user.
#
# Author:       alban
#
# Copyright:    2013 SSLyze developers
#
#   SSLyze is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 2 of the License, or
#   (at your option) any later version.
#
#   SSLyze is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with SSLyze.  If not, see <http://www.gnu.org/licenses/>.
#-------------------------------------------------------------------------------

import socket
from HTTPResponseParser import parse_http_response
from nassl import SSL_FILETYPE_ASN1,  SSL_FILETYPE_PEM, SSLV23, _nassl, SSL_VERIFY_NONE
from nassl.SslClient import SslClient



def create_sslyze_connection(target, shared_settings, sslVersion=None, sslVerifyLocations=None):
    """
    Utility function to create the proper SSLConnection based on what's 
    in the shared_settings. All plugins should use this for their SSL 
    connections.
    """
    (host, ip, port, sslSupport) = target
    # If no SSL version was provided, use the one supported by the server
    if sslVersion == None: 
        sslVersion = sslSupport
    
    # Create the proper connection
    timeout = shared_settings['timeout']
    startTls = shared_settings['starttls']
    
    STARTTLS_DISPATCH = { 'smtp' :  SMTPConnection,
                          587 :     SMTPConnection,
                          22 :      SMTPConnection,
                          'xmpp':   XMPPConnection,
                          5222 :    XMPPConnection,
                          5269 :    XMPPConnection,
                          'pop3' :  POP3Connection,
                          109 :     POP3Connection,
                          110 :     POP3Connection,
                          'imap' :  IMAPConnection,
                          143 :     IMAPConnection,
                          220 :     IMAPConnection,
                          'ftp' :   FTPConnection,
                          21 :      FTPConnection,
                          'ldap' :  LDAPConnection,
                          3268 :    LDAPConnection,
                          389 :     LDAPConnection }
    
    if shared_settings['starttls']:
        
        if shared_settings['starttls'] in STARTTLS_DISPATCH.keys():
            # Protocol was given in the command line
            connectionClass = STARTTLS_DISPATCH[startTls]

        elif shared_settings['starttls'] == 'auto': 
            # We use the port number to deduce the protocol
            if port in STARTTLS_DISPATCH.keys():
                connectionClass = STARTTLS_DISPATCH[port]    
            else:
                connectionClass = SSLConnection
                
        sslConn = connectionClass((ip,port), sslVersion, sslVerifyLocations, timeout)
        
        # XMPP configuration
        if connectionClass == XMPPConnection:
            if shared_settings['xmpp_to']:
                sslConn.set_xmpp_to(shared_settings['xmpp_to'])
            else:
                sslConn.set_xmpp_to(host)
                        
        
    elif shared_settings['https_tunnel_host']:
        # Using an HTTP CONNECT proxy to tunnel SSL traffic
        if shared_settings['http_get']:
            sslConn = HTTPSTunnelConnection((ip,port), sslVersion, 
                                            sslVerifyLocations, timeout, 
                                            shared_settings['https_tunnel_host'], 
                                            shared_settings['https_tunnel_port'])
        else:
            sslConn = SSLTunnelConnection((ip,port), sslVersion, 
                                          sslVerifyLocations, timeout, 
                                          shared_settings['https_tunnel_host'], 
                                          shared_settings['https_tunnel_port'])
    
    elif shared_settings['http_get']:
        sslConn = HTTPSConnection((ip,port), sslVersion, sslVerifyLocations, timeout)    
    else:
        sslConn = SSLConnection((ip,port), sslVersion, sslVerifyLocations, timeout)
    

    # Load client certificate and private key
    # These parameters should have been validated when parsing the command line
    if shared_settings['cert']:
        sslConn.use_certificate_file(shared_settings['cert'], 
                                            shared_settings['certform'])                
        sslConn.use_privateKey_file(shared_settings['key'], 
                                           shared_settings['keyform'], 
                                           shared_settings['keypass'])
        sslConn.check_private_key()
    
    
    # Add Server Name Indication
    if shared_settings['sni']:
        sslConn.set_tlsext_host_name(shared_settings['sni'])
    
    # Restrict cipher list to make the client hello smaller
    sslConn.set_cipher_list('HIGH:MEDIUM:-aNULL:-eNULL:-3DES:-SRP:-PSK:-CAMELLIA')

    return sslConn
    


class SSLHandshakeRejected(IOError):
    """
    The server explicitly rejected the SSL handshake.
    """
    pass



class StartTLSError(IOError):
    """
    The server rejected the StartTLS negotiation.
    """
    pass



class ProxyError(IOError):
    """
    The proxy was offline or did not return HTTP 200 to our CONNECT request.
    """
    pass



class ClientAuthenticationError(IOError):
    """
    The server asked for a client certificate and we didn't send one.
    """
    
    ERROR_MSG = 'Server requested a client certificate signed by one of the ' +\
    'following CAs: {0}; use the --cert and --key options.'
    
    
    def __init__(self, caList):
        self.caList = caList
        
    def __str__(self):
        caListStr = ''
        for ca in self.caList:
            caListStr += ca + ' '
        return self.ERROR_MSG.format(caListStr)



class SSLConnection(SslClient):
    """Base SSL connection class."""

    # The following errors mean that the server explicitly rejected the 
    # handshake. The goal to differentiate rejected handshakes from random 
    # network errors such as the server going offline, etc.
    HANDSHAKE_REJECTED_SOCKET_ERRORS = \
        {'was forcibly closed' : 'Received FIN',
         'reset by peer' : 'Received RST'}
        
    HANDSHAKE_REJECTED_SSL_ERRORS = \
        {'sslv3 alert handshake failure' : 'Alert handshake failure',
         'no ciphers available' : 'No ciphers available',
         'excessive message size' : 'Excessive message size',
         'bad mac decode' : 'Bad mac decode',
         'wrong version number' : 'Wrong version number',
         'no cipher match' : 'No cipher match',
         'no ciphers available' : 'No ciphers available',
         'bad decompression' : 'Bad decompression',
         'peer error no cipher' : 'Peer error no cipher',
         'no cipher list' : 'No ciphers list',
         'insufficient security' : 'Insufficient security',
         'block type is not 01' : 'block type is not 01'} # Actually an RSA error
    
    
    def __init__(self, (host, port), sslVersion, sslVerifyLocations, timeout):
        super(SSLConnection, self).__init__(None, sslVersion, SSL_VERIFY_NONE,
                                            sslVerifyLocations)
        self._timeout = timeout
        self._sock = None
        self._host = host
        self._port = port
    
 
    def do_pre_handshake(self):
        # Just a TCP connection            
        self._sock = socket.create_connection((self._host, self._port), self._timeout)
    

    def connect(self):
        
        # StartTLS negotiation or proxy setup if needed
        self.do_pre_handshake()
        
        try: # SSL handshake
            self.do_handshake()
            
        # The goal here to differentiate rejected SSL handshakes (which will
        # raise SSLHandshakeRejected) from random network errors

        except socket.error as e:
            for error_msg in self.HANDSHAKE_REJECTED_SOCKET_ERRORS.keys():
                if error_msg in str(e.args):
                    raise SSLHandshakeRejected('TCP - ' + self.HANDSHAKE_REJECTED_SOCKET_ERRORS[error_msg])
            raise # Unknown socket error
        
        except IOError as e:
            if 'Nassl SSL handshake failed' in str(e.args):
                raise SSLHandshakeRejected('TLS - Unexpected EOF')
            raise
        
        except _nassl.OpenSSLError as e:
            clientCertCaList = self.get_client_CA_list()
            if clientCertCaList: # Server wants a client certificate
                raise ClientAuthenticationError(clientCertCaList)
            
            for error_msg in self.HANDSHAKE_REJECTED_SSL_ERRORS.keys():
                if error_msg in str(e.args):
                    raise SSLHandshakeRejected('TLS - ' + self.HANDSHAKE_REJECTED_SSL_ERRORS[error_msg])
                
            raise # Unknown SSL error if we get there            

        
    def close(self):
        self.shutdown()
        if self._sock:
            self._sock.close()
        
        
    def post_handshake_check(self):
        return ''
    
    

class HTTPSConnection(SSLConnection):
    """SSL connection class that sends an HTTP GET request after the SSL
    handshake."""
    
    HTTP_GET_REQ = 'GET / HTTP/1.0\r\nConnection: close\r\n\r\n'
    
    GET_RESULT_FORMAT = 'HTTP {0} {1}{2}'
    
    ERR_TIMEOUT = 'Timeout on HTTP GET'
    ERR_NOT_HTTP = 'Server response was not HTTP'
    
    
    def post_handshake_check(self):
        
        result = ''
        try: # Send an HTTP GET to the server and store the HTTP Status Code
            self.write(self.HTTP_GET_REQ)
            # Parse the response and print the Location header
            httpResp = parse_http_response(self.read(2048))
            if httpResp.version == 9 :
                # HTTP 0.9 => Probably not an HTTP response
                result = self.ERR_NOT_HTTP
            else:    
                redirect = ''
                if httpResp.status >= 300 and httpResp.status < 400:
                    # Add redirection URL to the result
                    redirect = ' - ' + httpResp.getheader('Location', None)

                result = self.GET_RESULT_FORMAT.format(httpResp.status,
                                                       httpResp.reason,
                                                       redirect)                      
        except socket.timeout:
            result = self.ERR_TIMEOUT
                    
        return result
    


class SSLTunnelConnection(SSLConnection):
    """SSL connection class that connects to a server through a CONNECT proxy."""

    HTTP_CONNECT_REQ = 'CONNECT {0}:{1} HTTP/1.1\r\n\r\n'
    
    ERR_CONNECT_REJECTED = 'The proxy rejected the CONNECT request for this host'
    ERR_PROXY_OFFLINE = 'Could not connect to the proxy: "{0}"'
    
    
    def __init__(self, (host, port), sslVersion, sslVerifyLocations, timeout, tunnelHost, tunnelPort):
        
        super(SSLTunnelConnection, self).__init__((host, port), sslVersion,
                                                  sslVerifyLocations, timeout)
        self._tunnelHost = tunnelHost
        self._tunnelPort = tunnelPort
        
            
    def do_pre_handshake(self):
        
        try: # Connect to the proxy first
            self._sock = socket.create_connection((self._tunnelHost, 
                                                   self._tunnelPort), 
                                                   self._timeout)
        except socket.timeout as e:
            raise ProxyError(self.ERR_PROXY_OFFLINE.format(e[0]))
        except socket.error as e:
            raise ProxyError(self.ERR_PROXY_OFFLINE.format(e[1]))
        
        # Send a CONNECT request with the host we want to tunnel to
        self._sock.send(self.HTTP_CONNECT_REQ.format(self._host, self._port))
        httpResp = parse_http_response(self._sock.recv(2048))
        
        # Check if the proxy was able to connect to the host
        if httpResp.status != 200:
            raise ProxyError(self.ERR_CONNECT_REJECTED)



class HTTPSTunnelConnection(SSLTunnelConnection, HTTPSConnection):
    """SSL connection class that connects to a server through a CONNECT proxy 
    and sends an HTTP GET request after the SSL handshake."""



class SMTPConnection(SSLConnection):
    """SSL connection class that performs an SMTP StartTLS negotiation
    before the SSL handshake and sends a NOOP after the handshake."""

    ERR_SMTP_REJECTED = 'SMTP EHLO was rejected'
    ERR_NO_SMTP_STARTTLS = 'SMTP STARTTLS not supported'
    

    def do_pre_handshake(self):
        
        self._sock = socket.create_connection((self._host, self._port), self._timeout)
        # Get the SMTP banner
        self._sock.recv(2048)
        
        # Send a EHLO and wait for the 250 status
        self._sock.send('EHLO sslyze.scan\r\n')
        if '250 ' not in self._sock.recv(2048):
            raise StartTLSError(self.ERR_SMTP_REJECTED)
                
        # Send a STARTTLS
        self._sock.send('STARTTLS\r\n')
        if 'Ready to start TLS'  not in self._sock.recv(2048): 
            raise StartTLSError(self.ERR_NO_SMTP_STARTTLS)


    def post_handshake_check(self):
        try:
            self.write('NOOP\r\n')
            result = self.read(2048).strip()
        except socket.timeout:
            result = 'Timeout on SMTP NOOP'
        return result
        
        
        
class XMPPConnection(SSLConnection):
    """SSL connection class that performs an XMPP StartTLS negotiation
    before the SSL handshake."""
    
    ERR_XMPP_REJECTED = 'Error opening XMPP stream, try --xmpp_to'
    ERR_NO_XMPP_STARTTLS = 'XMPP STARTTLS not supported'
    
    XMPP_OPEN_STREAM = ("<stream:stream xmlns='jabber:client' xmlns:stream='"
        "http://etherx.jabber.org/streams' xmlns:tls='http://www.ietf.org/rfc/"
        "rfc2595.txt' to='{0}'>" )
    XMPP_STARTTLS = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
    
        
    def set_xmpp_to(self, xmpp_to):
        self._xmpp_to = xmpp_to


    def do_pre_handshake(self):
        """
        Connect to a host on a given (SSL) port, send a STARTTLS command,
        and perform the SSL handshake.
        """ 
        # Open an XMPP stream            
        self._sock = socket.create_connection((self._host, self._port), self._timeout)
        self._sock.send(self.XMPP_OPEN_STREAM.format(self._xmpp_to))
        if '<stream:error>' in self._sock.recv(2048):
            raise StartTLSError(self.ERR_XMPP_REJECTED)
            
        # Send a STARTTLS message
        self._sock.send(self.XMPP_STARTTLS)
        xmpp_resp = self._sock.recv(2048)
        if 'proceed'  not in xmpp_resp: 
            raise StartTLSError(self.ERR_NO_XMPP_STARTTLS)



class LDAPConnection(SSLConnection):
    """SSL connection class that performs an LDAP StartTLS negotiation
    before the SSL handshake."""
    
    ERR_NO_STARTTLS = 'LDAP AUTH TLS was rejected'
    
    START_TLS_CMD = bytearray(b'0\x1d\x02\x01\x01w\x18\x80\x161.3.6.1.4.1.1466.20037')
    START_TLS_OK = 'Start TLS request accepted.'


    def do_pre_handshake(self):
        """
        Connect to a host on a given (SSL) port, send a STARTTLS command,
        and perform the SSL handshake.
        """
        self._sock = socket.create_connection((self._host, self._port), self._timeout)
        
        # Send Start TLS
        self._sock.send(self.START_TLS_CMD)
        if self.START_TLS_OK  not in self._sock.recv(2048):
            raise StartTLSError(self.ERR_NO_STARTTLS)
        


class GenericStartTLSConnection(SSLConnection):
    """SSL connection class that performs a StartTLS negotiation
    before the SSL handshake. Used for POP3, IMAP and FTP."""


    def do_pre_handshake(self):
        """
        Connect to a host on a given (SSL) port, send a STARTTLS command,
        and perform the SSL handshake.
        """
        self._sock = socket.create_connection((self._host, self._port), self._timeout)
        
        # Grab the banner
        self._sock.recv(2048)
                
        # Send Start TLS
        self._sock.send(self.START_TLS_CMD)
        if self.START_TLS_OK  not in self._sock.recv(2048):
            raise StartTLSError(self.ERR_NO_STARTTLS)
        
        
        
class IMAPConnection(GenericStartTLSConnection):
    """SSL connection class that performs an IMAP StartTLS negotiation
    before the SSL handshake."""

    ERR_NO_STARTTLS = 'IMAP START TLS was rejected'

    START_TLS_CMD = '. STARTTLS\r\n'
    START_TLS_OK = '. OK'



class POP3Connection(GenericStartTLSConnection):
    """SSL connection class that performs a POP3 StartTLS negotiation
    before the SSL handshake."""

    ERR_NO_STARTTLS = 'POP START TLS was rejected'

    START_TLS_CMD = 'STLS\r\n'
    START_TLS_OK = '+OK'



class FTPConnection(GenericStartTLSConnection):
    """SSL connection class that performs an FTP StartTLS negotiation
    before the SSL handshake."""
    
    ERR_NO_STARTTLS = 'FTP AUTH TLS was rejected'

    START_TLS_CMD = 'AUTH TLS\r\n'
    START_TLS_OK = '234'


