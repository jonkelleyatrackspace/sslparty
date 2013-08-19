import ssl2json # Rename this module to ssl2dict actually
import json

class pullreport(object):
    """ This class is a wrapper for the ssl2json fork of sslyze. This should probably be refactored to a more generalized wrapper that works differently
        but this slower method will probably be acceptable for life. Who oughta need more then 640k mem?  -jonk
    """
    def __init__(self,target_list=None,shared_settings=None):
        self.outdict = ssl2json.get(target_list,shared_settings)['document']

    def get_dict(self):
        return self.outdict
    def get_dictbyhost(self):
        """ Builds a dict per domain as key """
        coreresultdict = self.get_dict()['results']['target']
        failedresultdict = self.get_dict()['invalidTargets']
        finalobject = {} # Final return
        i = 0
        for res in coreresultdict:
            hostport = res['@host']+':'+res['@port']
            finalobject[hostport] = coreresultdict[i]
            i += 1

        for item in failedresultdict['invalidTarget']: # Scoop up domains in error state and add error dict.
           finalobject[item['#text']] = { 'error' : item['@error'] }

        return finalobject
    def _get_epoch_from_ssltime(self,sslstamp):
        """ Takes SSL stamp from SSL library and simply returns a unix epoch
        Private method.
        """
        import ssl
        return int(ssl.cert_time_to_seconds(sslstamp))
    def build_report(self):

        """ Returns a dict { 'notBefore' : '', 'notAfter' : '' }
        """
        import time
        coreresultdict = self.get_dict()['results']['target']
        failedresultdict = self.get_dict()['invalidTargets']
        finalobject = {} # Final return
        for res in coreresultdict:
            hostport = res['@host']+':'+res['@port']
            finalobject[hostport] = {}
            
            finalobject[hostport]['ipAddr'] = res['@ip']
            
            # BUILDS REPORT FOR SSL VALIDITY
            validNotBefore = res['certinfo']['certificate']['validity']['notBefore']
            validNotAfter = res['certinfo']['certificate']['validity']['notAfter']
            valid = "False"
            timeNow = int(time.time())
            if self._get_epoch_from_ssltime(validNotBefore) <= timeNow:
                valid = "True"
            if self._get_epoch_from_ssltime(validNotAfter) >= timeNow:
                valid = "True"

            expiresin = int(self._get_epoch_from_ssltime(validNotAfter) - time.time())
            expiresindays = expiresin / 86400
            finalobject[hostport]['certValidity'] = {
                'daysUntilExpire' : expiresindays,
                'validForNow' : valid ,
                'dateRange' : {
                                "validNotBefore" : { 'stamp' : validNotBefore, 'epoch' : self._get_epoch_from_ssltime(validNotBefore) } , 
                                'validNotAfter' : { 'stamp' : validNotAfter, 'epoch' : self._get_epoch_from_ssltime(validNotAfter) } ,
                            },
                }
            
            # Trustworthyness
            doesCertMatchHostname = "False"
            if res['certinfo']['certificate']['subject']['commonName'] == res['@host']:
                doesCertMatchHostname = "True"
            finalobject[hostport]['certReputation'] = {
                'certMatchesHostname' : doesCertMatchHostname,
                'extendedValidation' : res['certinfo']['certificate']['@isExtendedValidation'] ,
                'mozillaTrust' : { 'trusted' : res['certinfo']['certificate']['@isTrustedByMozillaCAStore'] , 
                                    'whyNotMessage' : res['certinfo']['certificate']['@reasonWhyNotTrusted'] }
            }

            # Frivilous Data
            sha1                = res['certinfo']['certificate']['@sha1Fingerprint']
            serialNumber        = cryptoKeyLen = res['certinfo']['certificate']['serialNumber']
            certVersion         = res['certinfo']['certificate']['version']
            cryptoAlgorythm     = res['certinfo']['certificate']['subjectPublicKeyInfo']['publicKeyAlgorithm']
            cryptoKeyLen        = res['certinfo']['certificate']['subjectPublicKeyInfo']['publicKeySize']
            issuerCN            = res['certinfo']['certificate']['issuer']['commonName']
            subject             = res['certinfo']['certificate']['subject']
            finalobject[hostport]['certFields'] = {
                'sha1' : sha1,
                'serial' : serialNumber,
                'version' : certVersion,
                'crypto' : { 'algorythm' : cryptoAlgorythm, 
                             'keylen' : cryptoKeyLen  },
                 'issuer' : issuerCN,
            }

        # Failed item report.
        for item in failedresultdict['invalidTarget']: # Scoop up domains in error state and add error dict.
           finalobject[item['#text']] = { 'error' : item['@error'] }

        return finalobject



target_list = ['aolsss.com:80','aolsss.com:81','www.pcwebshop.co.uk','identity.api.rackspacecloud.com:443','manage.rackspacecloud.com:443','google.com:443']
shared_settings = {
        'certinfo':     'full',        'starttls':     None,       'resum':        None,
        'resum_rate':   None,           'http_get':     None,       'xml_file':     '/tmp/xy', 
        'compression':  None,           'tlsv1':        None,       'targets_in':   None, 
        'cert':         None,           'https_tunnel_port': None,  'keyform':      1, 
        'hsts':         None,           'sslv3':        None,       'sslv2':        None, 
        'https_tunnel': None,           'sni':          None,       'https_tunnel_host': None, 
        'regular':      None,           'key':          None,       'reneg':        None, 
        'tlsv1_2':      None,           'tlsv1_1':      None,       'hide_rejected_ciphers': None,
        'keypass':      '',             'nb_processes': 1,          'certform':     1, 
        'timeout':      5,              'xmpp_to':      None}



sslvalidator = pullreport(target_list,shared_settings)
instdict = sslvalidator.get_dict()
        
        
buildTempl = {} # Represents the 


import json

print "GET EXPIRE TIMES"
print json.dumps(sslvalidator.build_report(), indent=4)




"""
{
   "@MyPurpose": "To send you a dictionary with json back. Cool huh?", 
   "@SSLyzeVersion": "ohai v0.1 (SSLyze_v0.7)", 
   "@SSLyzeWeb": "https://github.com/jonkelleyatrackspace/sslyze", 
   "@title": "SSLyze Scan Results", 
   "invalidTargets": null, 
   "results": {
      "@defaultTimeout": "5", 
      "@httpsTunnel": "None", 
      "@startTLS": "None", 
      "@totalScanTime": "1.22882795334", 
      "target": [
         {
            "@host": "google.com", 
            "@ip": "74.125.227.7", 
            "@port": "443", 
            "certinfo": {
               "@argument": "full", 
               "@title": "Certificate", 
               "certificate": {
                  "@hasMatchingHostname": "True", 
                  "@isExtendedValidation": "False", 
                  "@isTrustedByMozillaCAStore": "True", 
                  "@reasonWhyNotTrusted": "ok", 
                  "@sha1Fingerprint": "39dc179fc4dc6732e2025ab9c418d79d4e1c6e94", 
                  "asPEM": "-----BEGIN CERTIFICATE-----\nMIIGKjCCBZOgAwIBAgIKEiIxuQABAACSsTANBgkqhkiG9w0BAQUFADBGMQswCQYD\nVQQGEwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzEiMCAGA1UEAxMZR29vZ2xlIElu\ndGVybmV0IEF1dGhvcml0eTAeFw0xMzA3MzExMTQwMzRaFw0xMzEwMzEyMzU5NTla\nMGYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1N\nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgSW5jMRUwEwYDVQQDFAwqLmdv\nb2dsZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAL+RiEjTLckQO7tb\nT9lIFriDh3P+zkRJNWxZYuRnwKcJadgN9pMaf1taf2HkjrskArM1QIANnOPOByvA\nJp4HYr6NJLD2OPOvLvYv98qLdkKTKjt/b2H6axfGiJY6g9QfQtc81zc/tL51vknz\nvSGaqOsAeJ0SO9SldqM7X/lDYkfTAgMBAAGjggP9MIID+TAdBgNVHSUEFjAUBggr\nBgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFD0slhILWX0Vi0EOxThOwOUUqKcJ\nMB8GA1UdIwQYMBaAFL/AMOv1QxE+Z7qekfv8atrjaxIkMFsGA1UdHwRUMFIwUKBO\noEyGSmh0dHA6Ly93d3cuZ3N0YXRpYy5jb20vR29vZ2xlSW50ZXJuZXRBdXRob3Jp\ndHkvR29vZ2xlSW50ZXJuZXRBdXRob3JpdHkuY3JsMGYGCCsGAQUFBwEBBFowWDBW\nBggrBgEFBQcwAoZKaHR0cDovL3d3dy5nc3RhdGljLmNvbS9Hb29nbGVJbnRlcm5l\ndEF1dGhvcml0eS9Hb29nbGVJbnRlcm5ldEF1dGhvcml0eS5jcnQwDAYDVR0TAQH/\nBAIwADCCAsMGA1UdEQSCArowggK2ggwqLmdvb2dsZS5jb22CDSouYW5kcm9pZC5j\nb22CFiouYXBwZW5naW5lLmdvb2dsZS5jb22CEiouY2xvdWQuZ29vZ2xlLmNvbYIW\nKi5nb29nbGUtYW5hbHl0aWNzLmNvbYILKi5nb29nbGUuY2GCCyouZ29vZ2xlLmNs\ngg4qLmdvb2dsZS5jby5pboIOKi5nb29nbGUuY28uanCCDiouZ29vZ2xlLmNvLnVr\ngg8qLmdvb2dsZS5jb20uYXKCDyouZ29vZ2xlLmNvbS5hdYIPKi5nb29nbGUuY29t\nLmJygg8qLmdvb2dsZS5jb20uY2+CDyouZ29vZ2xlLmNvbS5teIIPKi5nb29nbGUu\nY29tLnRygg8qLmdvb2dsZS5jb20udm6CCyouZ29vZ2xlLmRlggsqLmdvb2dsZS5l\nc4ILKi5nb29nbGUuZnKCCyouZ29vZ2xlLmh1ggsqLmdvb2dsZS5pdIILKi5nb29n\nbGUubmyCCyouZ29vZ2xlLnBsggsqLmdvb2dsZS5wdIIPKi5nb29nbGVhcGlzLmNu\nghQqLmdvb2dsZWNvbW1lcmNlLmNvbYINKi5nc3RhdGljLmNvbYIMKi51cmNoaW4u\nY29tghAqLnVybC5nb29nbGUuY29tghYqLnlvdXR1YmUtbm9jb29raWUuY29tgg0q\nLnlvdXR1YmUuY29tghYqLnlvdXR1YmVlZHVjYXRpb24uY29tggsqLnl0aW1nLmNv\nbYILYW5kcm9pZC5jb22CBGcuY2+CBmdvby5nbIIUZ29vZ2xlLWFuYWx5dGljcy5j\nb22CCmdvb2dsZS5jb22CEmdvb2dsZWNvbW1lcmNlLmNvbYIKdXJjaGluLmNvbYII\neW91dHUuYmWCC3lvdXR1YmUuY29tghR5b3V0dWJlZWR1Y2F0aW9uLmNvbTANBgkq\nhkiG9w0BAQUFAAOBgQClna2RVEEVPusOayhKQ0/JUSBkvL8TflvmgIL/L/4SXsPy\nAxcOwHBv0vfyX8cos1thOkyuSHEbuKqANW9BESg9dmqYWIG6hSWcVkbsqiaDS1CI\nkO1nUjlwRJ+udBYcQPy8yBgJhTQ/76rRYyXoiTHr5SoV25gQrSFcWUSEum9C5Q==\n-----END CERTIFICATE-----", 
                  "subjectPublicKeyInfo": {
                     "publicKey": {
                        "modulus": "00:bf:91:88:48:d3:2d:c9:10:3b:bb:5b:4f:d9:48:16:b8:83:87:73:fe:ce:44:49:35:6c:59:62:e4:67:c0:a7:09:69:d8:0d:f6:93:1a:7f:5b:5a:7f:61:e4:8e:bb:24:02:b3:35:40:80:0d:9c:e3:ce:07:2b:c0:26:9e:07:62:be:8d:24:b0:f6:38:f3:af:2e:f6:2f:f7:ca:8b:76:42:93:2a:3b:7f:6f:61:fa:6b:17:c6:88:96:3a:83:d4:1f:42:d7:3c:d7:37:3f:b4:be:75:be:49:f3:bd:21:9a:a8:eb:00:78:9d:12:3b:d4:a5:76:a3:3b:5f:f9:43:62:47:d3", 
                        "exponent": "65537"
                     }, 
                     "publicKeyAlgorithm": "rsaEncryption", 
                     "publicKeySize": "1024 bit"
                  }, 
                  "version": "2", 
                  "extensions": {
                     "X509v3SubjectKeyIdentifier": "3D:2C:96:12:0B:59:7D:15:8B:41:0E:C5:38:4E:C0:E5:14:A8:A7:09", 
                     "X509v3ExtendedKeyUsage": {
                        "TLSWebClientAuthentication": null, 
                        "TLSWebServerAuthentication": null
                     }, 
                     "AuthorityInformationAccess": {
                        "CAIssuers": {
                           "URI": {
                              "listEntry": "http://www.gstatic.com/GoogleInternetAuthority/GoogleInternetAuthority.crt"
                           }
                        }
                     }, 
                     "X509v3CRLDistributionPoints": {
                        "FullName": {
                           "listEntry": null
                        }, 
                        "URI": {
                           "listEntry": "http://www.gstatic.com/GoogleInternetAuthority/GoogleInternetAuthority.crl"
                        }
                     }, 
                     "X509v3BasicConstraints": "CA:FALSE", 
                     "X509v3SubjectAlternativeName": {
                        "DNS": {
                           "listEntry": [
                              "*.google.com", 
                              "*.android.com", 
                              "*.appengine.google.com", 
                              "*.cloud.google.com", 
                              "*.google-analytics.com", 
                              "*.google.ca", 
                              "*.google.cl", 
                              "*.google.co.in", 
                              "*.google.co.jp", 
                              "*.google.co.uk", 
                              "*.google.com.ar", 
                              "*.google.com.au", 
                              "*.google.com.br", 
                              "*.google.com.co", 
                              "*.google.com.mx", 
                              "*.google.com.tr", 
                              "*.google.com.vn", 
                              "*.google.de", 
                              "*.google.es", 
                              "*.google.fr", 
                              "*.google.hu", 
                              "*.google.it", 
                              "*.google.nl", 
                              "*.google.pl", 
                              "*.google.pt", 
                              "*.googleapis.cn", 
                              "*.googlecommerce.com", 
                              "*.gstatic.com", 
                              "*.urchin.com", 
                              "*.url.google.com", 
                              "*.youtube-nocookie.com", 
                              "*.youtube.com", 
                              "*.youtubeeducation.com", 
                              "*.ytimg.com", 
                              "android.com", 
                              "g.co", 
                              "goo.gl", 
                              "google-analytics.com", 
                              "google.com", 
                              "googlecommerce.com", 
                              "urchin.com", 
                              "youtu.be", 
                              "youtube.com", 
                              "youtubeeducation.com"
                           ]
                        }
                     }, 
                     "X509v3AuthorityKeyIdentifier": "keyid:BF:C0:30:EB:F5:43:11:3E:67:BA:9E:91:FB:FC:6A:DA:E3:6B:12:24"
                  }, 
                  "signatureValue": "a5:9d:ad:91:54:41:15:3e:eb:0e:6b:28:4a:43:4f:c9:51:20:64:bc:bf:13:7e:5b:e6:80:82:ff:2f:fe:12:5e:c3:f2:03:17:0e:c0:70:6f:d2:f7:f2:5f:c7:28:b3:5b:61:3a:4c:ae:48:71:1b:b8:aa:80:35:6f:41:11:28:3d:76:6a:98:58:81:ba:85:25:9c:56:46:ec:aa:26:83:4b:50:88:90:ed:67:52:39:70:44:9f:ae:74:16:1c:40:fc:bc:c8:18:09:85:34:3f:ef:aa:d1:63:25:e8:89:31:eb:e5:2a:15:db:98:10:ad:21:5c:59:44:84:ba:6f:42:e5", 
                  "signatureAlgorithm": "sha1WithRSAEncryption", 
                  "serialNumber": "122231B90001000092B1", 
                  "subject": {
                     "countryName": "US", 
                     "commonName": "*.google.com", 
                     "organizationName": "Google Inc", 
                     "localityName": "Mountain View", 
                     "stateOrProvinceName": "California"
                  }, 
                  "validity": {
                     "notAfter": "Oct 31 23:59:59 2013 GMT", 
                     "notBefore": "Jul 31 11:40:34 2013 GMT"
                  }, 
                  "issuer": {
                     "countryName": "US", 
                     "commonName": "Google Internet Authority", 
                     "organizationName": "Google Inc"
                  }
               }, 
               "ocspStapling": {
                  "@error": "Server did not send back an OCSP response"
               }
            }
         }, 
         {
            "@host": "identity.api.rackspacecloud.com", 
            "@ip": "72.3.138.129", 
            "@port": "443", 
            "certinfo": {
               "@argument": "full", 
               "@title": "Certificate", 
               "certificate": {
                  "@hasMatchingHostname": "False", 
                  "@isExtendedValidation": "False", 
                  "@isTrustedByMozillaCAStore": "True", 
                  "@reasonWhyNotTrusted": "ok", 
                  "@sha1Fingerprint": "5b7fa3290dc992f21a0ce5962dc5d2548b868de3", 
                  "asPEM": "-----BEGIN CERTIFICATE-----\nMIIEWjCCA0KgAwIBAgIQLFXkvd/ICT26gEgT36jh0TANBgkqhkiG9w0BAQUFADBe\nMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMVGhhd3RlLCBJbmMuMR0wGwYDVQQLExRE\nb21haW4gVmFsaWRhdGVkIFNTTDEZMBcGA1UEAxMQVGhhd3RlIERWIFNTTCBDQTAe\nFw0xMTExMTQwMDAwMDBaFw0xNjExMTIyMzU5NTlaMIHQMSgwJgYDVQQKFB9pZGVu\ndGl0eS5hcGkucmFja3NwYWNlY2xvdWQuY29tMTswOQYDVQQLEzJHbyB0byBodHRw\nczovL3d3dy50aGF3dGUuY29tL3JlcG9zaXRvcnkvaW5kZXguaHRtbDEiMCAGA1UE\nCxMZVGhhd3RlIFNTTDEyMyBjZXJ0aWZpY2F0ZTEZMBcGA1UECxMQRG9tYWluIFZh\nbGlkYXRlZDEoMCYGA1UEAxQfaWRlbnRpdHkuYXBpLnJhY2tzcGFjZWNsb3VkLmNv\nbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ/10+uJIDxCtoknjR0i\nK4/rSVkvUFFEWGQEkAknn8owjUDxLCiqBgP261qascPdXASDVDgQQ+iiv9G/xiOX\nrgKMwc2fnwaZFWg7xFr/F2nVSEdVUrbAhjizstdGcKF3bvpl9N2ke29BWa+iNXIc\nafTzAMYVkKR3BoL5yd4O+SpfXI5yjDLhMDkn/6j7Cy3Qm3PLA6uTeE9aRvsB53C+\nt1tmDmfd9BJV8yKTVcUt7/Bq8ekmmV7vNKFAQ69BTO2IpEGDLDjDs4I7Zcm7SP+i\nYrzeJC6iCmh/j9u0yVx/JrDdp9tfjbn0aQXbqgb7XfNocHyzE6pc+jACsIBQqGya\nQIkCAwEAAaOBoDCBnTAMBgNVHRMBAf8EAjAAMDoGA1UdHwQzMDEwL6AtoCuGKWh0\ndHA6Ly9zdnItZHYtY3JsLnRoYXd0ZS5jb20vVGhhd3RlRFYuY3JsMB0GA1UdJQQW\nMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAyBggrBgEFBQcBAQQmMCQwIgYIKwYBBQUH\nMAGGFmh0dHA6Ly9vY3NwLnRoYXd0ZS5jb20wDQYJKoZIhvcNAQEFBQADggEBAFPv\nYLTAqkcjJSOivymGZW2vsLK4Uor5kWO/2fvq2ZM4JvsTEejw3bhffFzH6KBXdVWE\nTahKjfBxtR3uRn4DE3gF4Udproz2Be/ty6zE87t/XJ2LZ2djFTp0zY5fCqZJdEhr\nb5fpxJAJfxGrINDiqG4arkVgIETS8cUMt44UmPBso35qEQzdyE+nNxGe3kYRT6a+\n/UAkq13xg+QdyCaGQtGbVYdANdCGvKPVDRJcfhlYr30WXYyou28Izcng0aVZM47L\ngz1twTumDKfrtl1AH5it8VNjp5I5/AG/CoV2RNPs7tGYJpd5eQScQoaYtPeJ+Qcy\nB9dczFr512paOEj8KYI=\n-----END CERTIFICATE-----", 
                  "subjectPublicKeyInfo": {
                     "publicKey": {
                        "modulus": "00:9f:f5:d3:eb:89:20:3c:42:b6:89:27:8d:1d:22:2b:8f:eb:49:59:2f:50:51:44:58:64:04:90:09:27:9f:ca:30:8d:40:f1:2c:28:aa:06:03:f6:eb:5a:9a:b1:c3:dd:5c:04:83:54:38:10:43:e8:a2:bf:d1:bf:c6:23:97:ae:02:8c:c1:cd:9f:9f:06:99:15:68:3b:c4:5a:ff:17:69:d5:48:47:55:52:b6:c0:86:38:b3:b2:d7:46:70:a1:77:6e:fa:65:f4:dd:a4:7b:6f:41:59:af:a2:35:72:1c:69:f4:f3:00:c6:15:90:a4:77:06:82:f9:c9:de:0e:f9:2a:5f:5c:8e:72:8c:32:e1:30:39:27:ff:a8:fb:0b:2d:d0:9b:73:cb:03:ab:93:78:4f:5a:46:fb:01:e7:70:be:b7:5b:66:0e:67:dd:f4:12:55:f3:22:93:55:c5:2d:ef:f0:6a:f1:e9:26:99:5e:ef:34:a1:40:43:af:41:4c:ed:88:a4:41:83:2c:38:c3:b3:82:3b:65:c9:bb:48:ff:a2:62:bc:de:24:2e:a2:0a:68:7f:8f:db:b4:c9:5c:7f:26:b0:dd:a7:db:5f:8d:b9:f4:69:05:db:aa:06:fb:5d:f3:68:70:7c:b3:13:aa:5c:fa:30:02:b0:80:50:a8:6c:9a:40:89", 
                        "exponent": "65537"
                     }, 
                     "publicKeyAlgorithm": "rsaEncryption", 
                     "publicKeySize": "2048 bit"
                  }, 
                  "version": "2", 
                  "extensions": {
                     "X509v3CRLDistributionPoints": {
                        "FullName": {
                           "listEntry": null
                        }, 
                        "URI": {
                           "listEntry": "http://svr-dv-crl.thawte.com/ThawteDV.crl"
                        }
                     }, 
                     "X509v3ExtendedKeyUsage": {
                        "TLSWebClientAuthentication": null, 
                        "TLSWebServerAuthentication": null
                     }, 
                     "AuthorityInformationAccess": {
                        "OCSP": {
                           "URI": {
                              "listEntry": "http://ocsp.thawte.com"
                           }
                        }
                     }, 
                     "X509v3BasicConstraints": "CA:FALSE"
                  }, 
                  "signatureValue": "53:ef:60:b4:c0:aa:47:23:25:23:a2:bf:29:86:65:6d:af:b0:b2:b8:52:8a:f9:91:63:bf:d9:fb:ea:d9:93:38:26:fb:13:11:e8:f0:dd:b8:5f:7c:5c:c7:e8:a0:57:75:55:84:4d:a8:4a:8d:f0:71:b5:1d:ee:46:7e:03:13:78:05:e1:47:69:ae:8c:f6:05:ef:ed:cb:ac:c4:f3:bb:7f:5c:9d:8b:67:67:63:15:3a:74:cd:8e:5f:0a:a6:49:74:48:6b:6f:97:e9:c4:90:09:7f:11:ab:20:d0:e2:a8:6e:1a:ae:45:60:20:44:d2:f1:c5:0c:b7:8e:14:98:f0:6c:a3:7e:6a:11:0c:dd:c8:4f:a7:37:11:9e:de:46:11:4f:a6:be:fd:40:24:ab:5d:f1:83:e4:1d:c8:26:86:42:d1:9b:55:87:40:35:d0:86:bc:a3:d5:0d:12:5c:7e:19:58:af:7d:16:5d:8c:a8:bb:6f:08:cd:c9:e0:d1:a5:59:33:8e:cb:83:3d:6d:c1:3b:a6:0c:a7:eb:b6:5d:40:1f:98:ad:f1:53:63:a7:92:39:fc:01:bf:0a:85:76:44:d3:ec:ee:d1:98:26:97:79:79:04:9c:42:86:98:b4:f7:89:f9:07:32:07:d7:5c:cc:5a:f9:d7:6a:5a:38:48:fc:29:82", 
                  "signatureAlgorithm": "sha1WithRSAEncryption", 
                  "serialNumber": "2C55E4BDDFC8093DBA804813DFA8E1D1", 
                  "subject": {
                     "commonName": "identity.api.rackspacecloud.com", 
                     "organizationalUnitName": "Domain Validated", 
                     "organizationName": "identity.api.rackspacecloud.com"
                  }, 
                  "validity": {
                     "notAfter": "Nov 12 23:59:59 2016 GMT", 
                     "notBefore": "Nov 14 00:00:00 2011 GMT"
                  }, 
                  "issuer": {
                     "countryName": "US", 
                     "commonName": "Thawte DV SSL CA", 
                     "organizationalUnitName": "Domain Validated SSL", 
                     "organizationName": "Thawte, Inc."
                  }
               }, 
               "ocspStapling": {
                  "@error": "Server did not send back an OCSP response"
               }
            }
         }, 
         {
            "@host": "manage.rackspacecloud.com", 
            "@ip": "67.192.1.7", 
            "@port": "443", 
            "certinfo": {
               "@argument": "full", 
               "@title": "Certificate", 
               "certificate": {
                  "@hasMatchingHostname": "True", 
                  "@isExtendedValidation": "True", 
                  "@isTrustedByMozillaCAStore": "True", 
                  "@reasonWhyNotTrusted": "ok", 
                  "@sha1Fingerprint": "3ffda03a9ac88bc40f900cba7b9772d7ab35928d", 
                  "asPEM": "-----BEGIN CERTIFICATE-----\nMIIFXDCCBESgAwIBAgIQcK96C5JilortXQKzTOxv/zANBgkqhkiG9w0BAQUFADCB\nizELMAkGA1UEBhMCVVMxFTATBgNVBAoTDHRoYXd0ZSwgSW5jLjE5MDcGA1UECxMw\nVGVybXMgb2YgdXNlIGF0IGh0dHBzOi8vd3d3LnRoYXd0ZS5jb20vY3BzIChjKTA2\nMSowKAYDVQQDEyF0aGF3dGUgRXh0ZW5kZWQgVmFsaWRhdGlvbiBTU0wgQ0EwHhcN\nMTMwNzA1MDAwMDAwWhcNMTUwODA0MjM1OTU5WjCB1TETMBEGCysGAQQBgjc8AgED\nEwJVUzEZMBcGCysGAQQBgjc8AgECFAhEZWxhd2FyZTEdMBsGA1UEDxMUUHJpdmF0\nZSBPcmdhbml6YXRpb24xEDAOBgNVBAUTBzQzNzc2ODcxCzAJBgNVBAYTAlVTMQ4w\nDAYDVQQIFAVUZXhhczEUMBIGA1UEBxQLU2FuIEFudG9uaW8xGzAZBgNVBAoUElJh\nY2tzcGFjZSBVUywgSW5jLjEiMCAGA1UEAxQZbWFuYWdlLnJhY2tzcGFjZWNsb3Vk\nLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN0U9YmB5NNS9iDZ\nR+2zcruIOcta/HIQHxc/q31HyURLq8b0ky78Q1MsVTEZKiN5lnXaB+Lx0sFRZTCU\nUeMaixBajjGRmuoIYwMp+PgrZ07qEAMQsVkEULWqtPTyYZimafMq64QGcnItw3r3\nnYZfJF5BwKPgp0u1w5HllHoF1ViraZlBdAFJs3M26c4LcFtq4Ha2vlX4oTPYX0aG\n0S5jrebPIxYVz3WUFHyl1UKKyd/axfbJyNxAwD5EkBwpWDKWFoBVDlCE33qm/JdN\n9I1zu6xtxne4VvPYJ2LHxOjUOfAfIz4xpRPLT7hw6+d6BIHfJd+2uATXjgmlyTff\nrxDITE0CAwEAAaOCAW4wggFqMCQGA1UdEQQdMBuCGW1hbmFnZS5yYWNrc3BhY2Vj\nbG91ZC5jb20wCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCBaAwOQYDVR0fBDIwMDAu\noCygKoYoaHR0cDovL2NybC50aGF3dGUuY29tL1RoYXd0ZUVWQ0EyMDA2LmNybDBC\nBgNVHSAEOzA5MDcGC2CGSAGG+EUBBzABMCgwJgYIKwYBBQUHAgEWGmh0dHBzOi8v\nd3d3LnRoYXd0ZS5jb20vY3BzMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD\nAjAfBgNVHSMEGDAWgBTNMuLyXSVHAqqPeUsy7gOZ/TBJ0TBoBggrBgEFBQcBAQRc\nMFowIgYIKwYBBQUHMAGGFmh0dHA6Ly9vY3NwLnRoYXd0ZS5jb20wNAYIKwYBBQUH\nMAKGKGh0dHA6Ly9jcmwudGhhd3RlLmNvbS9UaGF3dGVFVkNBMjAwNi5jZXIwDQYJ\nKoZIhvcNAQEFBQADggEBALL3Dl1pDrFxhwkR3h3664/Cp+RAAu/f2Tf8UHSw/K9v\nmfs3n8FJDAe/X5RZjmQsHGyVMMa1LOEtZmnyM3IWLG7Vi6gFe7PdB7MRbf4jllg3\nLwMncFkcMDUY0bt9dQnWdWUiEyzCP9c+rnzz9z8st+lS28vKTcGW4XIi1OBv5n1+\nMgiIJPAJGg6B0LZ21TdgY/vj/AhdJET/QcYkrwxGx/iHTkW/shUONVMo94FcQmMO\nsB1kn0loXhDVXRCIvn0nSdI6JGNi+jtJc1HpaKt3Dt1iGezcKhQxFfFXD4pyO59e\nBLGZ+1IR7E5pSd+1oXMX7qDLbta2aHCFYSM2zjqNC8w=\n-----END CERTIFICATE-----", 
                  "subjectPublicKeyInfo": {
                     "publicKey": {
                        "modulus": "00:dd:14:f5:89:81:e4:d3:52:f6:20:d9:47:ed:b3:72:bb:88:39:cb:5a:fc:72:10:1f:17:3f:ab:7d:47:c9:44:4b:ab:c6:f4:93:2e:fc:43:53:2c:55:31:19:2a:23:79:96:75:da:07:e2:f1:d2:c1:51:65:30:94:51:e3:1a:8b:10:5a:8e:31:91:9a:ea:08:63:03:29:f8:f8:2b:67:4e:ea:10:03:10:b1:59:04:50:b5:aa:b4:f4:f2:61:98:a6:69:f3:2a:eb:84:06:72:72:2d:c3:7a:f7:9d:86:5f:24:5e:41:c0:a3:e0:a7:4b:b5:c3:91:e5:94:7a:05:d5:58:ab:69:99:41:74:01:49:b3:73:36:e9:ce:0b:70:5b:6a:e0:76:b6:be:55:f8:a1:33:d8:5f:46:86:d1:2e:63:ad:e6:cf:23:16:15:cf:75:94:14:7c:a5:d5:42:8a:c9:df:da:c5:f6:c9:c8:dc:40:c0:3e:44:90:1c:29:58:32:96:16:80:55:0e:50:84:df:7a:a6:fc:97:4d:f4:8d:73:bb:ac:6d:c6:77:b8:56:f3:d8:27:62:c7:c4:e8:d4:39:f0:1f:23:3e:31:a5:13:cb:4f:b8:70:eb:e7:7a:04:81:df:25:df:b6:b8:04:d7:8e:09:a5:c9:37:df:af:10:c8:4c:4d", 
                        "exponent": "65537"
                     }, 
                     "publicKeyAlgorithm": "rsaEncryption", 
                     "publicKeySize": "2048 bit"
                  }, 
                  "version": "2", 
                  "extensions": {
                     "X509v3ExtendedKeyUsage": {
                        "TLSWebClientAuthentication": null, 
                        "TLSWebServerAuthentication": null
                     }, 
                     "AuthorityInformationAccess": {
                        "CAIssuers": {
                           "URI": {
                              "listEntry": "http://crl.thawte.com/ThawteEVCA2006.cer"
                           }
                        }, 
                        "OCSP": {
                           "URI": {
                              "listEntry": "http://ocsp.thawte.com"
                           }
                        }
                     }, 
                     "X509v3CRLDistributionPoints": {
                        "FullName": {
                           "listEntry": null
                        }, 
                        "URI": {
                           "listEntry": "http://crl.thawte.com/ThawteEVCA2006.crl"
                        }
                     }, 
                     "X509v3BasicConstraints": "CA:FALSE", 
                     "X509v3KeyUsage": {
                        "KeyEncipherment": null, 
                        "DigitalSignature": null
                     }, 
                     "X509v3SubjectAlternativeName": {
                        "DNS": {
                           "listEntry": "manage.rackspacecloud.com"
                        }
                     }, 
                     "X509v3AuthorityKeyIdentifier": "keyid:CD:32:E2:F2:5D:25:47:02:AA:8F:79:4B:32:EE:03:99:FD:30:49:D1", 
                     "X509v3CertificatePolicies": {
                        "Policy": {
                           "listEntry": "2.16.840.1.113733.1.7.48.1"
                        }, 
                        "CPS": {
                           "listEntry": "https://www.thawte.com/cps"
                        }
                     }
                  }, 
                  "signatureValue": "b2:f7:0e:5d:69:0e:b1:71:87:09:11:de:1d:fa:eb:8f:c2:a7:e4:40:02:ef:df:d9:37:fc:50:74:b0:fc:af:6f:99:fb:37:9f:c1:49:0c:07:bf:5f:94:59:8e:64:2c:1c:6c:95:30:c6:b5:2c:e1:2d:66:69:f2:33:72:16:2c:6e:d5:8b:a8:05:7b:b3:dd:07:b3:11:6d:fe:23:96:58:37:2f:03:27:70:59:1c:30:35:18:d1:bb:7d:75:09:d6:75:65:22:13:2c:c2:3f:d7:3e:ae:7c:f3:f7:3f:2c:b7:e9:52:db:cb:ca:4d:c1:96:e1:72:22:d4:e0:6f:e6:7d:7e:32:08:88:24:f0:09:1a:0e:81:d0:b6:76:d5:37:60:63:fb:e3:fc:08:5d:24:44:ff:41:c6:24:af:0c:46:c7:f8:87:4e:45:bf:b2:15:0e:35:53:28:f7:81:5c:42:63:0e:b0:1d:64:9f:49:68:5e:10:d5:5d:10:88:be:7d:27:49:d2:3a:24:63:62:fa:3b:49:73:51:e9:68:ab:77:0e:dd:62:19:ec:dc:2a:14:31:15:f1:57:0f:8a:72:3b:9f:5e:04:b1:99:fb:52:11:ec:4e:69:49:df:b5:a1:73:17:ee:a0:cb:6e:d6:b6:68:70:85:61:23:36:ce:3a:8d:0b:cc", 
                  "signatureAlgorithm": "sha1WithRSAEncryption", 
                  "serialNumber": "70AF7A0B9262968AED5D02B34CEC6FFF", 
                  "subject": {
                     "organizationName": "Rackspace US, Inc.", 
                     "businessCategory": "Private Organization", 
                     "serialNumber": "4377687", 
                     "commonName": "manage.rackspacecloud.com", 
                     "stateOrProvinceName": "Texas", 
                     "countryName": "US", 
                     "oid-1.3.6.1.4.1.311.60.2.1.2": "Delaware", 
                     "oid-1.3.6.1.4.1.311.60.2.1.3": "US", 
                     "localityName": "San Antonio"
                  }, 
                  "validity": {
                     "notAfter": "Aug  4 23:59:59 2015 GMT", 
                     "notBefore": "Jul  5 00:00:00 2013 GMT"
                  }, 
                  "issuer": {
                     "countryName": "US", 
                     "commonName": "thawte Extended Validation SSL CA", 
                     "organizationalUnitName": "Terms of use at https://www.thawte.com/cps (c)06", 
                     "organizationName": "thawte, Inc."
                  }
               }, 
               "ocspStapling": {
                  "@error": "Server did not send back an OCSP response"
               }
            }
         }, 
         {
            "@host": "www.pcwebshop.co.uk", 
            "@ip": "217.160.239.225", 
            "@port": "443", 
            "certinfo": {
               "@argument": "full", 
               "@title": "Certificate", 
               "certificate": {
                  "@hasMatchingHostname": "False", 
                  "@isExtendedValidation": "False", 
                  "@isTrustedByMozillaCAStore": "False", 
                  "@reasonWhyNotTrusted": "self signed certificate", 
                  "@sha1Fingerprint": "fd71ad430da8eff3cd442f706953fe93c3c897b1", 
                  "asPEM": "-----BEGIN CERTIFICATE-----\nMIIDszCCApsCBE6TRmYwDQYJKoZIhvcNAQEFBQAwgZ0xCzAJBgNVBAYTAlVTMREw\nDwYDVQQIEwhWaXJnaW5pYTEQMA4GA1UEBxMHSGVybmRvbjESMBAGA1UEChMJUGFy\nYWxsZWxzMRgwFgYDVQQLEw9QYXJhbGxlbHMgUGFuZWwxGDAWBgNVBAMTD1BhcmFs\nbGVscyBQYW5lbDEhMB8GCSqGSIb3DQEJARYSaW5mb0BwYXJhbGxlbHMuY29tMB4X\nDTExMTAxMDE5MjQyMloXDTEyMTAwOTE5MjQyMlowgZ0xCzAJBgNVBAYTAlVTMREw\nDwYDVQQIEwhWaXJnaW5pYTEQMA4GA1UEBxMHSGVybmRvbjESMBAGA1UEChMJUGFy\nYWxsZWxzMRgwFgYDVQQLEw9QYXJhbGxlbHMgUGFuZWwxGDAWBgNVBAMTD1BhcmFs\nbGVscyBQYW5lbDEhMB8GCSqGSIb3DQEJARYSaW5mb0BwYXJhbGxlbHMuY29tMIIB\nIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyVBD6pKOtmZAOTDyvP/LIdGP\nVRG5ImXexVTnWe56JYiJ8VFppQa1nDhFNCfploUvR9nEdyv9XIFeMlcdqndU/nCn\nQAZtTw7PhXL80obKZNIAQPWKZmzEARgPmq7+Oe2xZOvbw7Ah9htZ+U7vJNml6ivM\n5urmhv/Bm6YOdtkCAriUTZB5HEOpF3XYQMRX0KhC30vMztrf9PY9ACcmVvs3TIQQ\nGmvFyxFCBjdIVBIaGQ3hjqMkVFyYno++Nji9VLD7FtNl8NpRXxqhUnpsVXHJmSl9\nhoR2BhHwGfJOn+hXg5M4IlcvU51Zlr+LS/0fUfgIMYnOwmlg7LSBPD7mwMqN/QID\nAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBzsJCJg5I/bNFvPs+wNd2pnoI5tDMFYBEV\nxn+hENo7J2wtG1WTH854rwDwUuo8wVKFMSKCgu5XBSGicmfLyeBd5csJRzyh0csh\nHAanBrO7P2ne6sd154z+uDgztE0JvEcdtDhpp4UQCAd8qz1e/pfVPdHI7/Oem1kM\nZwPs0kWf8wDRBFtnU1UaKHd3lBWMDqNLMoyhUapN+q2R0FryCo5W8AquAeYLVJUS\nhSm5Otf3oje8ozKFDD217SAqf9bccxnGMgZ0vlrBWlpHCu4GIROqNIADM30nKze7\nPQKF1NdqU41oii6YMNMqwoH5j0w4Uy+KLx+PEHeFlFu5oMwsQVPs\n-----END CERTIFICATE-----", 
                  "subjectPublicKeyInfo": {
                     "publicKey": {
                        "modulus": "00:c9:50:43:ea:92:8e:b6:66:40:39:30:f2:bc:ff:cb:21:d1:8f:55:11:b9:22:65:de:c5:54:e7:59:ee:7a:25:88:89:f1:51:69:a5:06:b5:9c:38:45:34:27:e9:96:85:2f:47:d9:c4:77:2b:fd:5c:81:5e:32:57:1d:aa:77:54:fe:70:a7:40:06:6d:4f:0e:cf:85:72:fc:d2:86:ca:64:d2:00:40:f5:8a:66:6c:c4:01:18:0f:9a:ae:fe:39:ed:b1:64:eb:db:c3:b0:21:f6:1b:59:f9:4e:ef:24:d9:a5:ea:2b:cc:e6:ea:e6:86:ff:c1:9b:a6:0e:76:d9:02:02:b8:94:4d:90:79:1c:43:a9:17:75:d8:40:c4:57:d0:a8:42:df:4b:cc:ce:da:df:f4:f6:3d:00:27:26:56:fb:37:4c:84:10:1a:6b:c5:cb:11:42:06:37:48:54:12:1a:19:0d:e1:8e:a3:24:54:5c:98:9e:8f:be:36:38:bd:54:b0:fb:16:d3:65:f0:da:51:5f:1a:a1:52:7a:6c:55:71:c9:99:29:7d:86:84:76:06:11:f0:19:f2:4e:9f:e8:57:83:93:38:22:57:2f:53:9d:59:96:bf:8b:4b:fd:1f:51:f8:08:31:89:ce:c2:69:60:ec:b4:81:3c:3e:e6:c0:ca:8d:fd", 
                        "exponent": "65537"
                     }, 
                     "publicKeyAlgorithm": "rsaEncryption", 
                     "publicKeySize": "2048 bit"
                  }, 
                  "version": "0", 
                  "extensions": null, 
                  "signatureValue": "73:b0:90:89:83:92:3f:6c:d1:6f:3e:cf:b0:35:dd:a9:9e:82:39:b4:33:05:60:11:15:c6:7f:a1:10:da:3b:27:6c:2d:1b:55:93:1f:ce:78:af:00:f0:52:ea:3c:c1:52:85:31:22:82:82:ee:57:05:21:a2:72:67:cb:c9:e0:5d:e5:cb:09:47:3c:a1:d1:cb:21:1c:06:a7:06:b3:bb:3f:69:de:ea:c7:75:e7:8c:fe:b8:38:33:b4:4d:09:bc:47:1d:b4:38:69:a7:85:10:08:07:7c:ab:3d:5e:fe:97:d5:3d:d1:c8:ef:f3:9e:9b:59:0c:67:03:ec:d2:45:9f:f3:00:d1:04:5b:67:53:55:1a:28:77:77:94:15:8c:0e:a3:4b:32:8c:a1:51:aa:4d:fa:ad:91:d0:5a:f2:0a:8e:56:f0:0a:ae:01:e6:0b:54:95:12:85:29:b9:3a:d7:f7:a2:37:bc:a3:32:85:0c:3d:b5:ed:20:2a:7f:d6:dc:73:19:c6:32:06:74:be:5a:c1:5a:5a:47:0a:ee:06:21:13:aa:34:80:03:33:7d:27:2b:37:bb:3d:02:85:d4:d7:6a:53:8d:68:8a:2e:98:30:d3:2a:c2:81:f9:8f:4c:38:53:2f:8a:2f:1f:8f:10:77:85:94:5b:b9:a0:cc:2c:41:53:ec", 
                  "signatureAlgorithm": "sha1WithRSAEncryption", 
                  "serialNumber": "4E934666", 
                  "subject": {
                     "organizationalUnitName": "Parallels Panel", 
                     "organizationName": "Parallels", 
                     "commonName": "Parallels Panel", 
                     "stateOrProvinceName": "Virginia", 
                     "countryName": "US", 
                     "emailAddress": "info@parallels.com", 
                     "localityName": "Herndon"
                  }, 
                  "validity": {
                     "notAfter": "Oct  9 19:24:22 2012 GMT", 
                     "notBefore": "Oct 10 19:24:22 2011 GMT"
                  }, 
                  "issuer": {
                     "organizationalUnitName": "Parallels Panel", 
                     "organizationName": "Parallels", 
                     "commonName": "Parallels Panel", 
                     "stateOrProvinceName": "Virginia", 
                     "countryName": "US", 
                     "emailAddress": "info@parallels.com", 
                     "localityName": "Herndon"
                  }
               }, 
               "ocspStapling": {
                  "@error": "Server did not send back an OCSP response"
               }
            }
         }
      ]
   }
}
"""
"""     
        buildreturn['resultsList'] = {}
        for result in od['results']['target']:
            host = result['@host']+result['@port']
            buildreturn['resulsList'][host] = {}
            #### COMMON DATAS
            buildreturn['resultsList'][host]['commonName'] = result['certinfo']['certificate']['subject']['commonName'] #commoname

            #### VALIDITY DATAS
            # The .replace("*.*,"") was tacked on to replace wildcard certs beginning with *. with nothing, so
            #   it matches the actual socket connect host, and validates to true.
            if result['certinfo']['certificate']['subject']['commonName'].replace("*.", "") == result['@host']:
                buildreturn['resultsList'][host]['hasMatchingHostname']     = True # host name match
            else:
                buildreturn['resultsList'][host]['hasMatchingHostname']     = False # host name not match
            buildreturn['resultsList'][host]['isExtendedValidation']        = result['certinfo']['certificate']['@isExtendedValidation']
            buildreturn['resultsList'][host]['isTrustedByMozillaCAStore']   = result['certinfo']['certificate']['@isTrustedByMozillaCAStore']
            buildreturn['resultsList'][host]['reasonWhyNotTrusted']         = result['certinfo']['certificate']['@reasonWhyNotTrusted']
            
            #### FINGERPRINT DATAS
            buildreturn['resultsList'][host]['sha1Fingerprint']             = result['certinfo']['certificate']['@sha1Fingerprint']
            
            # Who wants this? # buildreturn['resultsList'][host]['certPEM'] = result['certinfo']['certificate']['@asPEM']
            
            #### CERTIFICATE AUTHORITAY[sic] DATAS
            try: # Some certs just aren't that legit!
                caissuer = result['certinfo']['certificate']['extensions']['AuthorityInformationAccess']['CAIssuers']['URI']['listEntry']
                buildreturn['resultsList'][host]['issuerURL']       = caissuer
            except:
                buildreturn['resultsList'][host]['issuerURL']       = ""
            buildreturn['resultsList'][host]['issuerCommonName']    = result['certinfo']['certificate']['issuer']['commonName']
            
            #### CRYPTO DATA
            buildreturn['resultsList'][host]['publicKeyAlgorithm']  = result['certinfo']['certificate']['subjectPublicKeyInfo']['publicKeyAlgorithm']
            buildreturn['resultsList'][host]['publicKeySize']       = result['certinfo']['certificate']['subjectPublicKeyInfo']['publicKeySize']
            
            #### EXPIRY DATA
            print "---- EXPIRE INFO ----"
            buildreturn['resultsList'][host]['validNotAfter']       = result['certinfo']['certificate']['validity']['notAfter']
            buildreturn['resultsList'][host]['validNotBefore']      = result['certinfo']['certificate']['validity']['notBefore']
            #TODO TODO TODO buildreturn['resultsList'][host]['validRightNow'] = False
            buildreturn['resultsList'][host]['serialNumber'] = result['certinfo']['certificate']['serialNumber']
"""
            # TODO HELPFUL TO INSPECT XXX XXX XXX XXX XXX XXX
            #print " xxxxxxxxxxxxxxxx=\t\t" + str( json.dumps(result['certinfo']['certificate']['subjectPublicKeyInfo'], indent=3) )


#{
# "document": {
#  "@SSLyzeVersion": "ssl2json v0.1 (SSLyze v0.7)", 
#  "@SSLyzeWeb": "https://github.com/jonkelleyatrackspace/sslyze", 
#  "@title": "SSLyze Scan Results", 
#  "invalidTargets": null, 
#  "results": {
#   "@defaultTimeout": "5", 
#   "@httpsTunnel": "None", 
#   "@startTLS": "None", 
#   "@totalScanTime": "0.573646068573", 
#   "target": [
#    {
#     "@host": "google.com", 
#     "@ip": "74.125.227.98", 
#     "@port": "443", 
#     "certinfo": {
#      "@argument": "full", 
#      "@title": "Certificate", 
#      "certificate": {
#       "@hasMatchingHostname": "True", 
#       "@isExtendedValidation": "False", 
#       "@isTrustedByMozillaCAStore": "True", 
#       "@reasonWhyNotTrusted": "ok", 
#       "@sha1Fingerprint": "39dc179fc4dc6732e2025ab9c418d79d4e1c6e94", 
#       "asPEM": "-----BEGIN CERTIFICATE-----\nMIIGKjCCBZOgAwIBAgIKEiIxuQABAACSsTANBgkqhkiG9w0BAQUFADBGMQswCQYD\nVQQGEwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzEiMCAGA1UEAxMZR29vZ2xlIElu\ndGVybmV0IEF1dGhvcml0eTAeFw0xMzA3MzExMTQwMzRaFw0xMzEwMzEyMzU5NTla\nMGYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1N\nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgSW5jMRUwEwYDVQQDFAwqLmdv\nb2dsZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAL+RiEjTLckQO7tb\nT9lIFriDh3P+zkRJNWxZYuRnwKcJadgN9pMaf1taf2HkjrskArM1QIANnOPOByvA\nJp4HYr6NJLD2OPOvLvYv98qLdkKTKjt/b2H6axfGiJY6g9QfQtc81zc/tL51vknz\nvSGaqOsAeJ0SO9SldqM7X/lDYkfTAgMBAAGjggP9MIID+TAdBgNVHSUEFjAUBggr\nBgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFD0slhILWX0Vi0EOxThOwOUUqKcJ\nMB8GA1UdIwQYMBaAFL/AMOv1QxE+Z7qekfv8atrjaxIkMFsGA1UdHwRUMFIwUKBO\noEyGSmh0dHA6Ly93d3cuZ3N0YXRpYy5jb20vR29vZ2xlSW50ZXJuZXRBdXRob3Jp\ndHkvR29vZ2xlSW50ZXJuZXRBdXRob3JpdHkuY3JsMGYGCCsGAQUFBwEBBFowWDBW\nBggrBgEFBQcwAoZKaHR0cDovL3d3dy5nc3RhdGljLmNvbS9Hb29nbGVJbnRlcm5l\ndEF1dGhvcml0eS9Hb29nbGVJbnRlcm5ldEF1dGhvcml0eS5jcnQwDAYDVR0TAQH/\nBAIwADCCAsMGA1UdEQSCArowggK2ggwqLmdvb2dsZS5jb22CDSouYW5kcm9pZC5j\nb22CFiouYXBwZW5naW5lLmdvb2dsZS5jb22CEiouY2xvdWQuZ29vZ2xlLmNvbYIW\nKi5nb29nbGUtYW5hbHl0aWNzLmNvbYILKi5nb29nbGUuY2GCCyouZ29vZ2xlLmNs\ngg4qLmdvb2dsZS5jby5pboIOKi5nb29nbGUuY28uanCCDiouZ29vZ2xlLmNvLnVr\ngg8qLmdvb2dsZS5jb20uYXKCDyouZ29vZ2xlLmNvbS5hdYIPKi5nb29nbGUuY29t\nLmJygg8qLmdvb2dsZS5jb20uY2+CDyouZ29vZ2xlLmNvbS5teIIPKi5nb29nbGUu\nY29tLnRygg8qLmdvb2dsZS5jb20udm6CCyouZ29vZ2xlLmRlggsqLmdvb2dsZS5l\nc4ILKi5nb29nbGUuZnKCCyouZ29vZ2xlLmh1ggsqLmdvb2dsZS5pdIILKi5nb29n\nbGUubmyCCyouZ29vZ2xlLnBsggsqLmdvb2dsZS5wdIIPKi5nb29nbGVhcGlzLmNu\nghQqLmdvb2dsZWNvbW1lcmNlLmNvbYINKi5nc3RhdGljLmNvbYIMKi51cmNoaW4u\nY29tghAqLnVybC5nb29nbGUuY29tghYqLnlvdXR1YmUtbm9jb29raWUuY29tgg0q\nLnlvdXR1YmUuY29tghYqLnlvdXR1YmVlZHVjYXRpb24uY29tggsqLnl0aW1nLmNv\nbYILYW5kcm9pZC5jb22CBGcuY2+CBmdvby5nbIIUZ29vZ2xlLWFuYWx5dGljcy5j\nb22CCmdvb2dsZS5jb22CEmdvb2dsZWNvbW1lcmNlLmNvbYIKdXJjaGluLmNvbYII\neW91dHUuYmWCC3lvdXR1YmUuY29tghR5b3V0dWJlZWR1Y2F0aW9uLmNvbTANBgkq\nhkiG9w0BAQUFAAOBgQClna2RVEEVPusOayhKQ0/JUSBkvL8TflvmgIL/L/4SXsPy\nAxcOwHBv0vfyX8cos1thOkyuSHEbuKqANW9BESg9dmqYWIG6hSWcVkbsqiaDS1CI\nkO1nUjlwRJ+udBYcQPy8yBgJhTQ/76rRYyXoiTHr5SoV25gQrSFcWUSEum9C5Q==\n-----END CERTIFICATE-----", 
#       "extensions": {
#        "AuthorityInformationAccess": {
#         "CAIssuers": {
#          "URI": {
#           "listEntry": "http://www.gstatic.com/GoogleInternetAuthority/GoogleInternetAuthority.crt"
#          }
#         }
#        }, 
#        "X509v3AuthorityKeyIdentifier": "keyid:BF:C0:30:EB:F5:43:11:3E:67:BA:9E:91:FB:FC:6A:DA:E3:6B:12:24", 
#        "X509v3BasicConstraints": "CA:FALSE", 
#        "X509v3CRLDistributionPoints": {
#         "FullName": {
#          "listEntry": null
#         }, 
#         "URI": {
#          "listEntry": "http://www.gstatic.com/GoogleInternetAuthority/GoogleInternetAuthority.crl"
#         }
#        }, 
#        "X509v3ExtendedKeyUsage": {
#         "TLSWebClientAuthentication": null, 
#         "TLSWebServerAuthentication": null
#        }, 
#        "X509v3SubjectAlternativeName": {
#         "DNS": {
#          "listEntry": [
#           "*.google.com", 
#           "*.android.com", 
#           "*.appengine.google.com", 
#           "*.cloud.google.com", 
#           "*.google-analytics.com", 
#           "*.google.ca", 
#           "*.google.cl", 
#           "*.google.co.in", 
#           "*.google.co.jp", 
#           "*.google.co.uk", 
#           "*.google.com.ar", 
#           "*.google.com.au", 
#           "*.google.com.br", 
#           "*.google.com.co", 
#           "*.google.com.mx", 
#           "*.google.com.tr", 
#           "*.google.com.vn", 
#           "*.google.de", 
#           "*.google.es", 
#           "*.google.fr", 
#           "*.google.hu", 
#           "*.google.it", 
#           "*.google.nl", 
#           "*.google.pl", 
#           "*.google.pt", 
#           "*.googleapis.cn", 
#           "*.googlecommerce.com", 
#           "*.gstatic.com", 
#           "*.urchin.com", 
#           "*.url.google.com", 
#           "*.youtube-nocookie.com", 
#           "*.youtube.com", 
#           "*.youtubeeducation.com", 
#           "*.ytimg.com", 
#           "android.com", 
#           "g.co", 
#           "goo.gl", 
#           "google-analytics.com", 
#           "google.com", 
#           "googlecommerce.com", 
#           "urchin.com", 
#           "youtu.be", 
#           "youtube.com", 
#           "youtubeeducation.com"
#          ]
#         }
#        }, 
#        "X509v3SubjectKeyIdentifier": "3D:2C:96:12:0B:59:7D:15:8B:41:0E:C5:38:4E:C0:E5:14:A8:A7:09"
#       }, 
#       "issuer": {
#        "commonName": "Google Internet Authority", 
#        "countryName": "US", 
#        "organizationName": "Google Inc"
#       }, 
#       "serialNumber": "122231B90001000092B1", 
#       "signatureAlgorithm": "sha1WithRSAEncryption", 
#       "signatureValue": "a5:9d:ad:91:54:41:15:3e:eb:0e:6b:28:4a:43:4f:c9:51:20:64:bc:bf:13:7e:5b:e6:80:82:ff:2f:fe:12:5e:c3:f2:03:17:0e:c0:70:6f:d2:f7:f2:5f:c7:28:b3:5b:61:3a:4c:ae:48:71:1b:b8:aa:80:35:6f:41:11:28:3d:76:6a:98:58:81:ba:85:25:9c:56:46:ec:aa:26:83:4b:50:88:90:ed:67:52:39:70:44:9f:ae:74:16:1c:40:fc:bc:c8:18:09:85:34:3f:ef:aa:d1:63:25:e8:89:31:eb:e5:2a:15:db:98:10:ad:21:5c:59:44:84:ba:6f:42:e5", 
#       "subject": {
#        "commonName": "*.google.com", 
#        "countryName": "US", 
#        "localityName": "Mountain View", 
#        "organizationName": "Google Inc", 
#        "stateOrProvinceName": "California"
#       }, 
#       "subjectPublicKeyInfo": {
#        "publicKey": {
#         "exponent": "65537", 
#         "modulus": "00:bf:91:88:48:d3:2d:c9:10:3b:bb:5b:4f:d9:48:16:b8:83:87:73:fe:ce:44:49:35:6c:59:62:e4:67:c0:a7:09:69:d8:0d:f6:93:1a:7f:5b:5a:7f:61:e4:8e:bb:24:02:b3:35:40:80:0d:9c:e3:ce:07:2b:c0:26:9e:07:62:be:8d:24:b0:f6:38:f3:af:2e:f6:2f:f7:ca:8b:76:42:93:2a:3b:7f:6f:61:fa:6b:17:c6:88:96:3a:83:d4:1f:42:d7:3c:d7:37:3f:b4:be:75:be:49:f3:bd:21:9a:a8:eb:00:78:9d:12:3b:d4:a5:76:a3:3b:5f:f9:43:62:47:d3"
#        }, 
#        "publicKeyAlgorithm": "rsaEncryption", 
#        "publicKeySize": "1024 bit"
#       }, 
#       "validity": {
#        "notAfter": "Oct 31 23:59:59 2013 GMT", 
#        "notBefore": "Jul 31 11:40:34 2013 GMT"
#       }, 
#       "version": "2"
#      }, 
#      "ocspStapling": {
#       "@error": "Server did not send back an OCSP response"
#      }
#     }
#    }, 
#    {
#     "@host": "www.example.com", 
#     "@ip": "93.184.216.119", 
#     "@port": "443", 
#     "certinfo": {
#      "@argument": "full", 
#      "@title": "Certificate", 
#      "certificate": {
#       "@hasMatchingHostname": "False", 
#       "@isExtendedValidation": "False", 
#       "@isTrustedByMozillaCAStore": "True", 
#       "@reasonWhyNotTrusted": "ok", 
#       "@sha1Fingerprint": "d8af998db5e042a7b47b6d41627500a7f7ed965c", 
#       "asPEM": "-----BEGIN CERTIFICATE-----\nMIISzTCCEbWgAwIBAgIQBi1IiYbJptf5SQHCtZBogjANBgkqhkiG9w0BAQUFADBm\nMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\nd3cuZGlnaWNlcnQuY29tMSUwIwYDVQQDExxEaWdpQ2VydCBIaWdoIEFzc3VyYW5j\nZSBDQS0zMB4XDTExMTAwMzAwMDAwMFoXDTE0MTIxMDEyMDAwMFowfTELMAkGA1UE\nBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFTATBgNVBAcTDFNhbnRhIE1vbmlj\nYTEgMB4GA1UEChMXRWRnZUNhc3QgTmV0d29ya3MsIEluYy4xIDAeBgNVBAMTF2dw\nMS53YWMuZWRnZWNhc3RjZG4ubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\nCgKCAQEAuK5V1nGoCRPLM/7fOM4QL3vv9W+7e6Gs3lvyMoTL3zieqzuAGpyM9Cs7\nvRv2g/rZ49l2KgzbNK9+JIee0LC2cTFbQuE9DaVXRGLo8dAhnP0cFMbErcxehWdY\n2uItl5RdxGzBYPvOTMBFpLgzqjqqvN0auTI0IYbszE4GIcJQQm6EnT4/eQ3FVCrD\no26j4itj8VP+jBvypzPdoTmSCbRABcp30IQPsV0kt1HM8ONyaMNk7+zx5OHLuBbS\nKcyFmvdkiT4Wx7/Q3dBh5Rx91uToIBoFIgeglmS3O4/qPnQdgQyXHAP/gnMKA00a\nY7qVJ54NrqxBk7/C8G1EXsADplT5gwIDAQABo4IPXjCCD1owHwYDVR0jBBgwFoAU\nUOpzidsp+xCPnuUBINTeeZlIg/cwHQYDVR0OBBYEFDQ6+zUrIfo4JLXmdSig/Shl\n8CedMIIMMQYDVR0RBIIMKDCCDCSCF2dwMS53YWMuZWRnZWNhc3RjZG4ubmV0ghB3\nd3cuZWRnZWNhc3QuY29tghN3YWMuZWRnZWNhc3RjZG4ubmV0ghZuZS53YWMuZWRn\nZWNhc3RjZG4ubmV0gg1zd2YubWl4cG8uY29tghVjZG4udHJhY2VyZWdpc3Rlci5j\nb22CDnMudG1vY2FjaGUuY29tghFzLm15LnRtb2NhY2hlLmNvbYINZTEuYm94Y2Ru\nLm5ldIINZTIuYm94Y2RuLm5ldIINZTMuYm94Y2RuLm5ldIINd3d3LnNvbm9zLmNv\nbYIac3RhdGljLWNhY2hlLnRwLWdsb2JhbC5uZXSCFXNzbC1jZG4uc29tZXRyaWNz\nLmNvbYIjY2FjaGUudmVoaWNsZWFzc2V0cy5jYXB0aXZlbGVhZC5jb22CEXN0YXRp\nYy53b29wcmEuY29tgg9pbWFnZXMuaW5rMi5jb22CF2Fzc2V0cy1zZWN1cmUucmF6\nb28uY29tggxlYy5wb25kNS5jb22CFWltYWdlcy5lc2VsbGVycHJvLmNvbYIPdXNl\nLnR5cGVraXQuY29tghFzdGF0aWMuaXNlYXR6LmNvbYIVc3RhdGljLnd3dy50dXJu\ndG8uY29tghhpbnBhdGgtc3RhdGljLmlzZWF0ei5jb22CF3NlY3VyZS5hdmVsbGVh\nc3NldHMuY29tghBzdGF0aWMuZHVibGkuY29tghR3d3ctY2RuLmNpbmFtdXNlLmNv\nbYITd3d3LWNkbi5jaW5lYmxlLmNvbYIVd3d3LWNkbi5jaW5lbWFkZW4uY29tghR3\nd3ctY2RuLmZpbG1sdXNoLmNvbYIWd3d3LWNkbi5mbGl4YWRkaWN0LmNvbYIRd3d3\nLWNkbi5pdHNoZC5jb22CFHd3dy1jZG4ubW92aWVhc2UuY29tghV3d3ctY2RuLm1v\ndmllbHVzaC5jb22CEnd3dy1jZG4ucmVlbGhkLmNvbYIUd3d3LWNkbi5wdXNocGxh\neS5jb22CE2NkbjEuZmlzaHBvbmQuY28ubnqCFGNkbjEuZmlzaHBvbmQuY29tLmF1\ngg13d3cuaXNhY2Eub3JnghJjZG4ub3B0aW1pemVseS5jb22CFXN0YXRpYy5zaG9l\nZGF6emxlLmNvbYIYd3d3LnRyYXZlbHJlcHVibGljLmNvLnVrgg5jZG4ubnByb3Zl\nLmNvbYISc3NsYmVzdC5ib296dHguY29tghZ3d3cudHJhdmVscmVwdWJsaWMuY29t\nghV3d3cuYmxhY2tsYWJlbGFkcy5jb22CEGNkbi53aG9pcy5jb20uYXWCF25lMS53\nYWMuZWRnZWNhc3RjZG4ubmV0ghdnczEud2FjLmVkZ2VjYXN0Y2RuLm5ldIIYYzEu\nc29jaWFsY2FzdGNvbnRlbnQuY29tghV3d3cuc3RlZXBhbmRjaGVhcC5jb22CFnd3\ndy53aGlza2V5bWlsaXRpYS5jb22CEXd3dy5jaGFpbmxvdmUuY29tghB3d3cudHJh\nbWRvY2suY29tghB3d3cuYm9ua3Rvd24uY29tghB3d3cuYnJvY2lldHkuY29tghNl\nZGdlY2FzdC5vbmVncnAuY29tggtjZG4ucHN3Lm5ldIIOY2RuLmdhZ2dsZS5uZXSC\nFHd3dy1jZG4ucmVlbHZpZHouY29tgg5mYXN0LmZvbnRzLmNvbYISZWMueG5nbG9i\nYWxyZXMuY29tgg9pbWFnZXMudnJiby5jb22CEmJldGEuZmlsZWJsYXplLm5ldIIa\nY2RuLmJyYW5kc2V4Y2x1c2l2ZS5jb20uYXWCEXd3dy1jZG4uaXJlZWwuY29tghBj\nZGNzc2wuaWJzcnYubmV0ghFjZG4uYmV0Y2hvaWNlLmNvbYIQcGxheWVyLnZ6YWFy\nLmNvbYIUZnJhbWVncmFicy52emFhci5jb22CEHRodW1icy52emFhci5jb22CG3N0\neWxpc3Rsb3VuZ2Uuc3RlbGxhZG90LmNvbYIRd3d3LnN0ZWxsYWRvdC5jb22CEWNv\nbnRlbnQuYXFjZG4uY29tghZjb250ZW50LmViZ2FtZXMuY29tLmF1ghVjb250ZW50\nLmViZ2FtZXMuY28ubnqCE2ltYWdlcy5wYWdlcmFnZS5jb22CFGltYWdlcy5hbGxz\nYWludHMuY29tghZjZG5iMS5rb2Rha2dhbGxlcnkuY29tghFjZG4ub3JiZW5naW5l\nLmNvbYITY2RuLnF1aWNrb2ZmaWNlLmNvbYITY29udGVudC5nbHNjcmlwLmNvbYIO\nY2RuLmJpZGZhbi5jb22CFG1lZGlhLnF1YW50dW1hZHMuY29tghVjZG4uYWxsZW5i\ncm90aGVycy5jb22CEXBpY3MuaW50ZWxpdXMuY29tghVwaWNzLnBlb3BsZWxvb2t1\ncC5jb22CFXBpY3MubG9va3VwYW55b25lLmNvbYIQY2RuMS1zc2wuaWhhLmNvbYIO\ncy5jZG4tY2FyZS5jb22CE2NkbjItYi5leGFtaW5lci5jb22CDGNkbi50cnRrLm5l\ndIIQZWRnZWNkbi5pbmsyLmNvbYIeZWMuZHN0aW1hZ2UuZGlzcG9zb2x1dGlvbnMu\nY29tgg5jZG4uY2x5dGVsLmNvbYIXd2VsY29tZTIuY2Fyc2RpcmVjdC5jb22CEnMx\nLmNhcmQtaW1hZ2VzLmNvbYIPdXBkYXRlLmFsb3QuY29tghJ3d3cub3V0c3lzdGVt\ncy5jb22CEHd3dy5kcndtZWRpYS5jb22CE2xvb2t1cC5ibHVlY2F2YS5jb22CDmNk\nbi50YXhhY3QuY29tghRjZG4udGF4YWN0b25saW5lLmNvbYIOY2RuLjIwMDU4MS5j\nb22CDWltZy52eGNkbi5jb22CDGpzLnZ4Y2RuLmNvbYIMd3d3LmdvYWwuY29tghZj\nZG5zMS5rb2Rha2dhbGxlcnkuY29tghZlZGdlLmRyb3Bkb3duZGVhbHMuY29tghFl\nZGdlLnBhZ2VyYWdlLmNvbYIVZWRnZS5zYW5pdHlzd2l0Y2guY29tgg9lZGdlLnlv\nbnRvby5jb22CEWxheWVycy55b250b28uY29tghRjZG4ud2lkZ2V0c2VydmVyLmNv\nbYISd3d3LmNsb3Vkd29yZHMuY29tghBlZGdlLmFjdGFhZHMuY29tghVpbWFnZXMu\nc2tpbmNhcmVyeC5jb22CEnNzbC5jZG4tcmVkZmluLmNvbYIVc21hbGwub3V0c28t\nbWVkaWEuY29tghBjZG4uZm94eWNhcnQuY29tghVlZGdlLmplZXR5ZXRtZWRpYS5j\nb22CEWNkbi50aWNrZXRmbHkuY29tghdpbWFnZXMuY29zbWV0aWNtYWxsLmNvbYIT\nd3d3LmJhY2tjb3VudHJ5LmNvbYIOc3NsLmJvb3p0eC5jb22CDXAudHlwZWtpdC5u\nZXSCD3VzZS50eXBla2l0Lm5ldIIUY2RuLnRoZXdhdGVyc2hlZC5jb22CDnd3dy5z\nZi1jZG4ubmV0gh9zdGF0aWMuY2RuLmRvbGxhcnNkaXJlY3QuY29tLmF1ghhlZGdl\nLnJlZGZvcmRtZWRpYWxsYy5jb22CF2VkZ2UucGx1cmFsbWVkaWFsbGMuY29tghp3\nd3cuZ291cm1ldGdpZnRiYXNrZXRzLmNvbYIad3d3Lm51bWJlcmludmVzdGlnYXRv\nci5jb22CHWIyYnBvcnRhbC5kaXNuZXlsYW5kcGFyaXMuY29tgiJiMmJwb3J0YWwu\nZGlzbmV5dHJhdmVsYWdlbnRzLmNvLnVrggt3d3cubndmLm9yZ4ISYXNzZXRzLnpl\nbmRlc2suY29tggxhLmNkbmtpYy5jb22CDHMuY2Rua2ljLmNvbYIZd3d3LnN1cGVy\nYmlrZXRveXN0b3JlLmNvbYIWY2RuLnN0eWxldGhyZWFkLmNvbS5hdYISY2RuLmNh\ncnRyYXdsZXIuY29tgiNwdWJsaWNzdGF0aWNjZG4udGFibGVhdXNvZnR3YXJlLmNv\nbYITc2VjdXJlLjMzYWNyb3NzLmNvbYIOYy56dHN0YXRpYy5jb22CDGMubXNjaW1n\nLmNvbYIYc3RhdGljLnRlYW10cmVlaG91c2UuY29tghh3YWMuQThCNS5lZGdlY2Fz\ndGNkbi5uZXQwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggr\nBgEFBQcDAjBhBgNVHR8EWjBYMCqgKKAmhiRodHRwOi8vY3JsMy5kaWdpY2VydC5j\nb20vY2EzLWcyMy5jcmwwKqAooCaGJGh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9j\nYTMtZzIzLmNybDCCAcQGA1UdIASCAbswggG3MIIBswYJYIZIAYb9bAEBMIIBpDA6\nBggrBgEFBQcCARYuaHR0cDovL3d3dy5kaWdpY2VydC5jb20vc3NsLWNwcy1yZXBv\nc2l0b3J5Lmh0bTCCAWQGCCsGAQUFBwICMIIBVh6CAVIAQQBuAHkAIAB1AHMAZQAg\nAG8AZgAgAHQAaABpAHMAIABDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABjAG8AbgBz\nAHQAaQB0AHUAdABlAHMAIABhAGMAYwBlAHAAdABhAG4AYwBlACAAbwBmACAAdABo\nAGUAIABEAGkAZwBpAEMAZQByAHQAIABDAFAALwBDAFAAUwAgAGEAbgBkACAAdABo\nAGUAIABSAGUAbAB5AGkAbgBnACAAUABhAHIAdAB5ACAAQQBnAHIAZQBlAG0AZQBu\nAHQAIAB3AGgAaQBjAGgAIABsAGkAbQBpAHQAIABsAGkAYQBiAGkAbABpAHQAeQAg\nAGEAbgBkACAAYQByAGUAIABpAG4AYwBvAHIAcABvAHIAYQB0AGUAZAAgAGgAZQBy\nAGUAaQBuACAAYgB5ACAAcgBlAGYAZQByAGUAbgBjAGUALjB7BggrBgEFBQcBAQRv\nMG0wJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBFBggrBgEF\nBQcwAoY5aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0SGlnaEFz\nc3VyYW5jZUNBLTMuY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQEFBQADggEB\nABsEwN1rIqeEddYizpZlJjxeEp1gU32RGANQJxdOeaVB0bEVR7fn1rCdJFfkWlX1\na9pPnL0zitoGTrH3J28ppHbW6a/ewT80DEEHUsTWQEvf+sMCYkj8ZBMoIzX4TzJr\nPHK9JxGNafSj7cV8mzqa39r67paJnpj3+tX+cXCO0kwjez+M9A7ORPjhOY7Ap/Qp\nXEtdhcPTfiPtIsZVtR0zq/eobNSNcLpub/2UAwaICXqOvbKyJY0PCvE4kX65AWh/\nMaJj+Pci0zocZTdjfaB29R4DgXCkph85Jg/viYZ92sf7Z9KZ4bUd5EROa7yO+U9p\n0plZ9V8ua43Z0K3TX56IqLY=\n-----END CERTIFICATE-----", 
#       "extensions": {
#        "AuthorityInformationAccess": {
#         "CAIssuers": {
#          "URI": {
#           "listEntry": "http://cacerts.digicert.com/DigiCertHighAssuranceCA-3.crt"
#          }
#         }, 
#         "OCSP": {
#          "URI": {
#           "listEntry": "http://ocsp.digicert.com"
#          }
#         }
#        }, 
#        "X509v3AuthorityKeyIdentifier": "keyid:50:EA:73:89:DB:29:FB:10:8F:9E:E5:01:20:D4:DE:79:99:48:83:F7", 
#        "X509v3BasicConstraints": "CA:FALSE", 
#        "X509v3CRLDistributionPoints": {
#         "FullName": {
#          "listEntry": [
#           null, 
#           null
#          ]
#         }, 
#         "URI": {
#          "listEntry": [
#           "http://crl3.digicert.com/ca3-g23.crl", 
#           "http://crl4.digicert.com/ca3-g23.crl"
#          ]
#         }
#        }, 
#        "X509v3CertificatePolicies": {
#         "CPS": {
#          "listEntry": "http://www.digicert.com/ssl-cps-repository.htm"
#         }, 
#         "ExplicitText": {
#          "listEntry": null
#         }, 
#         "Policy": {
#          "listEntry": "2.16.840.1.114412.1.1"
#         }, 
#         "UserNotice": {
#          "listEntry": null
#         }
#        }, 
#        "X509v3ExtendedKeyUsage": {
#         "TLSWebClientAuthentication": null, 
#         "TLSWebServerAuthentication": null
#        }, 
#        "X509v3KeyUsage": {
#         "DigitalSignature": null, 
#         "KeyEncipherment": null
#        }, 
#        "X509v3SubjectAlternativeName": {
#         "DNS": {
#          "listEntry": [
#           "gp1.wac.edgecastcdn.net", 
#           "www.edgecast.com", 
#           "wac.edgecastcdn.net", 
#           "ne.wac.edgecastcdn.net", 
#           "swf.mixpo.com", 
#           "cdn.traceregister.com", 
#           "s.tmocache.com", 
#           "s.my.tmocache.com", 
#           "e1.boxcdn.net", 
#           "e2.boxcdn.net", 
#           "e3.boxcdn.net", 
#           "www.sonos.com", 
#           "static-cache.tp-global.net", 
#           "ssl-cdn.sometrics.com", 
#           "cache.vehicleassets.captivelead.com", 
#           "static.woopra.com", 
#           "images.ink2.com", 
#           "assets-secure.razoo.com", 
#           "ec.pond5.com", 
#           "images.esellerpro.com", 
#           "use.typekit.com", 
#           "static.iseatz.com", 
#           "static.www.turnto.com", 
#           "inpath-static.iseatz.com", 
#           "secure.avelleassets.com", 
#           "static.dubli.com", 
#           "www-cdn.cinamuse.com", 
#           "www-cdn.cineble.com", 
#           "www-cdn.cinemaden.com", 
#           "www-cdn.filmlush.com", 
#           "www-cdn.flixaddict.com", 
#           "www-cdn.itshd.com", 
#           "www-cdn.moviease.com", 
#           "www-cdn.movielush.com", 
#           "www-cdn.reelhd.com", 
#           "www-cdn.pushplay.com", 
#           "cdn1.fishpond.co.nz", 
#           "cdn1.fishpond.com.au", 
#           "www.isaca.org", 
#           "cdn.optimizely.com", 
#           "static.shoedazzle.com", 
#           "www.travelrepublic.co.uk", 
#           "cdn.nprove.com", 
#           "sslbest.booztx.com", 
#           "www.travelrepublic.com", 
#           "www.blacklabelads.com", 
#           "cdn.whois.com.au", 
#           "ne1.wac.edgecastcdn.net", 
#           "gs1.wac.edgecastcdn.net", 
#           "c1.socialcastcontent.com", 
#           "www.steepandcheap.com", 
#           "www.whiskeymilitia.com", 
#           "www.chainlove.com", 
#           "www.tramdock.com", 
#           "www.bonktown.com", 
#           "www.brociety.com", 
#           "edgecast.onegrp.com", 
#           "cdn.psw.net", 
#           "cdn.gaggle.net", 
#           "www-cdn.reelvidz.com", 
#           "fast.fonts.com", 
#           "ec.xnglobalres.com", 
#           "images.vrbo.com", 
#           "beta.fileblaze.net", 
#           "cdn.brandsexclusive.com.au", 
#           "www-cdn.ireel.com", 
#           "cdcssl.ibsrv.net", 
#           "cdn.betchoice.com", 
#           "player.vzaar.com", 
#           "framegrabs.vzaar.com", 
#           "thumbs.vzaar.com", 
#           "stylistlounge.stelladot.com", 
#           "www.stelladot.com", 
#           "content.aqcdn.com", 
#           "content.ebgames.com.au", 
#           "content.ebgames.co.nz", 
#           "images.pagerage.com", 
#           "images.allsaints.com", 
#           "cdnb1.kodakgallery.com", 
#           "cdn.orbengine.com", 
#           "cdn.quickoffice.com", 
#           "content.glscrip.com", 
#           "cdn.bidfan.com", 
#           "media.quantumads.com", 
#           "cdn.allenbrothers.com", 
#           "pics.intelius.com", 
#           "pics.peoplelookup.com", 
#           "pics.lookupanyone.com", 
#           "cdn1-ssl.iha.com", 
#           "s.cdn-care.com", 
#           "cdn2-b.examiner.com", 
#           "cdn.trtk.net", 
#           "edgecdn.ink2.com", 
#           "ec.dstimage.disposolutions.com", 
#           "cdn.clytel.com", 
#           "welcome2.carsdirect.com", 
#           "s1.card-images.com", 
#           "update.alot.com", 
#           "www.outsystems.com", 
#           "www.drwmedia.com", 
#           "lookup.bluecava.com", 
#           "cdn.taxact.com", 
#           "cdn.taxactonline.com", 
#           "cdn.200581.com", 
#           "img.vxcdn.com", 
#           "js.vxcdn.com", 
#           "www.goal.com", 
#           "cdns1.kodakgallery.com", 
#           "edge.dropdowndeals.com", 
#           "edge.pagerage.com", 
#           "edge.sanityswitch.com", 
#           "edge.yontoo.com", 
#           "layers.yontoo.com", 
#           "cdn.widgetserver.com", 
#           "www.cloudwords.com", 
#           "edge.actaads.com", 
#           "images.skincarerx.com", 
#           "ssl.cdn-redfin.com", 
#           "small.outso-media.com", 
#           "cdn.foxycart.com", 
#           "edge.jeetyetmedia.com", 
#           "cdn.ticketfly.com", 
#           "images.cosmeticmall.com", 
#           "www.backcountry.com", 
#           "ssl.booztx.com", 
#           "p.typekit.net", 
#           "use.typekit.net", 
#           "cdn.thewatershed.com", 
#           "www.sf-cdn.net", 
#           "static.cdn.dollarsdirect.com.au", 
#           "edge.redfordmediallc.com", 
#           "edge.pluralmediallc.com", 
#           "www.gourmetgiftbaskets.com", 
#           "www.numberinvestigator.com", 
#           "b2bportal.disneylandparis.com", 
#           "b2bportal.disneytravelagents.co.uk", 
#           "www.nwf.org", 
#           "assets.zendesk.com", 
#           "a.cdnkic.com", 
#           "s.cdnkic.com", 
#           "www.superbiketoystore.com", 
#           "cdn.stylethread.com.au", 
#           "cdn.cartrawler.com", 
#           "publicstaticcdn.tableausoftware.com", 
#           "secure.33across.com", 
#           "c.ztstatic.com", 
#           "c.mscimg.com", 
#           "static.teamtreehouse.com", 
#           "wac.A8B5.edgecastcdn.net"
#          ]
#         }
#        }, 
#        "X509v3SubjectKeyIdentifier": "34:3A:FB:35:2B:21:FA:38:24:B5:E6:75:28:A0:FD:28:65:F0:27:9D"
#       }, 
#       "issuer": {
#        "commonName": "DigiCert High Assurance CA-3", 
#        "countryName": "US", 
#        "organizationName": "DigiCert Inc", 
#        "organizationalUnitName": "www.digicert.com"
#       }, 
#       "serialNumber": "062D488986C9A6D7F94901C2B5906882", 
#       "signatureAlgorithm": "sha1WithRSAEncryption", 
#       "signatureValue": "1b:04:c0:dd:6b:22:a7:84:75:d6:22:ce:96:65:26:3c:5e:12:9d:60:53:7d:91:18:03:50:27:17:4e:79:a5:41:d1:b1:15:47:b7:e7:d6:b0:9d:24:57:e4:5a:55:f5:6b:da:4f:9c:bd:33:8a:da:06:4e:b1:f7:27:6f:29:a4:76:d6:e9:af:de:c1:3f:34:0c:41:07:52:c4:d6:40:4b:df:fa:c3:02:62:48:fc:64:13:28:23:35:f8:4f:32:6b:3c:72:bd:27:11:8d:69:f4:a3:ed:c5:7c:9b:3a:9a:df:da:fa:ee:96:89:9e:98:f7:fa:d5:fe:71:70:8e:d2:4c:23:7b:3f:8c:f4:0e:ce:44:f8:e1:39:8e:c0:a7:f4:29:5c:4b:5d:85:c3:d3:7e:23:ed:22:c6:55:b5:1d:33:ab:f7:a8:6c:d4:8d:70:ba:6e:6f:fd:94:03:06:88:09:7a:8e:bd:b2:b2:25:8d:0f:0a:f1:38:91:7e:b9:01:68:7f:31:a2:63:f8:f7:22:d3:3a:1c:65:37:63:7d:a0:76:f5:1e:03:81:70:a4:a6:1f:39:26:0f:ef:89:86:7d:da:c7:fb:67:d2:99:e1:b5:1d:e4:44:4e:6b:bc:8e:f9:4f:69:d2:99:59:f5:5f:2e:6b:8d:d9:d0:ad:d3:5f:9e:88:a8:b6", 
#       "subject": {
#        "commonName": "gp1.wac.edgecastcdn.net", 
#        "countryName": "US", 
#        "localityName": "Santa Monica", 
#        "organizationName": "EdgeCast Networks, Inc.", 
#        "stateOrProvinceName": "California"
#       }, 
#       "subjectPublicKeyInfo": {
#        "publicKey": {
#         "exponent": "65537", 
#         "modulus": "00:b8:ae:55:d6:71:a8:09:13:cb:33:fe:df:38:ce:10:2f:7b:ef:f5:6f:bb:7b:a1:ac:de:5b:f2:32:84:cb:df:38:9e:ab:3b:80:1a:9c:8c:f4:2b:3b:bd:1b:f6:83:fa:d9:e3:d9:76:2a:0c:db:34:af:7e:24:87:9e:d0:b0:b6:71:31:5b:42:e1:3d:0d:a5:57:44:62:e8:f1:d0:21:9c:fd:1c:14:c6:c4:ad:cc:5e:85:67:58:da:e2:2d:97:94:5d:c4:6c:c1:60:fb:ce:4c:c0:45:a4:b8:33:aa:3a:aa:bc:dd:1a:b9:32:34:21:86:ec:cc:4e:06:21:c2:50:42:6e:84:9d:3e:3f:79:0d:c5:54:2a:c3:a3:6e:a3:e2:2b:63:f1:53:fe:8c:1b:f2:a7:33:dd:a1:39:92:09:b4:40:05:ca:77:d0:84:0f:b1:5d:24:b7:51:cc:f0:e3:72:68:c3:64:ef:ec:f1:e4:e1:cb:b8:16:d2:29:cc:85:9a:f7:64:89:3e:16:c7:bf:d0:dd:d0:61:e5:1c:7d:d6:e4:e8:20:1a:05:22:07:a0:96:64:b7:3b:8f:ea:3e:74:1d:81:0c:97:1c:03:ff:82:73:0a:03:4d:1a:63:ba:95:27:9e:0d:ae:ac:41:93:bf:c2:f0:6d:44:5e:c0:03:a6:54:f9:83"
#        }, 
#        "publicKeyAlgorithm": "rsaEncryption", 
#        "publicKeySize": "2048 bit"
#       }, 
#       "validity": {
#        "notAfter": "Dec 10 12:00:00 2014 GMT", 
#        "notBefore": "Oct  3 00:00:00 2011 GMT"
#       }, 
#       "version": "2"
#      }, 
#      "ocspStapling": {
#       "@error": "Server did not send back an OCSP response"
#      }
#     }
#    }, 
#    {
#     "@host": "www.reddit.com", 
#     "@ip": "107.14.36.137", 
#     "@port": "443", 
#     "certinfo": {
#      "@argument": "full", 
#      "@title": "Certificate", 
#      "certificate": {
#       "@hasMatchingHostname": "False", 
#       "@isExtendedValidation": "False", 
#       "@isTrustedByMozillaCAStore": "True", 
#       "@reasonWhyNotTrusted": "ok", 
#       "@sha1Fingerprint": "9fee18cc4363903bdde3f06598ece727b5500c16", 
#       "asPEM": "-----BEGIN CERTIFICATE-----\nMIIDkzCCAvygAwIBAgIEByekaTANBgkqhkiG9w0BAQUFADB1MQswCQYDVQQGEwJV\nUzEYMBYGA1UEChMPR1RFIENvcnBvcmF0aW9uMScwJQYDVQQLEx5HVEUgQ3liZXJU\ncnVzdCBTb2x1dGlvbnMsIEluYy4xIzAhBgNVBAMTGkdURSBDeWJlclRydXN0IEds\nb2JhbCBSb290MB4XDTEzMDcyNDE3NDkwMVoXDTEzMTIzMTE4NDc0MlowbjELMAkG\nA1UEBhMCVVMxCzAJBgNVBAgTAk1BMRIwEAYDVQQHEwlDYW1icmlkZ2UxIjAgBgNV\nBAoTGUFrYW1haSBUZWNobm9sb2dpZXMsIEluYy4xGjAYBgNVBAMTEWEyNDguZS5h\na2FtYWkubmV0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCtB+6BABORwgAQ\nttknTFiK6R+DocLozlKUEhnKP2CSn38AB2DPNduVmLUGX1gomNDGA8RhOzIy8TSO\nV4/ngXeAdZTguAxBUWhsAJbArHR8dm4cmNgeOT9POrjOqg0hxB3tJ4B9yoLMpHF/\nseURQHm9YFtSc4aSS9GJ1yWZSKo2owIDAQABo4IBNTCCATEwCQYDVR0TBAIwADBE\nBgNVHREEPTA7gg4qLmFrYW1haWhkLm5ldIIWKi5ha2FtYWloZC1zdGFnaW5nLm5l\ndIIRYTI0OC5lLmFrYW1haS5uZXQwCwYDVR0PBAQDAgUgMIGJBgNVHSMEgYEwf6F5\npHcwdTELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD0dURSBDb3Jwb3JhdGlvbjEnMCUG\nA1UECxMeR1RFIEN5YmVyVHJ1c3QgU29sdXRpb25zLCBJbmMuMSMwIQYDVQQDExpH\nVEUgQ3liZXJUcnVzdCBHbG9iYWwgUm9vdIICAaUwRQYDVR0fBD4wPDA6oDigNoY0\naHR0cDovL3d3dy5wdWJsaWMtdHJ1c3QuY29tL2NnaS1iaW4vQ1JMLzIwMTgvY2Rw\nLmNybDANBgkqhkiG9w0BAQUFAAOBgQCHBT6y6uIpJCr5RuQ0uVwdO4opImJ7acEx\nuZsGycUVJhURq1DtaNVo5EsatyULoEcbTH8ud/jD9ndGBD353LCMwpRPs9oSBx7U\nM4VOrsza8ePCJ2RAF3EHpLxerW3y3LV/S1Rtv3ido1plVwCP+Ta7Mw5ZgKvhcTIb\nyNlxO8TCzg==\n-----END CERTIFICATE-----", 
#       "extensions": {
#        "X509v3AuthorityKeyIdentifier": "DirName:/C=US/O=GTE Corporation/OU=GTE CyberTrust Solutions, Inc./CN=GTE CyberTrust Global Root\nserial:01:A5", 
#        "X509v3BasicConstraints": "CA:FALSE", 
#        "X509v3CRLDistributionPoints": {
#         "FullName": {
#          "listEntry": null
#         }, 
#         "URI": {
#          "listEntry": "http://www.public-trust.com/cgi-bin/CRL/2018/cdp.crl"
#         }
#        }, 
#        "X509v3KeyUsage": {
#         "KeyEncipherment": null
#        }, 
#        "X509v3SubjectAlternativeName": {
#         "DNS": {
#          "listEntry": [
#           "*.akamaihd.net", 
#           "*.akamaihd-staging.net", 
#           "a248.e.akamai.net"
#          ]
#         }
#        }
#       }, 
#       "issuer": {
#        "commonName": "GTE CyberTrust Global Root", 
#        "countryName": "US", 
#        "organizationName": "GTE Corporation", 
#        "organizationalUnitName": "GTE CyberTrust Solutions, Inc."
#       }, 
#       "serialNumber": "0727A469", 
#       "signatureAlgorithm": "sha1WithRSAEncryption", 
#       "signatureValue": "87:05:3e:b2:ea:e2:29:24:2a:f9:46:e4:34:b9:5c:1d:3b:8a:29:22:62:7b:69:c1:31:b9:9b:06:c9:c5:15:26:15:11:ab:50:ed:68:d5:68:e4:4b:1a:b7:25:0b:a0:47:1b:4c:7f:2e:77:f8:c3:f6:77:46:04:3d:f9:dc:b0:8c:c2:94:4f:b3:da:12:07:1e:d4:33:85:4e:ae:cc:da:f1:e3:c2:27:64:40:17:71:07:a4:bc:5e:ad:6d:f2:dc:b5:7f:4b:54:6d:bf:78:9d:a3:5a:65:57:00:8f:f9:36:bb:33:0e:59:80:ab:e1:71:32:1b:c8:d9:71:3b:c4:c2:ce", 
#       "subject": {
#        "commonName": "a248.e.akamai.net", 
#        "countryName": "US", 
#        "localityName": "Cambridge", 
#        "organizationName": "Akamai Technologies, Inc.", 
#        "stateOrProvinceName": "MA"
#       }, 
#       "subjectPublicKeyInfo": {
#        "publicKey": {
#         "exponent": "65537", 
#         "modulus": "00:ad:07:ee:81:00:13:91:c2:00:10:b6:d9:27:4c:58:8a:e9:1f:83:a1:c2:e8:ce:52:94:12:19:ca:3f:60:92:9f:7f:00:07:60:cf:35:db:95:98:b5:06:5f:58:28:98:d0:c6:03:c4:61:3b:32:32:f1:34:8e:57:8f:e7:81:77:80:75:94:e0:b8:0c:41:51:68:6c:00:96:c0:ac:74:7c:76:6e:1c:98:d8:1e:39:3f:4f:3a:b8:ce:aa:0d:21:c4:1d:ed:27:80:7d:ca:82:cc:a4:71:7f:b1:e5:11:40:79:bd:60:5b:52:73:86:92:4b:d1:89:d7:25:99:48:aa:36:a3"
#        }, 
#        "publicKeyAlgorithm": "rsaEncryption", 
#        "publicKeySize": "1024 bit"
#       }, 
#       "validity": {
#        "notAfter": "Dec 31 18:47:42 2013 GMT", 
#        "notBefore": "Jul 24 17:49:01 2013 GMT"
#       }, 
#       "version": "2"
#      }, 
#      "ocspStapling": {
#       "@error": "Server did not send back an OCSP response"
#      }
#     }
#    }
#   ]
#  }
# }
#}
