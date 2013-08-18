SSL Party
=========

#### Overview

1. Prerequisite Dependencies
2. Installation
3. What does this do?

#### Prerequisite Dependencies

This application REQUIRES Python 2.7

This application is intended to be back-ended by a Postgres 9.x database server.  As such, it depends on the Python modules "momoko" and "psycopg2" as well as on the Postgres Client Libraries.

This application also depends on the nassl project from https://github.com/nabla-c0d3/nassl which may need to be compiled for your system if there are not packages available.  nassl is a C/Python wrapper for OpenSSL that statically compiles in the latest Zlib and OpenSSL libraries.

Finally, we are using the Tornado framework for building this API driven application to provide the ability to handle requests and perform jobs asynchronously.

#### Installation

First, install dependencies

````
yum install -y $(cat yum.txt)
pip install -r pip.txt
````

Then install nassl if you have not already done so.

Finally, clone this repo, change directory into it, an d then run the following

````
python setup.py install
````

To build RPM packages (not including dependency checking), run

````
python setup.py bdist --format=rpm
````

#### What does this do?

This application is designed to run as a daemon that provides both an API and a poller to run the jobs.  API methods that are available are documented below:

##### POST Methods
* AddSite
* RemoveSite
Both of these methods take the following JSON object along with a Content-Type: application/json header and return HTTP status codes only.
````
'{"site":
    {
        "url":"example.com",
        "port":"443"
    }
}'
````
* ForceCheck
This method takes the following JSON object along with a Content-Type: application/json header and returns a status report for the passed-in site/domain, without adding it to be checked in the future.
````
Takes:
'{"site":
    {
        "url":"example.com",
        "port":"443"
    }
}'
Returns:
'{"site":
    {
        "url":"example.com",
        "port":"443",
        "is_valid":"true",
        "issuer":"self-signed",
        "cert_expiry":"2015-01-10",
        "serial":"6132AD22D9CB",
        "domain_expiry":"2015-05-23"
    }
}'
````
* AddDomain
* RemoveDomain
Both of these methods take the following JSON object along with the Content-Type: application/json header and return HTTP status codes only.
````
'{"domain":
    {
        "domain":"example.com"
    }
}'
````
##### GET Methods
* ListSites
This method returns a list of sites and their last check timestamp, could be used to feed a poller or dashboard. The last check timestamp matches the format of `date +%F\ %T`.
````
'{"sites":
    {"site":
        {
            "url":"example.com",
            "port":"443",
            "lastcheck":"2013-08-18 03:34:45"
        }
    },
    {"site":
        {
            "url":"google.com",
            "port":"443",
            "lastcheck":"2013-08-18 03:34:45"
        }
    }
}'
````
* Report
This method returns a total dump of the data contained with the database to be parsed by a dashboard or alerting/reporting application.  The last check timestamp matches the format of `date +%F\ %T`.
````
'{"sites":
    {"site":
        {
            "url":"example.com",
            "port":"443",
            "lastcheck":"2013-08-18 03:34:45",
            "is_valid":"true",
            "issuer":"verisign",
            "cert_expiry":"2015-01-10",
            "serial":"6132AD22D9CB",
            "domain_expiry":"2015-05-23"
        }
    }
}'
````
* FailedSites
This method returns the same data as the Report method, but only for sites which have the value "false" is_valid.


##### Poller
The poller uses an ioloop to test the expiration status and other factors of the SSL certificate, and check the whois record for the domains, which are contained within it's database.  The time between checks is determined by a configurable value, but by default is 24 hours.  When the check runs, it verifies that it's been at least that long since the last time it was checked by comparing the current time to the lastcheck field.


Happy SSL Party!
