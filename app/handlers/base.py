import os
import threading
import tornado.options
import tornado.ioloop
import tornado.httpserver
import tornado.httpclient
import tornado.web
from tornado import gen
from tornado.web import asynchronous


class BaseHandler(tornado.web.RequestHandler):
    """A class to collect common handler methods - all other handlers should
subclass this one.
"""
    def load_json(self):
        print "blahhhhhh"

