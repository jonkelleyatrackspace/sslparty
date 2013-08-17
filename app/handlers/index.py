from app.handlers.base import BaseHandler
from app.handlers.base import *

import os
import threading
import tornado.options
import tornado.ioloop
import tornado.httpserver
import tornado.httpclient
import tornado.web

from tornado import gen
from tornado.web import asynchronous

import time
class IndexHandler(tornado.web.RequestHandler):
    client = tornado.httpclient.AsyncHTTPClient()

    @asynchronous
    @gen.engine
    def get(self):
        response = yield gen.Task(self.client.fetch, "http://google.com")
        self.finish("Google's homepage is %d bytes long" % len(response.body))
