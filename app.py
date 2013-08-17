import os
import threading
import tornado.options
import tornado.ioloop
import tornado.httpserver
import tornado.httpclient
import tornado.web
from tornado import gen
from tornado.web import asynchronous

import app.handlers

tornado.options.define('port', type=int, default=9000, help='server port number (default: 9000)')
tornado.options.define('debug', type=bool, default=True, help='run in debug mode with autoreload (default: False)')


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", app.handlers.index.IndexHandler),
            (r"/thread", app.handlers.thread.ThreadHandler),
        ]
        settings = dict(
            static_path = os.path.join(os.path.dirname(__file__), "static"),
            template_path = os.path.join(os.path.dirname(__file__), "templates"),
            debug = tornado.options.options.debug,
        )
        tornado.web.Application.__init__(self, handlers, **settings)
        
        
def main():
    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(tornado.options.options.port)
    tornado.ioloop.IOLoop.instance().start()



if __name__ == "__main__":
    main()
