import os
import threading
import tornado.options
import tornado.ioloop
import tornado.httpserver
import tornado.httpclient
import tornado.web
from tornado import gen
from tornado.web import asynchronous

import sys
sys.path.append('app/classes/thirdparty/sslyze/')

tornado.options.define('port', type=int, default=9000, help='server port number (default: 9000)')
tornado.options.define('debug', type=bool, default=True, help='run in debug mode with autoreload (default: False)')

# app.handlers exists within the directory structure of this tornado project.
#  This is how your routes know how to register the handlers from your handler classes. YAY!
from app.handlers import (
    base,
    index,
    thread,
    threadtwo,
)
class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", index.IndexHandler),
            (r"/thread", thread.ThreadHandler),
            (r"/thread2", threadtwo.ThreadHandlerTwo),
            #(r"/forcecheck/domain/all", app.handlers.forcecheck.ForceCheckHandler),
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
