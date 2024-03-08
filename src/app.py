from .common.config import get_conf
from .common.web_handler import *
from .route import urls
from .asy.mysql_client import MysqlPool
import asyncio

def _init():
    loop = get_loop()
    mp = MysqlPool(loop)
    asyncio.run_coroutine_threadsafe(mp.create_mysql_pool(), loop)


def main():
    settings = get_conf().get('tornado', {})
    app = Application(urls, **settings)
    server = httpserver.HTTPServer(app)
    server.bind(10001, '0.0.0.0')
    server.start(1)
    _init()
    IOLoop.current().start()
