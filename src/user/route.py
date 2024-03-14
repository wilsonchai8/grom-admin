from src.common.web_handler import WebHandler, url_unescape
from .views import *
from src.common.log_handler import logger

class AuthHandler(WebHandler):
    async def get(self, *args, **kwargs):
        query = self.get_request_query_json()
        um = UserManager()
        data = await um.user_refresh(**query)
        self.reply(**data)

    async def post(self, *args, **kwargs):
        body = self.get_request_body_json()
        username = body.get('username', None)
        password = body.get('password', None)
        um = UserManager()
        payload = await um.login(username, password)
        self.reply(**payload)

    async def put(self, *args, **kwargs):
        origin_url = self.request.headers.get('origin-url')
        um = UserManager()
        token = self.request.headers.get('Authorization')
        if token:
            payload = {
                'token': token
            }
            await um.token_check(payload)
        else:
            payload = {
                'username': self.get_cookie('username'),
                'super': int(self.get_cookie('super')),
                'auth': self.get_cookie('auth'),
                'routes': url_unescape(self.get_cookie('routes')),
                'requests': url_unescape(self.get_cookie('requests')),
                'components': url_unescape(self.get_cookie('components')),
            }
            await um.user_check(payload, origin_url=origin_url)
        self.reply()

    def patch(self, *args, **kwargs):
        body = self.get_request_body_json()
        print(body)

    def prepare(self):
        pass
    
class TestHandler(WebHandler):
    async def get(self, *args, **kwargs):
        query = self.get_request_query_json()
        print(query)
        self.reply()

    def prepare(self):
        pass
        


class UserHandler(WebHandler):
    async def get(self, *args, **kwargs):
        query = self.get_request_query_json()
        um = UserManager()
        data = await um.user_crud('retrieve', **query)
        self.reply(**data)

    async def post(self, *args, **kwargs):
        body = self.get_request_body_json()
        um = UserManager()
        data = await um.user_crud('add', **body)
        self.reply(**data)

    async def put(self, *args, **kwargs):
        body = self.get_request_body_json()
        um = UserManager()
        data = await um.user_crud('update', **body) or {}
        self.reply(**data)

    async def delete(self, *args, **kwargs):
        query = self.get_request_query_json()
        um = UserManager()
        await um.user_crud('delete', **query)
        self.reply()


        
class RoleHandler(WebHandler):
    async def get(self, *args, **kwargs):
        query = self.get_request_query_json()
        um = UserManager()
        data = await um.role_crud('retrieve', **query)
        self.reply(**data)

    async def post(self, *args, **kwargs):
        body = self.get_request_body_json()
        um = UserManager()
        data = await um.role_crud('add', **body)
        self.reply(**data)

    async def put(self, *args, **kwargs):
        body = self.get_request_body_json()
        um = UserManager()
        data = await um.role_crud('update', **body)
        self.reply(**data)

    async def delete(self, *args, **kwargs):
        query = self.get_request_query_json()
        um = UserManager()
        data = await um.role_crud('delete', **query)
        self.reply(**data)


class TokenHandler(WebHandler):
    async def get(self, *args, **kwargs):
        query = self.get_request_query_json()
        token = Token()
        data = await token.list_token(**query)
        self.reply(**data)

    async def post(self, *args, **kwargs):
        body = self.get_request_body_json()
        token = Token()
        await token.add(**body)
        self.reply()

    async def delete(self, *args, **kwargs):
        query = self.get_request_query_json()
        token = Token()
        await token.delete(**query)
        self.reply()

class UserSelfHandler(WebHandler):

    async def put(self, *args, **kwargs):
        body = self.get_request_body_json()
        user = User()
        await user.self_update(**body)
        self.reply()


login_urls = [
    (r'/auth', AuthHandler),
    (r'/test', TestHandler),
    (r'/user/users', UserHandler),
    (r'/user/roles', RoleHandler),
    (r'/user/token', TokenHandler),
    (r'/user/userself', UserSelfHandler),
]
