from src.asy.mysql_client import MysqlPool
from src.common.web_handler import get_loop, JwtManager
from src.common.exception_handler import *
from src.common.utils import Singleton
from src.common.log_handler import logger
import random
import re

__all__ = (
    'UserManager',
    'User',
    'Role',
    'Token',
)


class User:

    def __init__(self) -> None:
        self.loop = get_loop()
        self.mp = MysqlPool(self.loop)

    async def add(self,
                  username,
                  password,
                  role_id=None,
                  nickname=None,
                  email=None,
                  contact=None) -> dict:
        if await self.exist(username=username, status='0,1'):
            return {
                'code': 3,
                'msg': 'user exists'
            }
        sql = "insert into user(username, password, role_id, nickname, email, contact, status)" \
              "values (%s, %s, %s, %s, %s, %s, %s)"
        condition = (username, password, role_id, nickname, email, contact, 1)
        await self.mp.dml(sql, condition)

    async def update(self, **data):
        id = data.get('id')
        role_id = data.get('role_id') if data.get('role_id') != '' else None
        nickname = data.get('nickname')
        email = data.get('email')
        contact = data.get('contact')
        status = data.get('status', True)
        password = data.get('password')
        sql = "update user set " \
              "role_id = %s, nickname = %s, email = %s, " \
              "contact = %s, status = %s " \
              "where id = %s"
        if password:
            sql = "update user set " \
                "role_id = %s, nickname = %s, email = %s, " \
                "contact = %s, status = %s, password = %s " \
                "where id = %s"
            condition = (role_id, nickname, email,
                         contact, status, password, id,)
        else:
            sql = "update user set " \
                "role_id = %s, nickname = %s, email = %s, " \
                "contact = %s, status = %s " \
                "where id = %s"
            condition = (role_id, nickname, email, contact, status, id,)
        await self.mp.dml(sql, condition)

    async def self_update(self, id, password, email, contact):
        if password:
            sql = "update user set password = %s, email = %s, contact = %s where id = %s"
            conditions = (password, email, contact, id)
        else:
            sql = "update user set email = %s, contact = %s where id = %s"
            conditions = (email, contact, id)
        await self.mp.dml(sql, conditions)

    async def delete(self, id, status) -> None:
        sql = "update user set status = %s where id = %s"
        condition = (status, id,)
        await self.mp.dml(sql, condition)

    async def exist(self, id=None, username=None, status=1) -> bool:
        if id:
            sql = "select count(*) as exist from user where id = %s and status in ({})".format(status)
            condition = (id,)
        else:
            sql = "select count(*) as exist from user where username = %s and status in ({})".format(status)
            condition = (username,)
        ret = await self.mp.dml(sql, condition)
        return True if ret['exist'] == 1 else False

    async def list_user(self, id=None, username=None, role_id=None, page=1, limit=15, status=1, conditions=''):
        ret = {
            'user_counts': 0,
            'user_list': [],
            'user_info': {}
        }
        if id:
            sql = "select * from user left join role " \
                "on user.role_id=role.id " \
                "where user.id = %s"
            condition = (id,)
            user_info = await self.mp.dml(sql, conditions=condition)
            user_info['password'] = ''
            ret['user_info'] = user_info
        elif username:
            sql = "select * from user left join role " \
                "on user.role_id=role.id " \
                "where user.username = %s"
            condition = (username,)
            user_info = await self.mp.dml(sql, conditions=condition)
            user_info['password'] = ''
            ret['user_info'] = user_info
        elif role_id:
            sql = "select user.* from user,role " \
                "where user.role_id=role.id " \
                "and role.id = %s and user.role_id is not null and user.status = 1"
            condition = (role_id,)
            return await self.mp.dml(sql, conditions=condition, all=True)
        else:
            counts_sql = "select count(*) as counts from user left join role on user.role_id = role.id " \
                         "where super = 0 and status in ({})".format(status)
            counts = await self.mp.dml(counts_sql)
            if counts == 0:
                return ret
            page = int(page) - 1 if int(page) > 1 else 0
            limit = int(limit)
            user_list_sql = \
                "select u.id, username, rolename, nickname, role_id, contact, email, u.status, last_login_time, create_time " \
                "from (select * from user where username like CONCAT('%%', %s, '%%') union " \
                "select * from user where nickname like CONCAT('%%', %s, '%%') union " \
                "select * from user where email like CONCAT('%%', %s, '%%') union " \
                "select * from user where contact like CONCAT('%%', %s, '%%') " \
                ") u left join role on u.role_id=role.id " \
                "where super = 0 and u.status in ({}) limit {},{} ".format(status, page*limit, limit)
            user_list = []
            def f_hash(): return lambda self: hash(self.info['id'])
            def f_eq(
            ): return lambda self, other: self.info['id'] == other.info['id']
            for cond in conditions.split(','):
                conds = (cond, cond, cond, cond)
                user_ret = await self.mp.dml(user_list_sql, conditions=conds, all=True)
                for piece in user_ret:
                    user_list.append(type("User", (), dict(
                        info=piece, __hash__=f_hash(), __eq__=f_eq()))())
            ret['user_counts'] = counts.get('counts')
            ret['user_list'] = [x.info for x in list(set(user_list))]
        return ret

    async def validate_user(self, username=None, password=None) -> dict:
        sql = "select * from user left join role " \
              "on user.role_id=role.id " \
              "where user.username = %s and user.password = %s and user.status = 1"
        condition = (username, password)
        return await self.mp.dml(sql, condition)


class Role:
    def __init__(self) -> None:
        self.loop = get_loop()
        self.mp = MysqlPool(self.loop)

    async def list_role(self, id=None, page=1, limit=15, conditions=''):
        ret = {
            'role_counts': 0,
            'role_list': [],
            'role_info': {}
        }
        if id:
            sql = "select * from role where id = %s"
            condition = (id,)
            role_info = await self.mp.dml(sql, condition)
            ret['role_info'] = role_info
        else:
            counts_sql = "select count(*) as counts from role"
            counts = await self.mp.dml(counts_sql)
            if counts == 0:
                return ret
            page = int(page) - 1 if int(page) > 1 else 0
            limit = int(limit)
            role_list_sql = \
                "select * from (" \
                "select * from role where rolename like CONCAT('%%', %s, '%%') union " \
                "select * from role where routes like CONCAT('%%', %s, '%%') union " \
                "select * from role where components like CONCAT('%%', %s, '%%') " \
                ") as r limit {},{} ".format(page*limit, limit)
            for cond in conditions.split(','):
                conds = (cond, cond, cond)
                role_list = await self.mp.dml(role_list_sql, conditions=conds, all=True)
            ret['role_counts'] = counts.get('counts')
            ret['role_list'] = role_list
        return ret

    async def add(self, rolename, routes='', components='', requests='', comment=''):
        if await self.exist(rolename=rolename):
            return {
                'code': 3,
                'msg': '角色已存在'
            }
        sql = "insert into role(rolename, routes, components, requests, comment)" \
              "values (%s, %s, %s, %s, %s)"
        condition = (rolename, routes, components, requests, comment,)
        await self.mp.dml(sql, condition)
        id_sql = "select id from role where rolename = %s"
        id_condition = (rolename,)
        ret = await self.mp.dml(id_sql, id_condition)
        return ret

    async def update(self,
                     id,
                     rolename,
                     routes,
                     components,
                     requests,
                     comment):
        sql = "update role set " \
              "rolename = %s, routes = %s, components = %s, requests = %s, comment = %s " \
              "where id = %s"
        condition = (rolename, routes, components, requests, comment, id,)
        await self.mp.dml(sql, condition)

    async def delete(self, id):
        if not await self.exist(id=id):
            return {
                'code': 3,
                'msg': 'role not exists'
            }
        sql = "delete from role where id = %s"
        condition = (id,)
        await self.mp.dml(sql, condition)

    async def exist(self, id=None, rolename=None) -> bool:
        if id:
            sql = "select count(*) as exist from role where id = %s"
            condition = (id)
        else:
            sql = "select count(*) as exist from role where rolename = %s"
            condition = (rolename)
        ret = await self.mp.dml(sql, condition)
        return True if ret['exist'] == 1 else False


class Token:

    def __init__(self) -> None:
        self.loop = get_loop()
        self.mp = MysqlPool(self.loop)

    async def add(self, tokenname):
        is_exists = await self.token_exists(tokenname=tokenname)
        if is_exists['counts'] == 1:
            raise RunError(msg='token已存在，请检查')
        tokenkey = ''.join(random.sample('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890', 16))
        payload = JwtManager().encode({
            'tokenname': tokenname,
            'tokenkey': tokenkey,
        }, expire=0)
        await self.mp.dml(
            "insert into token(tokenname, tokenkey, payload) values(%s, %s, %s) " ,
            (tokenname, tokenkey, payload)
        )

    async def delete(self, id):
        await self.mp.dml(
            "delete from token where id = %s",
            (id,)
        )

    async def list_token(self, id=None, page=1, limit=15):
        ret = {
            'token_counts': 0,
            'token_list': [],
            'token_info': {}
        }
        if id:
            token_info = await self.mp.dml(
                "select * from token where id = %s", 
                (id,)
            )
            ret['token_info'] = token_info
        else:
            counts = await self.mp.dml(
                "select count(1) counts from token"
            )
            page = int(page) - 1 if int(page) > 1 else 0
            limit = int(limit)
            token_list = await self.mp.dml(
                "select * from token order by id desc limit {}, {} ".format(page*limit, limit), 
                all=True
            )
            ret['token_counts'] = counts.get('counts')
            ret['token_list'] = token_list
        return ret

    async def token_exists(self, id=None, tokenname=None):
        res = 0
        if id:
            res = await self.mp.dml(
                "select count(1) counts from token where id = %s", 
                (id,)
            )
        if tokenname:
            res = await self.mp.dml(
                "select count(1) counts from token where tokenname = %s", 
                (tokenname,)
            )
        return res


class UserManager(metaclass=Singleton):

    async def has_permission(self, token):
        try:
            jm = JwtManager()
            return jm.decode(token)
        except Exception as e:
            raise AuthError(e)

    async def login(self, username=None, password=None) -> dict:
        login = await User().validate_user(username, password)
        if not login:
            raise LoginError()

        auth = JwtManager().encode({
            'username': login.get('username'),
        })
        user_info = {
            'auth': auth,
            'id': login.get('id'),
            'username': login.get('username'),
            'role_id': login.get('role_id'),
            'super': login.get('super'),
            'rolename': login.get('rolename'),
            'nickname': login.get('nickname'),
            'email': login.get('email'),
            'contact': login.get('contact'),
            'routes': login.get('routes'),
            'components': login.get('components'),
            'requests': login.get('requests')
        }
        setattr(self, username, user_info)
        return user_info

    async def user_refresh(self, id, **kwargs):
        data = await User().list_user(id) or {}
        user_info = data['user_info']
        if not user_info['super']:
            self.get_user_in_cache(user_info['username'])
        return user_info
        
    def get_user_in_cache(self, username):
        try:
            return getattr(self, username)
        except AttributeError:
            logger.info('current user {} need refresh'.format(username))
            raise AuthError()

    async def update_user_in_cache(self, username):
        user_info = self.get_user_in_cache(username)
        res = await User().list_user(username=username) or {}
        for k, v in res['user_info'].items():
            user_info[k] = v

    def logout(self, username) -> None:
        try:
            delattr(self, username)
        except AttributeError:
            logger.info('User {} not login'.format(username))

    async def user_crud(self, user_type, **kwargs) -> dict:
        if user_type == 'retrieve':
            data = await User().list_user(**kwargs) or {}
        else:
            fn = getattr(User(), user_type)
            data = await fn(**kwargs) or {}

        return data

    async def role_crud(self, role_type, **kwargs) -> dict:
        if role_type == 'retrieve':
            data = await Role().list_role(**kwargs) or {}
        elif role_type == 'add':
            data = await Role().add(**kwargs) or {}
        else:
            users_through_role = await User().list_user(role_id=kwargs['id'])
            if role_type == 'delete' and len(users_through_role) > 0:
                return {
                    'code': 1,
                    'msg': '该角色已关联用户，无法删除'
                }
            fn = getattr(Role(), role_type)
            data = await fn(**kwargs) or {}
            for u in users_through_role:
                await self.update_user_in_cache(u.get('username'))
        return data

    async def user_check(self, payload, **kwargs) -> None:
        if not payload['super']:
            username = payload['username']
            method, origin_path, permission = kwargs.get('origin_url').split(':')
            user_in_cache = self.get_user_in_cache(username)

            logger.info(user_in_cache)
            if not payload.get('routes', '') == user_in_cache.get('routes', ''): 
               logger.info(
                   'permission of route has changed, need refresh'.format(username))
               raise ForbiddenError()

            if not payload.get('components', '') == user_in_cache.get('components', ''): 
               logger.info(
                   'permission of components has changed, need refresh'.format(username))
               raise ForbiddenError()

            if permission == '1':
                requests = [x for x in user_in_cache.get('requests').split(',')]
                origin_path_and_method = '{}:{}'.format(origin_path, method.lower())
                if not origin_path_and_method in requests:
                   logger.info('current user {} no permission for {}, request forbidden'.format(username, origin_path_and_method))
                   raise ForbiddenError()

    async def token_check(self, payload):
        loop = get_loop()
        mp = MysqlPool(loop)
        try:
            auth_type, token = re.split(r'\s+', payload['token'])
            res = JwtManager().decode(token)
            tokenname = res['tokenname']
            tokenkey = res['tokenkey']
            token_res = await mp.dml(
                "select count(1) counts from token where tokenname = %s and tokenkey = %s",
                (tokenname, tokenkey)
            )
            if token_res['counts'] != 1:
                raise RuntimeError('token找不到')
        except Exception as e:
            raise AuthError(str(e))
