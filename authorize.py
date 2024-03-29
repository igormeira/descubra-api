from flask import request
from hasher import hash_all, digest
import consulta_db


class Token(object):
    def __init__(self):
        self.ip = request.remote_addr
        self.uri = 'login'


class Authorize(object):
    def __init__(self, realm):
        self.sessions = dict()
        self.user = ''
        self.realm = realm
        self.qop = 'auth'

    def check_password(self, hashed_password, user_pass, username):
        return hashed_password == hash_all(username, self.realm, user_pass)

    def get_users(self):
        query = """SELECT id, email, senha FROM table_usuario"""
        rows = consulta_db.consulta_BD(query)
        return rows

    def validate(self, username, password):
        completion = False
        rows = self.get_users()
        for row in rows:
            dbUsername = row.get("email")
            dbPassword = row.get("senha")
            if dbUsername == username:
                completion = self.check_password(dbPassword, password, username)
        return completion

    def gen_session(self, username):
        token = Token()
        self.user = username

        hA1 = hash_all(self.user)
        hA2 = hash_all(token.ip, token.uri)

        session = digest(hA1, hA2, self.qop, self.realm)
        self.sessions[hA1] = session
        return session

    def check_session(self):
        if self.user is None: return False

        hA1 = hash_all(self.user)
        return self.sessions.get(hA1, False)

    def authenticate(self, username, password):
        if username == '' or password == '': return False
        validate = self.validate(username, password)
        return validate

    def logout(self):
        hA1 = hash_all(auth.user)
        del self.sessions[hA1]
        self.user = ''
        return False
