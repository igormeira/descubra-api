#!/usr/bin/env python
# -*- coding: utf-8 -*-

from flask import Flask, json, jsonify, make_response, request
from flask_jwt_extended import JWTManager, jwt_required, \
    get_jwt_identity, revoke_token, unrevoke_token, \
    get_stored_tokens, get_all_stored_tokens, create_access_token, \
    create_refresh_token, jwt_refresh_token_required, \
    get_raw_jwt, get_stored_token

import simplekv.memory
import datetime
import consulta_db
import os
from authorize import Authorize
from hasher import hash_all


app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(12)
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_STORE'] = simplekv.memory.DictStore()
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = 'all'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=365)

jwt = JWTManager(app)

realm = "DESCUBRA"
auth = Authorize(realm)
completion = False

#CORS headers
@app.after_request
def add_headers(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With')
    return response

#Authentication
def get_response(data):
    response = make_response(data)
    response.headers['Access-Control-Allow-Methods'] = "GET, POST, OPTIONS"
    return response

@app.route('/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    current_user = get_jwt_identity()
    ret = {
        'access_token': create_access_token(identity=current_user)
    }
    return jsonify(ret), 200

def _revoke_current_token():
    current_token = get_raw_jwt()
    jti = current_token['jti']
    revoke_token(jti)

#API
@app.route('/')
def hello_world():
    return 'API do Descubra!'

#ADD INFO TO DB ENDPOINTS

#Celular
@app.route('/add/celular/<op>/<pl>/<pr>/<val>/<net>/<de>')
def addDataCel(op=None, pl=None, pr=None, net=None, val=None, de=None):
    if (op is None) and (pl is None) and (net is None) and (pr is None):
        response = 'Erro ao inserir dados!'
    else:
        query = """INSERT INTO table_celular (operadora,plano,preco,validade,internet,detalhes) VALUES ('"""+\
                str(op)+"""','"""+str(pl)+"""','"""+str(pr)+"""','"""+str(val)+"""','"""+str(net)+"""','"""+str(de)+"""');"""
        response = json.dumps(consulta_db.update_BD(query))
        response = make_response(response)
    return response

#Fixo
@app.route('/add/fixo/<op>/<pl>/<pr>/<de>')
def addDataFixo(op=None, pl=None, pr=None, de=None):
    if (op is None) and (pl is None) and (pr is None):
        response = 'Erro ao inserir dados!'
    else:
        query = """INSERT INTO table_fixo (operadora,plano,preco,detalhes) VALUES ('"""+\
                str(op)+"""','"""+str(pl)+"""','"""+str(pr)+"""','"""+str(de)+"""');"""
        response = json.dumps(consulta_db.update_BD(query))
        response = make_response(response)
    return response

#Internet
@app.route('/add/internet/<prov>/<pl>/<pr>/<val>/<de>')
def addDataNet(prov=None, pl=None, pr=None, val=None, de=None):
    if (prov is None) and (pl is None) and (pr is None):
        response = 'Erro ao inserir dados!'
    else:
        query = """INSERT INTO table_internet (provedor,plano,preco,validade,detalhes) VALUES ('"""+\
                str(prov)+"""','"""+str(pl)+"""','"""+str(pr)+"""','"""+str(val)+"""','"""+str(de)+"""');"""
        response = json.dumps(consulta_db.update_BD(query))
        response = make_response(response)
    return response

#TV
@app.route('/add/tv/<prov>/<pl>/<pr>/<de>')
def addDataTv(prov=None, pl=None, pr=None, de=None):
    if (prov is None) and (pl is None) and (pr is None):
        response = 'Erro ao inserir dados!'
    else:
        query = """INSERT INTO table_tv (provedor,plano,preco,detalhes) VALUES ('"""+\
                str(prov)+"""','"""+str(pl)+"""','"""+str(pr)+"""','"""+str(de)+"""');"""
        response = json.dumps(consulta_db.update_BD(query))
        response = make_response(response)
    return response

#GET INFO FROM DB ENDPOINTS

#Celular
@app.route('/celular')
@app.route('/celular/<op>')
def getDataCel(op=None):
    if op is None:
        query = """SELECT * FROM table_celular"""
    else:
        query = """SELECT * FROM table_celular WHERE (operadora='"""+str(op)+"""')"""
    response = json.dumps(consulta_db.consulta_BD(query))
    response = make_response(response)
    return response

@app.route('/celular/plano/<tipo>')
def getCelByPlan(tipo=None):
    if tipo is None:
        query = """SELECT * FROM table_celular"""
    else:
        query = """SELECT * FROM table_celular WHERE (plano='"""+str(tipo)+"""')"""
    response = json.dumps(consulta_db.consulta_BD(query))
    response = make_response(response)
    return response

#Fixo
@app.route('/fixo')
@app.route('/fixo/<op>')
def getDataFixo(op=None):
    if op is None:
        query = """SELECT * FROM table_fixo"""
    else:
        query = """SELECT * FROM table_fixo WHERE (operadora='"""+str(op)+"""')"""
    response = json.dumps(consulta_db.consulta_BD(query))
    response = make_response(response)
    return response

#Internet
@app.route('/internet')
@app.route('/internet/<prov>')
def getDataNet(prov=None):
    if prov is None:
        query = """SELECT * FROM table_internet"""
    else:
        query = """SELECT * FROM table_internet WHERE (provedor='"""+str(prov)+"""')"""
    response = json.dumps(consulta_db.consulta_BD(query))
    response = make_response(response)
    return response

#TV
@app.route('/tv')
@app.route('/tv/<prov>')
def getDataTv(prov=None):
    if prov is None:
        query = """SELECT * FROM table_tv"""
    else:
        query = """SELECT * FROM table_tv WHERE (provedor='"""+str(prov)+"""')"""
    response = json.dumps(consulta_db.consulta_BD(query))
    response = make_response(response)
    return response

#USUARIO

#Infos
@app.route('/usuario/<email>')
def getUsuario(email=None):
    query = """SELECT * FROM table_usuario WHERE (email='"""+str(email)+"""')"""
    response = json.dumps(consulta_db.consulta_BD(query))
    response = make_response(response)
    return response

#Login
@app.route('/login', methods=['POST'])
def login():
    data = json.dumps([{'Authorized': completion}])
    resp = make_response(data)

    if request.method == 'POST':
        data = request.json
        email = data.get("email")
        senha = data.get("senha")

        completionAux = auth.authenticate(email, senha)

        if completionAux == False:
            data = json.dumps([{'Authorized' : completionAux, 'msg': "Bad email or password"}])
            return get_response(data), 401

        data = json.dumps([{
            'Authorized' : completionAux,
            'access_token' : create_access_token(identity=email),
            'refresh_token' : create_refresh_token(identity=senha)
        }])
        return make_response(data), 200

    return resp

#Logout
@app.route('/logout', methods=['POST'])
@jwt_required
def logout():
    data = json.dumps([{'Authorized' : completion}])
    resp = make_response(data)

    if request.method == 'POST':
        try:
            _revoke_current_token()
            completionAux = False
        except KeyError:
            return make_response(json.dumps([{
                'msg': 'Access token not found in the blacklist store'
            }])), 500

        data = json.dumps([{'Authorized' : completionAux, "msg": "Logged Out"}])
        return make_response(data), 200

    return resp

#Cadastro
@app.route('/cadastro', methods=['POST'])
def singUp():
    data = request.json
    nome = data.get("nome")
    email = data.get("email")
    senha = data.get("senha")
    ddd = data.get("ddd")
    sexo = data.get("sexo")

    hashed_pwrd = hash_all(email, realm, senha)

    query = """INSERT INTO table_usuario (nome, email, senha, ddd, sexo) VALUES ('"""+\
            str(nome)+"""','"""+str(email)+"""','"""+str(hashed_pwrd)+"""',"""+ddd+""",'"""+str(sexo)+"""')"""
    print(query)
    response = json.dumps(consulta_db.update_BD(query))
    response = make_response(response)

    return response

