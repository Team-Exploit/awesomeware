from flask import request, jsonify
from awesomeware import app

@app.route('/')
def index():
    return jsonify({'status': 'ok'})

@app.route('/postpair', methods=['POST'])
def post_key_pair():
    try:
        privatekey = request.form['privatekey']
        publickey = request.form['publickey']
        auth_key = request.form['auth_key']
    except KeyError:
        return "You asshole"
    if auth_key != 'merhdadisthebestdad':
        return jsonify({
            'status': 'ko',
            'reason': 'You bastard son'})
    with open('privatekey.pem', 'w') as fhandler:
        fhandler.write(privatekey)
    with open('publickey.pem', 'w') as fhandler:
        fhandler.write(publickey)
    return jsonify({'status': 'ok'})

@app.route('/getprivatekey', methods=['GET'])
def get_private_key():
    try:
        publickey = request.args['publickey']
        auth_key = request.args['auth_key']
    except KeyError:
        return ('You asshole')
    if auth_key != 'merhdadisthebestdad':
        return jsonify({
            'status': 'ko',
            'reason': 'You bastard son'})
    with open("publickey.pem", 'r') as fhandler:
        stored_publickey = fhandler.read()
    if publickey == stored_publickey:
        with open("privatekey.pem", 'r') as fhandler:
            privatekey = fhandler.read()
        return jsonify({
            'status': 'ok',
            'privatekey': privatekey
        })
    return jsonify({
        'status': 'ko',
        'reason': 'Not vegan'})
