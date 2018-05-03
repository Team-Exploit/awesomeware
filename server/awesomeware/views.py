from flask import request, jsonify
from awesomeware import app

@app.route('/')
def index():
    return jsonify({'status': 'ok'})

@app.route('/toto')
def toto():
    magic = "Toto is the best"
    return jsonify(magic)

@app.route('/postpair', methods=['POST'])
def post_key_pair():
    try:
        privatekey = request.form['privatekey']
        publickey = request.form['publickey']
    except KeyError:
        return "You asshole"
    # put the keys in database OR json
    return jsonify({'status': 'ok'})

@app.route('/getprivatekey', methods=['GET'])
def get_private_key():
    try:
        publickey = request.headers['Publickey']
    except KeyError:
        return ('You asshole')
    # Match public key
    # Return privatekey
    return jsonify({
        'status': 'ok',
        'privatekey': "12345678987654323456789"
        })
