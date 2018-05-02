from flask import request, jsonify
from awesomeware import app

@app.route('/')
def index():
    return jsonify({'status': 'ok'})

@app.route('/toto')
def toto():
    magic = "Toto is the best"
    return jsonify(magic)
