'''
title           : blockchain_client.py
description     : A blockchain implemenation 
authors         : Dickson Lim, Tan Kok Hui, Yoong Hor Meng
date_created    : 26 May 2018
date_modified   : 9 June 2018
version         : 0.1
usage           : python blockchain_client.py
                  python blockchain_client.py -p 8080
                  python blockchain_client.py --port 8080
python_version  : 3.6.5
Comments        : The blockchain implementation is mostly based on [1] and [2]. 
                  Code was modified to meet project requirements of Blockchain Developer Course 
                  in Singapore (May 2018) 
                  
References      : [1] https://github.com/dvf/blockchain/blob/master/blockchain.py
                  [2] https://github.com/adilmoujahid/blockchain-python-tutorial
'''

from collections import OrderedDict
from flask import Flask, jsonify, request, render_template, session

from Crypto.Random import random
from pycoin.ecdsa import generator_secp256k1, sign, verify
from urllib.parse import urlparse
import hashlib, os, json, binascii, datetime, requests

class Transaction:

    def __init__(self, sender_address, sender_private_key, recipient_address, value):
        self.sender_address = sender_address
        self.sender_private_key = sender_private_key
        self.recipient_address = recipient_address
        self.value = value

    def __getattr__(self, attr):
        return self.data[attr]

    def to_dict(self):
        return OrderedDict({'sender_address': self.sender_address,
                            'recipient_address': self.recipient_address,
                            'value': self.value})

def get_signed_txn(sender_private_key, recipient_address, value, msg, fee):
    priv_key_hex = sender_private_key
    priv_key_int = private_key_hex_to_int(priv_key_hex)
    pub_key = private_key_to_public_key(priv_key_int)
    pub_key_compressed = get_pub_key_compressed(pub_key)
    pub_addr = public_key_compressed_to_address(pub_key_compressed)
    timestamp = datetime.datetime.now().isoformat()
    timestamp = timestamp + "Z"
    transaction = {"from": pub_addr, "to": recipient_address, "value": int(value), "fee": int(fee), 
    "dateCreated": timestamp, "data": msg, "senderPubKey": pub_key_compressed}
    json_encoder = json.JSONEncoder(separators=(',',':'))
    tran_json = json_encoder.encode(transaction)
    tran_hash = sha256(tran_json)
    tran_hash_hex = hex(tran_hash)[2:]
    tran_signature = sign(generator_secp256k1, priv_key_int, tran_hash)
    element1 = str(hex(tran_signature[0]))[2:]
    element2 = str(hex(tran_signature[1]))[2:]
    tran_signature_str = (element1,element2)
    # Signed txn (appended hash and signature)
    signed_txn = {"from": pub_addr, "to": recipient_address, "value": value, "fee": fee, 
    "dateCreated": timestamp, "data": msg, "senderPubKey": pub_key_compressed,
    "transactionDataHash": tran_hash_hex, "senderSignature": tran_signature_str}
    return signed_txn
    
def private_key_hex_to_int(private_key_hex: str):
    return int(private_key_hex, 16)
    
def private_key_to_public_key(private_key):
    return (generator_secp256k1 * private_key).pair()

def get_pub_key_compressed(pub_key):
    return hex(pub_key[0])[2:] + str(pub_key[1] % 2)

def public_key_compressed_to_address(public_key_compressed):
    return ripemd160(public_key_compressed)

def ripemd160(msg: str) -> str:
  hash_bytes = hashlib.new('ripemd160', msg.encode("utf8")).digest()
  return hash_bytes.hex()

def sha256(msg: str) -> int:
  hash_bytes = hashlib.sha256(msg.encode("utf8")).digest()
  return int.from_bytes(hash_bytes, byteorder="big")  

app = Flask(__name__)
app.secret_key = "any random string"

@app.route('/')
def index():
    return render_template('./index.html')

@app.route('/make/transaction')
def make_transaction():
    return render_template('./make_transaction.html')
    
@app.route('/faucet')
def faucet():
    return render_template('./faucet.html')

@app.route('/view/transactions')
def view_transaction():
    return render_template('./view_transactions.html')

@app.route('/view/balances')
def view_balances():
    return render_template('./check_balance.html')

@app.route('/get_session_var')
def get_session_var():
    response = {
        'wallet_addr': session['wallet_addr'],
        'wallet_key': session['wallet_key']
    }
    return jsonify(response), 200

@app.route('/wallet/new', methods=['GET'])
def new_wallet():
    priv_key_hex = hex(random.getrandbits(256))[2:]
    priv_key_int = private_key_hex_to_int(priv_key_hex)
    pub_key = private_key_to_public_key(priv_key_int)
    pub_key_compressed = get_pub_key_compressed(pub_key)
    pub_addr = public_key_compressed_to_address(pub_key_compressed)
    session['wallet_addr'] = pub_addr
    session['wallet_key'] = priv_key_hex
    response = {
        'private_key': priv_key_hex,
        'public_key': pub_key_compressed,
        'public_addr': pub_addr
    }
    return jsonify(response), 200

@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
    #sender_address = request.form['sender_address']
    sender_private_key = request.form['sender_private_key']
    recipient_address = request.form['recipient_address']
    value = request.form['amount']
    fee = request.form['fee']
    msg = request.form['message']
    response = get_signed_txn(sender_private_key, recipient_address, value, msg, fee)
    return jsonify(response), 200

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8080, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port)