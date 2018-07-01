'''
title           : blockchain.py
description     : A blockchain implemenation 
authors         : Dickson Lim, Tan Kok Hui, Yoong Hor Meng
date_created    : 26 May 2018
date_modified   : 9 June 2018
version         : 0.1
usage           : python blockchain.py
                  python blockchain.py -p 5000
                  python blockchain.py --port 5000
python_version  : 3.6.5
Comments        : The blockchain implementation is mostly based on [1] and [2]. 
                  Code was modified to meet project requirements of Blockchain Developer Course 
                  in Singapore (May 2018) 
                  
References      : [1] https://github.com/dvf/blockchain/blob/master/blockchain.py
                  [2] https://github.com/adilmoujahid/blockchain-python-tutorial
'''

from collections import OrderedDict
from flask import Flask, jsonify, request, render_template
from Crypto.Random import random
from pycoin.ecdsa import generator_secp256k1, sign, verify
from urllib.parse import urlparse
import hashlib, os, json, binascii, datetime, requests 
from time import time
from uuid import uuid4
from flask_cors import CORS

MINING_SENDER = "THE BLOCKCHAIN"
MINING_REWARD = 5000000
MINING_DIFFICULTY = 2

class Blockchain:

    def __init__(self):        
        #List of pending transactions
        self.transactions = []
        #List of blocks in the blockchain
        self.chain = []
        #List of neighbour nodes (peers)
        self.nodes = set()
        #Dictionary of block candidate map to blockDataHash
        self.block_candidate_map = {}
        #Generate random number to be used as node_id
        self.node_id = str(uuid4()).replace('-', '')
        #Create genesis block
        self.createGenesisBlock()

    # Transfer coins to faucet (addr = 255eb98...)
    def createGenesisBlock(self):
        transaction = {"from": "0000000000000000000000000000000000000000",
                       "to": "255eb98d31880f6c5ce9180970c9fd65d17053f1",
                       "value": 1000000000000,
                       "fee": 0,
                       "dateCreated": "2018-01-01T00:00:00.000Z",
                       "data": "genesis txn",
                       "senderPubKey": "00000000000000000000000000000000000000000000000000000000000000000",
                       "transactionDataHash": "8a684cb8491ee419e7d46a0fd2438cad82d1278c340b5d01974e7beb6b72ecc2", "senderSignature": 
                       ["0000000000000000000000000000000000000000000000000000000000000000","0000000000000000000000000000000000000000000000000000000000000000"],"minedInBlockIndex": 0, 
                       "transferSuccessful": "True"}
        self.transactions.append(transaction)
        block = {'index': 0,
                'transactions': self.transactions,
                "difficulty": 0,
                "prevBlockHash": "c6da93eb4249cb5ff4f9da36e2a7f8d0d61999221ed6910180948153e71cc47f",
                "minedBy": "0000000000000000000000000000000000000000",
                "blockDataHash": "15cc5052fb3c307dd2bfc6bcaa057632250ee05104e4fb7cc75e59db1a92cefc",
                "nonce": 0,
                "dateCreated": "2018-01-01T00:00:00.000Z",
                "blockHash": "c6da93eb4249cb5ff4f9da36e2a7f8d0d61999221ed6910180948153e71cc47f"
                }
        self.chain.append(block)
        self.transactions = []
        return block
        
    def register_node(self, node_url):
        """
        Add a new node to the list of nodes
        """
        #Checking node_url has valid format
        parsed_url = urlparse(node_url)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')


    def submit_transaction(self, _transaction):
        """
        Add a transaction to transactions array if the signature verified
        """
        transaction = _transaction
        self.transactions.append(transaction)
        return len(self.chain) + 1
        

    def hash(self, block):
        """
        Create a SHA-256 hash of a block
        """
        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()


    def resolve_conflicts(self):
        """
        Resolve conflicts between blockchain's nodes
        by replacing our chain with the longest one in the network.
        """
        neighbours = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            print('http://' + node + '/chain')
            response = requests.get('http://' + node + '/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                # if length > max_length and self.valid_chain(chain):
                if length > max_length:
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False

    def submit_minedBlockHash(self, _minedBlockHash):
        # Retrieve block candidate based on block data hash
        block_candidate = self.block_candidate_map[_minedBlockHash['blockDataHash']]
        # Add data from miner to block candidate
        block_candidate['nonce'] = _minedBlockHash['nonce']
        block_candidate['dateCreated'] = _minedBlockHash['dateCreated']
        block_candidate['blockHash'] = _minedBlockHash['blockHash']
        self.transactions = []
        self.chain.append(block_candidate)
        self.block_candidate_map.clear()
        return block_candidate

def sha256(msg: str) -> int:
    hash_bytes = hashlib.sha256(msg.encode("utf8")).digest()
    return int.from_bytes(hash_bytes, byteorder="big")

def mineBlockHash(_blockDataHash, _difficulty):
    nonce = 1
    zero_string = '00000000000000000000000000000'
    dateCreated = datetime.datetime.now().isoformat() + "Z"
    
    while True:
      t = _blockDataHash + "|" + dateCreated + "|" + str(nonce)
      mined_hash = hashlib.sha256(t.encode("utf8")).hexdigest()
      if mined_hash[:_difficulty] == zero_string[:_difficulty]:
          break
      nonce = nonce + 1
    
    minedBlockHash = { 
        "blockDataHash": _blockDataHash, 
        "dateCreated": dateCreated, 
        "nonce": str(nonce), 
        "blockHash": mined_hash 
    }
    return minedBlockHash  


def getConfirmedBalanceByAddress(_address):
    confirmed_balance = 0
    #confirmed balance from mined transactions in the chain
    for i in range(0, len(blockchain.chain)):
        for j in range(0, len(blockchain.chain[i]["transactions"])):
            trans = blockchain.chain[i]["transactions"][j]
            if trans["from"] == _address:
                confirmed_balance -= trans["value"]
                confirmed_balance -= trans["fee"]
            if trans["to"] == _address:
                confirmed_balance += trans["value"]
    return confirmed_balance
      
      
# Instantiate the Node
app = Flask(__name__)
CORS(app)

# Instantiate the Blockchain
blockchain = Blockchain()

@app.route('/')
def index():
    return render_template('./index.html')

    
@app.route('/configure')
def configure():
    return render_template('./configure.html')


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.form

    # Check that the required fields are in the POST'ed data
    required = ['from', 'to', 'value', 'fee', 'dateCreated', 'data', 'senderPubKey', 'transactionDataHash','senderSignature']
    if not all(k in values for k in required):
        return 'Missing values', 400
    
    # Check available balance
    if (getConfirmedBalanceByAddress(values["from"]) < (int(values["value"]) + int(values["fee"]))):
        return 'Sender has insufficient balance', 400
        
    # Check transaction data hash
    transaction = {"from": values["from"],
                   "to": values["to"],
                   "value": int(values["value"]),
                   "fee": int(values["fee"]),
                   "dateCreated": values["dateCreated"],
                   "data": values["data"],
                   "senderPubKey": values["senderPubKey"]
                  }
    json_encoder = json.JSONEncoder(separators=(',',':'))
    tran_json = json_encoder.encode(transaction)
    tran_hash = sha256(tran_json)
    tran_hash_hex = hex(tran_hash)[2:]
    if (tran_hash_hex != values["transactionDataHash"]):
        print("Invalid txn hash")
        print("Received:",values["transactionDataHash"])
        print("Calculated:",tran_hash_hex)
        return 'Invalid transaction data hash', 400
    print("Transaction data hash is valid")
    
    # Create a new Transaction
    transaction = {"from": values["from"],
                   "to": values["to"],
                   "value": int(values["value"]),
                   "fee": int(values["fee"]),
                   "dateCreated": values["dateCreated"],
                   "data": values["data"],
                   "senderPubKey": values["senderPubKey"],
                   "transactionDataHash": values["transactionDataHash"],
                   "senderSignature": values["senderSignature"],
                   "minedInBlockIndex": len(blockchain.chain), 
                   "transferSuccessful": True
                  }
    
    transaction_result = blockchain.submit_transaction(transaction)
    response = {'message': 'Transaction will be added to Block '+ str(transaction_result)}
    return jsonify(response), 201
    

@app.route('/transactions/get', methods=['GET'])
def get_transactions():
    #Get transactions from transactions pool
    transactions = blockchain.transactions
    response = {'transactions': transactions}
    return jsonify(response), 200


@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


@app.route('/getBalance', methods=['POST'])
def getBalance():
    confirmed_balance=0
    pending_balance=0
    #address= "30befa830b9edabbf86d409ed0a5821191e87c09"
    address = request.form['addr']

    #confirmed balance from mined transactions in the chain
    for i in range(0, len(blockchain.chain)):
        for j in range(0, len(blockchain.chain[i]["transactions"])):
            trans = blockchain.chain[i]["transactions"][j]
            if trans["from"] == address:
                confirmed_balance -= trans["value"]
                confirmed_balance -= trans["fee"]
            if trans["to"] == address:
                confirmed_balance += trans["value"]

    #pending balance from unmined transactions
    for i in range(0, len(blockchain.transactions)):
        trans = blockchain.transactions[i]
        if trans["from"] == address:
            pending_balance -= trans["value"]
            pending_balance -= trans["fee"]
        if trans["to"] == address:
            pending_balance += trans["value"]

    response = {
        'confirmed_balance': confirmed_balance,
        'pending_balance': pending_balance
    }
    return jsonify(response), 200


@app.route('/mining/get-mining-job/<miner_address>', methods=['GET'])
def get_mining_job(miner_address):
    
    # Create coinbase transaction
    coinbase_txn = {
        "from": "0000000000000000000000000000000000000000",
        "to": miner_address,
        "value": MINING_REWARD,
        "fee": 0,
        "dateCreated": datetime.datetime.now().isoformat() + "Z",
        "data": "coinbase tx",
        "senderPubKey": "00000000000000000000000000000000000000000000000000000000000000000",
        "transactionDataHash": "",
        "senderSignature": ["0000000000000000000000000000000000000000000000000000000000000000","0000000000000000000000000000000000000000000000000000000000000000"],
        "minedInBlockIndex": len(blockchain.chain),
        "transferSuccessful": True
    }
    # print ("Coinbase: ", coinbase_txn)
    
    # Create transaction list
    block_candidate_txns = []
    block_candidate_txns.append(coinbase_txn)
    for i in range(0, len(blockchain.transactions)):
        trans = blockchain.transactions[i]
        block_candidate_txns.append(trans)
    
    # Get previous block hash
    block = blockchain.chain[len(blockchain.chain) - 1]
    prevBlockHash = block['blockHash']
    # print("Prev block hash: ", prevBlockHash)
    
    # Calculate block data hash
    block_data = {
        "index": len(blockchain.chain),
        "transactions": block_candidate_txns,
        "difficulty": MINING_DIFFICULTY,
        "prevBlockHash": prevBlockHash,
        "minedBy": miner_address,
    }
    
    json_encoder = json.JSONEncoder(separators=(',',':'))
    block_data_json = json_encoder.encode(block_data)
    block_data_hash = sha256(block_data_json)
    block_data_hash_hex = hex(block_data_hash)[2:]
    # print("Block data hash: ", block_data_hash_hex)
    
    # Create block candidate
    block_candidate = {
        "index": len(blockchain.chain),
        "transactions": block_candidate_txns,
        "difficulty": MINING_DIFFICULTY, 
        "prevBlockHash": prevBlockHash,
        "minedBy": miner_address,
        "blockDataHash": block_data_hash_hex
    }
    # print ("Block candidate: ", block_candidate)
    # Map block data hash to block candidate
    blockchain.block_candidate_map[block_data_hash_hex] = block_candidate
    minedBlockHash = mineBlockHash(block_data_hash_hex, MINING_DIFFICULTY)
    minedBlock = blockchain.submit_minedBlockHash(minedBlockHash)
    return jsonify(minedBlock), 200

    
@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.form
    nodes = values.get('nodes').replace(" ", "").split(',')

    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': [node for node in blockchain.nodes],
    }
    return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }
    return jsonify(response), 200


@app.route('/nodes/get', methods=['GET'])
def get_nodes():
    nodes = list(blockchain.nodes)
    response = {'nodes': nodes}
    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port
    app.run(host='127.0.0.1', port=port)
