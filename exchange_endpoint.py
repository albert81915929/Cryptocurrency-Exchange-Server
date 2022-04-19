from web3 import Web3
from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine
from flask import jsonify
import json
import eth_account
import algosdk
from algosdk import mnemonic
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only
from datetime import datetime
import math
import sys
import traceback

# TODO: make sure you implement connect_to_algo, send_tokens_algo, and send_tokens_eth
from send_tokens import connect_to_algo, connect_to_eth, send_tokens_algo, send_tokens_eth

from models import Base, Order, TX,Log
engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

""" Pre-defined methods (do not need to change) """

@app.before_request
def create_session():
    g.session = scoped_session(DBSession)

@app.teardown_appcontext
def shutdown_session(response_or_exc):
    sys.stdout.flush()
    g.session.commit()
    g.session.remove()

def connect_to_blockchains():
    try:
        # If g.acl has not been defined yet, then trying to query it fails
        acl_flag = False
        g.acl
    except AttributeError as ae:
        acl_flag = True
    
    try:
        if acl_flag or not g.acl.status():
            # Define Algorand client for the application
            g.acl = connect_to_algo()
    except Exception as e:
        print("Trying to connect to algorand client again")
        print(traceback.format_exc())
        g.acl = connect_to_algo()
    
    try:
        icl_flag = False
        g.icl
    except AttributeError as ae:
        icl_flag = True
    
    try:
        if icl_flag or not g.icl.health():
            # Define the index client
            g.icl = connect_to_algo(connection_type='indexer')
    except Exception as e:
        print("Trying to connect to algorand indexer client again")
        print(traceback.format_exc())
        g.icl = connect_to_algo(connection_type='indexer')

        
    try:
        w3_flag = False
        g.w3
    except AttributeError as ae:
        w3_flag = True
    
    try:
        if w3_flag or not g.w3.isConnected():
            g.w3 = connect_to_eth()
    except Exception as e:
        print("Trying to connect to web3 again")
        print(traceback.format_exc())
        g.w3 = connect_to_eth()
        
""" End of pre-defined methods """
        
""" Helper Methods (skeleton code for you to implement) """

def log_message(message_dict):
    msg = json.dumps(message_dict)

    # TODO: Add message to the Log table
    log = Log(message = msg)
    g.session.add(log)
    g.session.commit()
    return

# self added
def verify(content):

    #Check if signature is valid
    sig = content['sig']
    payload = content['payload']

    pk = payload['sender_pk']
    platform = payload['platform']

    payload_json = json.dumps(content['payload'])

    if platform =='Ethereum' :
        eth_encoded_msg = eth_account.messages.encode_defunct(text=payload_json)

        if eth_account.Account.recover_message(eth_encoded_msg,signature = hex(int(sig,16)))== pk :
            result = True
        else:
            result = False
    elif platform == 'Algorand':
        if algosdk.util.verify_bytes(payload_json.encode('utf-8'), sig, pk) :
            result = True
        else:
            result = False
    else:
        result = False
    #Should only be true if signature validates
    return jsonify(result)


def get_algo_keys():
    
    # TODO: Generate or read (using the mnemonic secret) 
    # the algorand public/private keys
    # algo_sk, algo_pk = algosdk.generate_account();
    algo_sk = "ne6y1xzYbRPrnVax/5iEVFPGKfnia67yYMWkENlPbjmDzrcaydFr7anA655m7r1nwGFdXxYQEP05fNn9cdiZHA=="
    algo_pk = "QPHLOGWJ2FV63KOA5OPGN3V5M7AGCXK7CYIBB7JZPTM724OYTEOFNFU6LQ"
    return algo_sk, algo_pk


def get_eth_keys(filename = "eth_mnemonic.txt"):
    w3 = Web3()
    
    # TODO: Generate or read (using the mnemonic secret) 
    # the ethereum public/private keys
    w3.eth.account.enable_unaudited_hdwallet_features()
    acct, mnemonic_secret = w3.eth.account.create_with_mnemonic()

    eth_pk = acct._address
    eth_sk = acct._private_key

    return eth_sk, eth_pk



# 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)
def check_valid_order(order_obj):
    tx_id = order_obj.tx_id
    if order_obj.sell_currency == "Ethereum":
        try:
            transaction = w3.eth.get_transaction(tx_id)
            if transaction['value'] == order.sell_amount and transaction['from'] == order.sender_pk:
                # receiver == get_eth_keys()[0]
                return True
            else:
                return False
        except Exception as e:
            return False;

    elif order_obj.sell_currency == "Algorand":
        txes = g.icl.search_transactions(txid=tx_id)
        try:
            for tx in txes:
                if tx['payment-transaction']['amount'] == order.sell_amount and tx['sender'] == order.sender_pk:
                    return True
        except Exception as e:
            return False
    return False





def fill_order(order, txes=[]):
    # TODO: 
    # Match orders (same as Exchange Server II)

    exist_orderlist = g.session.query(Order).filter(Order.creator == None)
    all();
    for exist_order in exist_orderlist:
        if (exist_order.buy_currency == order.sell_currency and exist_order.sell_currency == order.buy_currency
                and exist_order.sell_amount / exist_order.buy_amount >= order.buy_amount / order.sell_amount):
            # existing_order.filled must be None
            if (exist_order.filled == None):

                exist_buy_sell_rate = exist_order.buy_amount / exist_order.sell_amount
                order_buy_sell_rate = order.buy_amount / order.sell_amount

                order.filled = datetime.now()
                exist_order.filled = datetime.now()
                order.counterparty_id = exist_order.id
                exist_order.counterparty_id = order.id

                g.session.commit()
                # update txes
                tx_dict = {'order_id': order.id, 'platform': order.sell_currency,
                           'receiver_pk': order.receiver_pk,
                           'order': exist_order, 'tx_amount': order.sell_amount}
                txes.append(tx_dict)
                txes.append(exist_order)
                # ----------------------------------------------------------------
                if (order.buy_amount < exist_order.sell_amount):
                    new_order = {}
                    new_order['buy_currency'] = exist_order.buy_currency
                    new_order['sell_currency'] = exist_order.sell_currency
                    new_order['buy_amount'] = exist_buy_sell_rate * (exist_order.sell_amount - order.buy_amount)
                    new_order['sell_amount'] = exist_order.sell_amount - order.buy_amount
                    new_order['sender_pk'] = exist_order.sender_pk
                    new_order['receiver_pk'] = exist_order.receiver_pk
                    new_order['creator_id'] = exist_order.id

                    fields = ['sender_pk', 'receiver_pk', 'buy_currency', 'sell_currency', 'buy_amount', 'sell_amount',
                              'creator_id']
                    order_obj_child = Order(**{f: new_order[f] for f in fields})

                    g.session.add(order_obj_child)
                    txes.append(order_obj_child)
                    g.session.commit()

                elif (exist_order.buy_amount < order.sell_amount):
                    new_order = {}
                    new_order['buy_currency'] = order.buy_currency
                    new_order['sell_currency'] = order.sell_currency
                    new_order['buy_amount'] = order_buy_sell_rate * (order.sell_amount - exist_order.buy_amount)
                    new_order['sell_amount'] = order.sell_amount - exist_order.buy_amount
                    new_order['sender_pk'] = order.sender_pk
                    new_order['receiver_pk'] = order.receiver_pk
                    new_order['creator_id'] = order.id

                    fields = ['sender_pk', 'receiver_pk', 'buy_currency', 'sell_currency', 'buy_amount', 'sell_amount',
                              'creator_id']
                    order_obj_child = Order(**{f: new_order[f] for f in fields})

                    g.session.add(order_obj_child)
                    txes.append(order_obj_child)
                    g.session.commit()

                    # Validate the order has a payment to back it (make sure the counterparty also made a payment)
                    # Make sure that you end up executing all resulting transactions!
    # pass
  
def execute_txes(txes):
    if txes is None:
        return True
    if len(txes) == 0:
        return True
    print( f"Trying to execute {len(txes)} transactions" )
    print( f"IDs = {[tx['order_id'] for tx in txes]}" )
    eth_sk, eth_pk = get_eth_keys()
    algo_sk, algo_pk = get_algo_keys()
    
    if not all( tx['platform'] in ["Algorand","Ethereum"] for tx in txes ):
        print( "Error: execute_txes got an invalid platform!" )
        print( tx['platform'] for tx in txes )

    algo_txes = [tx for tx in txes if tx['platform'] == "Algorand" ]
    eth_txes = [tx for tx in txes if tx['platform'] == "Ethereum" ]

    # TODO: 
    #       1. Send tokens on the Algorand and eth testnets, appropriately
    #          We've provided the send_tokens_algo and send_tokens_eth skeleton methods in send_tokens.py
    #       2. Add all transactions to the TX table
    fields = ['platform', 'receiver_pk', 'order_id', 'tx_id']
    send_tokens_algo(acl, algo_sk, algo_txes)
    for tx in algo_txes:
        new_tx = TX(**{f: tx[f] for f in fields})
        g.session.add(new_tx)
        g.session.commit()
    send_tokens_eth(w3,eth_sk,eth_txes)
    for tx in eth_txes:
        new_tx = TX(**{f: tx[f] for f in fields})
        g.session.add(new_tx)
        g.session.commit()
    # pass

""" End of Helper methods"""
  
@app.route('/address', methods=['POST'])
def address():
    if request.method == "POST":
        content = request.get_json(silent=True)
        if 'platform' not in content.keys():
            print( f"Error: no platform provided" )
            return jsonify( "Error: no platform provided" )
        if not content['platform'] in ["Ethereum", "Algorand"]:
            print( f"Error: {content['platform']} is an invalid platform" )
            return jsonify( f"Error: invalid platform provided: {content['platform']}"  )
        
        if content['platform'] == "Ethereum":
            #Your code here
            eth_sk, eth_pk = get_eth_keys()
            return jsonify(eth_pk)
        if content['platform'] == "Algorand":
            #Your code here
            algo_sk, algo_pk = get_algo_keys()

            return jsonify(algo_pk)

@app.route('/trade', methods=['POST'])
def trade():
    print( "In trade", file=sys.stderr )
    connect_to_blockchains()
    get_keys()
    if request.method == "POST":
        content = request.get_json(silent=True)
        columns = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform", "tx_id", "receiver_pk"]
        fields = [ "sig", "payload" ]
        error = False
        for field in fields:
            if not field in content.keys():
                print( f"{field} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print( f"{column} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        # Your code here
        
        # 1. Check the signature
        
        # 2. Add the order to the table
        if verify(content):
            order = {}
            order['signature'] = content['sig']
            order['buy_amount'] = content['payload']['buy_amount']
            order['sell_amount'] = content['payload']['sell_amount']
            order['sender_pk'] = content['payload']['sender_pk']
            order['receiver_pk'] = content['payload']['receiver_pk']
            order['sell_currency'] = content['payload']['sell_currency']
            order['buy_currency'] = content['payload']['buy_currency']
            order['tx_id'] = content['payload']['tx_id']

            fields = ['sender_pk', 'receiver_pk', 'buy_currency', 'sell_currency', 'buy_amount',
                      'sell_amount','signature', 'tx_id']
            order_obj = Order(**{f: order[f] for f in fields})


            g.session.add(order_obj)
            g.session.commit()
            txes = []
            if check_valid_order(order_obj):
                fill_order(order_obj,txes)
                execute_txes(txes)
        else:
            log_message(content['payload'])
            return jsonify(False)

        # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)

        # 3b. Fill the order (as in Exchange Server II) if the order is valid
        
        # 4. Execute the transactions
        
        # If all goes well, return jsonify(True). else return jsonify(False)
        return jsonify(True)

@app.route('/order_book')
def order_book():
    fields = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "signature", "tx_id", "receiver_pk", "sender_pk" ]
    
    # Same as before
    # added
    orders = []
    for order in g.session.query(Order):
        order_dict = {}

        order_dict['sender_pk'] = order.sender_pk
        order_dict['receiver_pk'] = order.receiver_pk
        order_dict['buy_currency'] = order.buy_currency
        order_dict['sell_currency'] = order.sell_currency
        order_dict['buy_amount'] = order.buy_amount
        order_dict['sell_amount'] = order.sell_amount
        order_dict['signature'] = order.signature
        order_dict["tx_id"] = order.tx_id

        orders += [order_dict]


    return jsonify(data=orders)
    # added
    # pass

if __name__ == '__main__':
    app.run(port='5002')