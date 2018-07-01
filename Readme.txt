# How to run the code

. 

To start a blockchain node, go to ```blockchain``` folder and execute the command below:
python blockchain.py -p 5000


You can add a new node to blockchain by executing the same command and specifying a port that is not already used. For example, python blockchain.py -p 5001


To start the blockchain client, go to ```blockchain_client``` folder and execute the command 
python blockchain_client.py -p 8080


You can access the blockchain frontend and blockchain client dashboards from your browser by going to localhost:5000 and localhost:8080



The blockchain node is also the miner.
The blockchain client is the wallet