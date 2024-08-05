import os

import web3
from solcx import set_solc_version, install_solc
from solcx import compile_source
install_solc('0.8.19')
set_solc_version('v0.8.19')
import json,base64
  
        
#Compilation contract
def compile_source_file(file_path):
   with open(file_path, 'r') as f:
      source = f.read()
   return compile_source(source)
#Deployment contracts
def deploy_contract(w3, contract_interface):
    contract = w3.eth.contract(
        abi=contract_interface['abi'],
        bytecode=contract_interface['bin'])
    accounts0 = w3.eth.accounts[0]
    transaction_hash = contract.constructor().transact({'from': accounts0})
    # Wait for the contract to be deployed
    transaction_receipt = w3.eth.wait_for_transaction_receipt(transaction_hash)
    # Get the contract address after deployment
    contract_address = transaction_receipt['contractAddress']
    return contract_address
#Compile the deployment contract (return call object)
def compile_deploy_file(w3, file_path):
    compiled_sol = compile_source_file(file_path)
    contract_id, contract_interface= compiled_sol.popitem()
    address1 = deploy_contract(w3, contract_interface)
    abi1 = contract_interface['abi']
    Contract = w3.eth.contract(address=address1, abi=abi1)    
    return Contract

#Connecting to the server
w3=web3.Web3(web3.HTTPProvider('http://127.0.0.1:7545', request_kwargs={'timeout': 60 * 10}))

#Build and deploy contract_g16.sol
groth_Contract=compile_deploy_file(w3,"contract_g16.sol")


# read JSON file
with open('gorth16_output.json', 'r') as file:
    data = json.load(file)
#call groth contract
result = groth_Contract.functions.verifyProof(data["G_proof"],data["G_input"]).call({'from':w3.eth.accounts[0]})

estimate_gas = groth_Contract.functions.verifyProof(data["G_proof"],data["G_input"]).estimate_gas({'from':w3.eth.accounts[0]})
print(not bool(result))


