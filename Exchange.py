from web3 import Web3

w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:7545'))
from solcx import compile_standard, install_solc

install_solc("0.8.0")
import json  
import random
import secrets
import sympy  # Needed for mod_inverse
import utils.PVSS as PVSS
import utils.util as util
import utils.AES as AES 
import sys
import time
import subprocess
from py_ecc.bn128 import G1, G2
from py_ecc.bn128 import add, multiply, neg, pairing, is_on_curve
from py_ecc.bn128 import curve_order as CURVE_ORDER
from py_ecc.bn128 import field_modulus as FIELD_MODULUS
from typing import Tuple, Dict, List, Iterable, Union
from py_ecc.fields import bn128_FQ as FQ


with open("Contracts/Exchange.sol", "r") as file:
    contact_list_file = file.read()

compiled_sol = compile_standard(
    {
        "language": "Solidity",
        "sources": {"Exchange.sol": {"content": contact_list_file}},
        "settings": {
            "outputSelection": {
                "*": {
                    "*": ["abi", "metadata", "evm.bytecode", "evm.bytecode.sourceMap"]
                    # output needed to interact with and deploy contract
                }
            }
        },
    },
    solc_version="0.8.0",
)

# print(compiled_sol)
with open("compiled_code.json", "w") as file:
    json.dump(compiled_sol, file)
# get bytecode
bytecode = compiled_sol["contracts"]["Exchange.sol"]["Exchange"]["evm"]["bytecode"]["object"]
# get abi
abi = json.loads(compiled_sol["contracts"]["Exchange.sol"]["Exchange"]["metadata"])["output"]["abi"]
# Create the contract in Python
contract = w3.eth.contract(abi=abi, bytecode=bytecode)

chain_id = 5777
accounts0 = w3.eth.accounts[0]
transaction_hash = contract.constructor().transact({'from': accounts0})
# Wait for the contract to be deployed
transaction_receipt = w3.eth.wait_for_transaction_receipt(transaction_hash)
# Get the deployed contract address
contract_address = transaction_receipt['contractAddress']
# print(" contract deployed, address: ", contract_address)
Contract = w3.eth.contract(address=contract_address, abi=abi)

keccak_256 = Web3.solidity_keccak


"""
# 128位的AES密钥
key = b'0123456789abcdef0123456789abcdef'
print(type(key))
message = b'Hello, AESDJAKJDKLAJDALKJDALKJDAOID789765456AOIJA,DAKJDLKAJDAKNDM,ANDAKHDJKASHDJKADAM encryption!1564987564654564897987894545645623'

encrypted_data = AES.Encrypt(key, message)
print("Encrypted data:", encrypted_data)
decrypted_data = AES.Decrypt(key,encrypted_data)
print("Decrypted data:", decrypted_data.decode('utf-8'))

print(type(decrypted_data.decode('utf-8')))
"""
H1 = multiply(G1, 9868996996480530350723936346388037348513707152826932716320380442065450531909)  # Generator H1

def seller_commit_data(seller_address, n: int, t: int, secret:bytes):

    s = PVSS.random_scalar()
    #print("anwser:",multiply(G1,s))
    binary_str=bin(int(multiply(G1,s)[0]))[2:130]
    # 将二进制字符串转换为整数
    decimal_num = int(binary_str, 2)
    # 将整数转换为bytes类型
    # 128位的AES密钥
    key = decimal_num.to_bytes((len(binary_str) + 7) // 8, 'big')

    shares = PVSS.Share(s, H1, pk, n, t)
    #print(shares["c"])
    agg = util.Dataconvert(shares)  # Data transformation  for data of PVSS.Share
    dleq_proof = []
    for i in range(0, n):
        temp = util.Point2IntArr(shares["DLEQ_Proof"][i])
        dleq_proof.extend([temp])
    # Convert for DLEQ Proof data format
    #key = b'2934a65826d016786c2687bd6e647036'
    #print(key)
    encrypted_data = AES.Encrypt(key, secret)
    #print("Encrypted data:", encrypted_data)
    #decrypted_data = AES.Decrypt(key,encrypted_data)
    #print("Decrypted data:", decrypted_data.decode('utf-8'))
    Contract.functions.SellerUpload(agg["c1"], agg["c2"], agg["v1"], agg["v2"], 
                                    dleq_proof,encrypted_data,seller_address).transact({'from': seller_address})
    #print(type(decrypted_data.decode('utf-8')))
    zkSNARKs_Hash=str(key)+str(shares)+str(encrypted_data)+str(secret)
    #print(zkSNARKs_Hash)
    #print(type(zkSNARKs_Hash))
    with open('zkSNARKs_Hash.txt', 'w') as file:
    # 要写入的字符串
    # 将字符串写入文件
        file.write(zkSNARKs_Hash)

    return key,s


def NormalExchange(key):
    encrypted_data=Contract.functions.DownloadCiphertext().call()
    decrypted_data = AES.Decrypt(key,encrypted_data)
    print("Decrypted data:", decrypted_data.decode('utf-8'))
    

def Recovery(pk,sk,t):
    shares=[]
    for i in range(0,t):
        sh=TTP_decrypt(i+1, pk[i], sk[i])
        shares.extend([sh])


    t1 = time.time()
    result=PVSS.Reconstruct(shares)    #off-chain
    elapsed_time_ms = (time.time() - t1) * 1000
    print(f'enc:{elapsed_time_ms:.4f}ms')
    #result=Contract.functions.Reconstruction().call()
    binary_str=bin(int(result[0]))[2:130]
    # 将二进制字符串转换为整数
    decimal_num = int(binary_str, 2)
    # 将整数转换为bytes类型
    # 128位的AES密钥
    key = decimal_num.to_bytes((len(binary_str) + 7) // 8, 'big')
    encrypted_data=Contract.functions.DownloadCiphertext().call()
    decrypted_data = AES.Decrypt(key,encrypted_data)
    print("Decrypted data:", decrypted_data.decode('utf-8'))



    

def TTP_decrypt(No: int, pk_i, sk_i):
    """
        The function defines the transactions that a tallier T_i should complete
        No denotes the number of tallier, for example: No 1 is the tallier1 and (pk_1, sk_1) is the key of tallier1
    """

    aggCV = Contract.functions.DownloadShare(No).call()
    # Download the accumulated V,C data from the chain

    C_i = (FQ(aggCV[0]), FQ(aggCV[1]))
    # Data transformation
    
    sh1 = PVSS.Decrypt(C_i, sk_i)
    # Call PVSS.Decrypt function to decrypt the cumulative share C*

    proof = PVSS.DLEQ(G1, pk_i, sh1, C_i, sk_i)
    # Generate DLEQ P_Proof, proof is the share c decrypted by this tallier T_i

    result=Contract.functions.Decrypted_ShareUpload(No, util.Point2IntArr(sh1), util.Point2IntArr(proof)).call(
        {'from': w3.eth.accounts[0]})
    # upload the decrypted share and P_Proof to the chain.
    # Once verified, keep the decrypted share in the DecryptedShare array on the chain
    print("TTP", No, "done","  verify result:",result)
    if(result==True):
        return sh1

def SmartContract_Verify():
    # 编译Go文件
    cmd = ['go', 'build', 'main.go']
    subprocess.run(cmd)

    # 执行可执行文件
    cmd = ['./main']
    subprocess.run(cmd)

    result=Contract.functions.PVSS_Verify().call()
    print("PVSS.Verify result:",result)
    return result

if __name__ == '__main__':
    #n = int(sys.argv[1])
    n=int(30)
    # Set the number n of talliers

    t = int(n / 2)+1
    # Set the threshold value t
    print("...........................................Initialization.............................................", n, t)

    key = PVSS.Setup(n, t)
    # PVSS Key Generation

    pk = key["pk"]  # Set public key array
    sk = key["sk"]  # Set private key array
    pks = [util.Point2IntArr(pk[i]) for i in range(n)]  # Data transformation
    Contract.functions.Set_TTPs_PKs(pks).transact({'from': w3.eth.accounts[0]})
    sk_buyer = PVSS.random_scalar()
    pk_buyer = multiply(G1,sk_buyer)

    print("............................................Commit_data.....................................................")
    
    #print( Contract.functions.show(w3.eth.accounts[0]).call())

    secret = b'Hello, AESDJAKJDKLAJDALKJDALKJDAOID444444889sfsdfsdf789765456AOIJA,DAKJDLKAJDAKNDM,ANDAKHDJKASHDJKADAM encryption!1564987564654564897987894545645623'
    key_aes = seller_commit_data(w3.eth.accounts[2], n,t,secret)
    #print( Contract.functions.show(w3.eth.accounts[0]).call())
    result=SmartContract_Verify()

    print("..........................................Transfer_asset.....................................................")
    
    if(result==True):
        Contract.functions.BuyerUpload(w3.eth.accounts[3],30000000000000000).transact({'from': w3.eth.accounts[3],'value': 30000000000000000})
        print("Buyer had lock asset")
        Contract.functions.ETHtransfer(w3.eth.accounts[2]).transact({'from': w3.eth.accounts[2]})
        print("Buyer had transfer asset to Seller")

    
    print("............................................Reveal_key....................................................")
    #print(key_aes[1])
    c_e = multiply(pk_buyer,key_aes[1])
    pub=multiply(H1,key_aes[1])
    #print(int(key_aes))
    
    proof=PVSS.DLEQ(H1,pub,pk_buyer,c_e,key_aes[1])

    res=Contract.functions.DLEQ_verify(util.Point2IntArr(H1),util.Point2IntArr(pub),util.Point2IntArr(pk_buyer),util.Point2IntArr(c_e),util.Point2IntArr(proof)).call()
    print("DLEQ result: ",res)
    if(res==True):
        re=PVSS.Decrypt(c_e,sk_buyer) 

        #print("anwser:",multiply(G1,s))
        binary_str=bin(int(re[0]))[2:130]
        # 将二进制字符串转换为整数
        decimal_num = int(binary_str, 2)
        # 将整数转换为bytes类型
        # 128位的AES密钥
        key2 = decimal_num.to_bytes((len(binary_str) + 7) // 8, 'big')

        encrypted_data=Contract.functions.DownloadCiphertext().call()
        decrypted_data = AES.Decrypt(key2,encrypted_data)  
        print("Decrypted data:", decrypted_data.decode('utf-8'))
        #print(re)
        #print(multiply(G1,key_aes[1]))

    else:   
        print("............................................Recovery (optional)....................................................")
        Recovery(pk,sk,n)
    #NormalExchange(key_aes[0])
    
        
    #Recovery1(pk,sk,n)
    #print(Contract.functions.show2().call())
    
    




    
    
    





