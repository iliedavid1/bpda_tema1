from multiversx_sdk import (ProxyNetworkProvider, Transaction, Address, TokenTransfer, TransactionComputer, UserSigner, QueryRunnerAdapter,
                            SmartContractQueriesController, TokenPayment, TransactionPayload)
from pathlib import Path
from multiversx_sdk import SmartContractTransactionsFactory
from multiversx_sdk.core.tokens import Token, TokenTransfer
from multiversx_sdk.core.transactions_factories.smart_contract_transactions_factory import IConfig
import hashlib
import asyncio
import time

# decode data from nftSuply
def decode_data(data):
    offset = 0
    data_length = len(data)

    token_type = data[offset]
    offset += 1

    amount = int.from_bytes(data[offset:offset], "big")
    offset += 4

    frozen = bool(data[offset])
    offset += 1

    offset += 4
    hash_value = None
    hash_value = data[offset:offset + 33].hex()
    offset += 33

    name_length = int.from_bytes(data[offset:offset + 4], "big")
    offset += 4    
    name = data[offset:offset + name_length].decode()
    offset += name_length

    attributes_length = int.from_bytes(data[offset:offset + 4], "big")
    offset += 4
    attributes = data[offset:offset + attributes_length]
    offset += attributes_length


    return {
        "token_type": token_type,
        "amount": amount,
        "frozen": frozen,
        "hash": hash_value,
        "name": name,
        "attributes": attributes
    }

def get_account_nonce(proxy_url, sender_address):
    proxy = ProxyNetworkProvider(proxy_url)
    sender = Address.from_bech32(sender_address)
    account_info = proxy.get_account(sender)
    return account_info.nonce

def create_nft(proxy_url, sender_address, token_identifier, name, attributes, quantity, royalties, nft_hash):
    current_nonce = get_account_nonce(proxy_url, sender_address)
    print(f"Current Nonce: {current_nonce}")
    
    # Initialize the provider
    proxy = ProxyNetworkProvider(proxy_url)

    # Prepare sender address
    sender_b32 = Address.from_bech32(sender_address)
    sender = sender_b32.bech32()

    uris = ["https://img.freepik.com/photos-gratuite/gros-plan-iguane-dans-nature_23-2151718775.jpg"]
    quantity = 1

    signer = UserSigner.from_pem_file(Path("/home/iliedavid123/bpda/new_wallet.pem"))

    encoded_token_identifier = token_identifier.encode("utf-8").hex()
    encoded_name = name.encode("utf-8").hex()
    encoded_royalties = format(royalties, "x")
    encoded_attributes = int.from_bytes(attributes, byteorder='big')
    encoded_uris = [uri.encode("utf-8").hex() for uri in uris]

    # Transaction data
    transaction_data = f"ESDTNFTCreate@{encoded_token_identifier}@01@{encoded_name}@09c4@{nft_hash}@{encoded_attributes:06x}@{encoded_uris[0]}".encode("utf-8")
    transaction = Transaction(
        sender=sender,
        receiver=sender,
        gas_limit=60000000,
        value="0",
        data=transaction_data,
        chain_id="D",
        nonce=current_nonce
    )

    transaction_computer = TransactionComputer()

    # Sign the transaction with the sender's private key
    transaction.signature = signer.sign(transaction_computer.compute_bytes_for_signing(transaction))

    # Send the transaction
    tx_hash = proxy.send_transaction(transaction)
    print(f"NFT creation transaction sent! Tx Hash: {tx_hash}")
    time.sleep(2)
    while True:
        status = proxy.get_transaction_status(tx_hash)
        print(f"Transaction Status: {status}")
        if not status.is_pending():
            break
        time.sleep(5)
    return tx_hash

def get_nonce(attributes, data_parts):
    for idx, metadata in enumerate(data_parts, start=1):
        try:
            metadata = decode_data(metadata)
        except:
            metadata = None
        nft = {
            "nonce": idx,
            "metadata": metadata
        }
        if metadata is None:
            continue
        if (metadata["attributes"].hex() == attributes):
            print("Nonce: " + str(idx) + "  " + str(metadata))
            return idx, metadata["attributes"]

def create_token_transfer_data(token_id, token_nonce, amount):

    token_id_hex = token_id.encode("utf-8").hex()
    token_nonce_hex = f"{token_nonce:016x}"
    amount_hex = f"{amount:016x}"
    return f"{token_id_hex}@{token_nonce_hex}@{amount_hex}"

class Config(IConfig):
    def __init__(self):
        self.chain_id = "D"
        self.gas_limit_guard_account = 10_000_000
        self.gas_limit_per_byte = 1_500
        self.gas_limit_persist_per_byte = 2_000
        self.gas_limit_save_key_value = 5_000
        self.gas_limit_set_guardian = 20_000_000
        self.gas_limit_store_per_byte = 2_500
        self.gas_limit_unguard_account = 10_000_000
        self.min_gas_limit = 15_000_000

# call exchangeNft endpoint
async def exchange_nft(proxy_url, wallet_address, contract_address, nonce, token_id, token_nonce):
    proxy = ProxyNetworkProvider(proxy_url)

    sender = Address.from_bech32(wallet_address)

    account_info = proxy.get_account(sender)
    current_nonce = get_account_nonce(proxy_url, sender_address)

    token = Token(token_id, token_nonce)
    token_transfer = TokenTransfer(token, 1)
    signer = UserSigner.from_pem_file(Path("/home/iliedavid123/bpda/new_wallet.pem"))
    chain_id = "D"

    config = Config()

    factory = SmartContractTransactionsFactory(config)

    transaction = factory.create_transaction_for_execute(
        sender=sender,
        contract=contract_address,
        function="exchangeNft",
        arguments=[nonce],
        gas_limit=60000000,
        token_transfers=[token_transfer]
    )
    transaction.nonce = current_nonce
    transaction.chain_id = chain_id

    transaction_computer = TransactionComputer()

    transaction.signature = signer.sign(transaction_computer.compute_bytes_for_signing(transaction))

    tx_hash = proxy.send_transaction(transaction)
    print(f"Transaction Hash: {tx_hash}")
    return tx_hash

# call the getYourNftCardProperties endpoint to get properties
def get_prop(proxy_url, wallet_address, contract_address):
    proxy = ProxyNetworkProvider(proxy_url)

    sender = Address.from_bech32(wallet_address)

    account_info = proxy.get_account(sender)
    current_nonce = get_account_nonce(proxy_url, sender_address)

    signer = UserSigner.from_pem_file(Path("/home/iliedavid123/bpda/new_wallet.pem"))
    chain_id = "D"

    config = Config()

    factory = SmartContractTransactionsFactory(config)

    transaction = factory.create_transaction_for_execute(
        sender=sender,
        contract=contract_address,
        function="getYourNftCardProperties",
        arguments=[],
        gas_limit=60000000,
        token_transfers=[]
    )
    transaction.nonce = current_nonce
    transaction.chain_id = chain_id

    transaction_computer = TransactionComputer()

    transaction.signature = signer.sign(transaction_computer.compute_bytes_for_signing(transaction))

    tx_hash = proxy.send_transaction(transaction)
    print(f"Transaction for Prop Hash: {tx_hash}")
    time.sleep(1)

    while True:
        status = proxy.get_transaction_status(tx_hash)
        print(f"Transaction Status: {status}")
        if not status.is_pending():
            break
        time.sleep(5)
    if (status.is_successful()):
        transaction_details = proxy.get_transaction(tx_hash)
        print(f"Transaction Details: {transaction_details}")
        event = transaction_details.logs.events[0]
        data = str(event.additional_data[0]).split('@')[-1]
        print(data)
        return data

    return None


# get attributes
query_runner = QueryRunnerAdapter(ProxyNetworkProvider("https://devnet-gateway.multiversx.com"))
query_controller = SmartContractQueriesController(query_runner)
contract_address = Address.from_bech32("erd1qqqqqqqqqqqqqpgqeq48vn8w9zv8x04tcgkmrphkque3ldm0uvaqpsdw8a")
sender_address = "erd14mkk6pqeuya6xdy442yv2najjry35jzje79s997dka7fesld7wcs7jqumx"
proxy_url = "https://devnet-api.multiversx.com"

attributes = get_prop(proxy_url, sender_address, contract_address)

#get nonce
query = query_controller.create_query(
    contract=contract_address.to_bech32(),
    function="nftSupply",
    arguments=[]
)

response = query_controller.run_query(query)
data_parts = query_controller.parse_query_response(response)

nft_nonce, attributes_nft = get_nonce(attributes, data_parts)

# create nft
token_identifier = "BPDA-6c0a5f"
name = "david.ilie"
quantity = 1
nft_hash = hashlib.sha256(attributes.encode("utf-8")).hexdigest()
royalties = 2500

create_nft(proxy_url, sender_address, token_identifier, name, attributes_nft, quantity, royalties, nft_hash)

your_nft_nonce = 19
asyncio.run(exchange_nft(proxy_url, sender_address, contract_address, nft_nonce, token_identifier, 19))
