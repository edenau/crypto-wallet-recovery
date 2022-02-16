def base58(address_hex):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    b58_string = ''
    # Get the number of leading zeros and convert hex to decimal
    leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
    # Convert hex to decimal
    address_int = int(address_hex, 16)
    # Append digits to the start of string
    while address_int > 0:
        digit = address_int % 58
        digit_char = alphabet[digit]
        b58_string = digit_char + b58_string
        address_int //= 58
    # Add '1' for each 2 leading zeros
    ones = leading_zeros // 2
    for one in range(ones):
        b58_string = '1' + b58_string
    return b58_string

def seed2entropy(seed, extra_word=None):
    """Phrase (+Extra Word) -> Entropy Bytes"""
    from mnemonic import Mnemonic
    assert isinstance(seed, str), 'seed should be str'
    if extra_word is None:
        extra_word = ''
    assert isinstance(extra_word, str), 'extra_word should be str or None'

    mnemo = Mnemonic('english')
    return mnemo.to_seed(seed, passphrase=extra_word)

def entropy2prvhex(entropy, derivation_path):
    """Entropy Bytes -> Private Key Hex"""
    from bip32utils import BIP32Key, BIP32_HARDEN
    assert isinstance(derivation_path, str), 'str_ should be str'
    path_list = derivation_path.split('/')
    assert path_list[0] == 'm', 'Derivation path should start with char "m"'

    xkey = BIP32Key.fromEntropy(entropy).ExtendedKey()
    key = BIP32Key.fromExtendedKey(xkey)
    for path in path_list[1:]:
        if path[-1] == "'":
            key = key.ChildKey(int(path[:-1])+BIP32_HARDEN)
        else:
            key = key.ChildKey(int(path))
    return key.PrivateKey().hex()

def prvhex2pubhex_bitcoin_uncompressed(prvhex):
    """Private Key Hex -> Bitcoin Uncompressed Public Key Hex"""
    import ecdsa
    prvkey_bytes = bytes.fromhex(prvhex)
    # pubkey_body = concat(x,y) where (x,y) = ecdsa_secp256k1(prvkey)
    pubkey_raw = ecdsa.SigningKey.from_string(prvkey_bytes, curve=ecdsa.SECP256k1).verifying_key
    pubkey_bytes = pubkey_raw.to_string()
    # pubkey = concat(prefix_byte=\x04, pubkey_body)
    return (b'\x04'+pubkey_bytes).hex()

def prvhex2pubhex_bitcoin(prvhex):
    """Private Key Hex -> Bitcoin Compressed Public Key Hex"""
    import ecdsa
    prvkey_bytes = bytes.fromhex(prvhex)
    # (x,y) = ecdsa_secp256k1(prvkey)
    pubkey_raw = ecdsa.SigningKey.from_string(prvkey_bytes, curve=ecdsa.SECP256k1).verifying_key

    # pubkey_body = x in (x,y)
    # prefix_byte = \x02 if is_even(pubkey_body[-1]) else \x03
    # pubkey = concat(prefix_byte, pubkey_body)
    return pubkey_raw.to_string('compressed').hex()

def pubhex2address_bitcoin_legacy(pubhex):
    """Public Key Hex -> Bitcoin Legacy Address"""
    import hashlib
    pubkey_bytes = bytes.fromhex(pubhex)

    # network_byte = \x00 if mainnet
    # address_body = concat(network_byte, ripemd160(sha256(pubkey)))
    hashed_pubkey_bytes = hashlib.sha256(pubkey_bytes).digest()
    appended_hashed_hashed_pubkey_bytes = b'\x00' + hashlib.new('ripemd160', hashed_pubkey_bytes).digest()

    # checksum = sha256(sha256(address_body))[:4]
    checksum = hashlib.sha256(hashlib.sha256(appended_hashed_hashed_pubkey_bytes).digest()).digest()[:4]

    # address = base58(concat(address_body, checksum))
    address_hex = (appended_hashed_hashed_pubkey_bytes+checksum).hex()
    return base58(address_hex)

def pubhex2address_bitcoin_segwit(pubhex):
    """Public Key Hex -> Bitcoin Segwit Address"""
    import hashlib, bech32
    pubkey_bytes = bytes.fromhex(pubhex)

    # hrp = 'bc' if mainnet
    # network_byte = \x00 if mainnet
    # address = bech32(hrp, network_byte, ripemd160(sha256(pubkey)))
    hashed_pubkey_bytes = hashlib.sha256(pubkey_bytes).digest()
    hashed_hashed_pubkey_bytes = hashlib.new('ripemd160', hashed_pubkey_bytes).digest()
    return bech32.encode(hrp='bc', witver=0, witprog=hashed_hashed_pubkey_bytes)

def prvhex2pubhex_ethereum(prvhex):
    """Private Key Hex -> Ethereum Public Key Hex"""
    import ecdsa
    prvkey_bytes = bytes.fromhex(prvhex)
    # pubkey = concat(x,y) where (x,y) = ecdsa_secp256k1(prvkey)
    pubkey_raw = ecdsa.SigningKey.from_string(prvkey_bytes, curve=ecdsa.SECP256k1).verifying_key
    pubkey_bytes = pubkey_raw.to_string()
    return pubkey_bytes.hex()

def pubhex2address_ethereum(pubhex):
    """Public Key Hex -> Ethereum Address"""

    from Crypto.Hash import keccak
    pubhex_bytes = bytes.fromhex(pubhex)
    # address_body = keccak256((pubkey)[-20:]
    truncated_hashed_pubkey_bytes = keccak.new(data=pubhex_bytes, digest_bits=256).digest()[-20:]
    address_body = truncated_hashed_pubkey_bytes.hex()

    # Element-wise hex-to-hex comparison
    # checksum_reference = hex(keccak256(hex(address_body)))[:20]
    # checksummed_address_body = stringify([ a.uppercase() if c>=8 else a for (a,c) in zip(address_body, checksum_reference) ])
    checksum = keccak.new(data=address_body.encode(), digest_bits=256).hexdigest()
    checksum_address = '0x'
    for i in range(len(address_body)):
        address_char = address_body[i]
        checksum_char = checksum[i]
        if int(checksum_char, 16) >= 8:
            checksum_address += address_body[i].upper()
        else:
            checksum_address += address_body[i]
    # address = concat('0x', checksummed_address_body)
    return checksum_address

def prvhex2pubhex_cosmos(prvhex):
    """Private Key Hex -> Cosmos Public Key Hex"""
    return prvhex2pubhex_bitcoin(prvhex)

def pubhex2address_cosmos(pubhex, prefix='cosmos'):
    import hashlib, bech32
    pubhex_bytes = bytes.fromhex(pubhex)
    hashed_pubkey_bytes = hashlib.sha256(pubhex_bytes).digest()
    hashed_hashed_pubkey_bytes = hashlib.new('ripemd160', hashed_pubkey_bytes).digest()
    hashed_hashed_pubkey_bytes_base5 = bech32.convertbits(hashed_hashed_pubkey_bytes, 8, 5)
    return bech32.bech32_encode(prefix, hashed_hashed_pubkey_bytes_base5)

def address2address_cosmos(address, prefix):
    import bech32
    return bech32.bech32_encode(prefix, bech32.bech32_decode(address)[1])

def default_derivation_path(identifier):
    # m / purpose' / coin_type' / account' / change / address_index
    if identifier in ['metamask','ethereum']:
        return "m/44'/60'/0'/0"
    elif identifier in ['keplr','cosmos']:
        # Not all IBC tokens adopt coin_type = 118
        return f"m/44'/118'/0'/0/0"
    else:
        raise NotImplementedError(f'{identifier} is not implemented.')

def get_ethereum_address(seed, extra_word=None, identifier=None, derivation_path=None):
    """Seed (+Extra Word) -> Ethereum Address"""
    if not isinstance(derivation_path, str):
        isinstance(identifier, str), 'supply identifier || derivation_path'
        derivation_path = default_derivation_path(identifier.lower())
    entropy = seed2entropy(seed, extra_word)
    prvkey_hex = entropy2prvhex(entropy, derivation_path)
    pubkey_hex = prvhex2pubhex_ethereum(prvkey_hex)
    address = pubhex2address_ethereum(pubkey_hex)
    return address
