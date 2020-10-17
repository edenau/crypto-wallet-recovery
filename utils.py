def phrase2seed(phrase, extra_word=''):
    """Phrase (+Extra Word) -> Seed"""
    from mnemonic import Mnemonic
    assert isinstance(phrase, str), 'phrase should be str'
    assert isinstance(extra_word, str), 'extra_word should be str'

    mnemo = Mnemonic('english')
    return mnemo.to_seed(phrase, passphrase=extra_word)

def seed2prvkey(seed, derivation_path):
    """Seed -> Private Key"""
    from bip32utils import BIP32Key, BIP32_HARDEN
    assert isinstance(derivation_path, str), 'str_ should be str'
    path_list = derivation_path.split('/')
    assert path_list[0] == 'm', 'Derivation path should start with char "m"'

    xkey = BIP32Key.fromEntropy(seed).ExtendedKey()
    key = BIP32Key.fromExtendedKey(xkey)
    for path in path_list[1:]:
        if path[-1] == "'":
            key = key.ChildKey(int(path[:-1])+BIP32_HARDEN)
        else:
            key = key.ChildKey(int(path))
    return key.PrivateKey().hex()

def prvkey2ethaddr(prvkey, checksum=True):
    """Private Key -> Ethereum Address"""
    import blocksmith
    addr = blocksmith.EthereumWallet.generate_address(prvkey)
    if checksum:
        return blocksmith.EthereumWallet.checksum_address(addr)
    else:
        return addr

def phrase2ethaddr(phrase, extra_word, derivation_path, checksum=True):
    """Phrase (+Extra Word) -> Ethereum Address"""
    return prvkey2ethaddr(seed2prvkey(seed=phrase2seed(phrase, extra_word),
                                      derivation_path=derivation_path),
                          checksum=checksum)
