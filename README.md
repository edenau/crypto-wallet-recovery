# crypto-wallet-recovery

A minimal Python script for recovering your mnemonic phrase given

- All but one phrases (and their positions) are known
- Known extra word (if any)
- Known derivation path
- Known target address

With slight modification, this script can recover mnemonic phrase

- with more than one unknown phrases (requires more computational power, recommends using `asyncio` module)
- with a list of possible extra words
- with a list of possible derivation paths
- with a list of possible target addresses
- of any cryptocurrency address derived by BIP39 and BIP44
- with unknown addresses (check if balance is non-zero using `web3`)
