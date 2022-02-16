from utils import get_ethereum_address

def txt2list(fname):
    with open(fname, 'r') as f:
        return [line.strip() for line in f]

# Assumes BIP39 and BIP44
def main(phrase, extra_word, derivation_path, addr, missing_notation='?', verbose=True):
    mnemonic_dictionary = txt2list('bip39_words_english.txt')
    phrase_list = phrase.split(' ')
    if verbose:
        print('Phrase given:')
        print(phrase)

    num_missing_word = sum(1 if _ == missing_notation else 0 for _ in phrase_list)
    if num_missing_word > 1:
        raise Exception('Multiple missing words is not supported yet.')

    pos_missing_word = phrase_list.index(missing_notation)
    for guess_word in mnemonic_dictionary:
        phrase_list[pos_missing_word] = guess_word
        phrase_printable = ' '.join(phrase_list)

        if get_ethereum_address(phrase_printable, extra_word, derivation_path=derivation_path).lower() == addr.lower(): # Ethereum addr is case-insensitive
            if verbose:
                print('Found correct phrase:')
            print(phrase_printable)
            break
    else:
        if verbose:
            print('Not found!')


if __name__ == '__main__':
    phrase = 'school antique detect emotion pepper weasel topic arm shoulder ? chapter deny' # an example
    extra_word = '' # empty string if no extra word
    derivation_path = "m/44'/60'/0'/0/0" # the most common derivation path for generating Ethereum addresses
    addr = '0x426D485C3116Ee7941aB83133D14cA1176Ec99b7'

    main(phrase, extra_word, derivation_path, addr)
