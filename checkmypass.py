import requests
import hashlib
import sys


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)

    if res.status_code != 200:
        raise RuntimeError(
            f'Request failed : {res.status_code}. Please try again with different charater string')
    else:
        return res


def get_hash_leak_count(hashes, hash):

    hashes = (line.split(':') for line in hashes.text.splitlines())
    for val, count in hashes:
        if(hash == val):
            return count
    return 0


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first_5_char, tail = sha1password[:5], sha1password[5:]
    res = request_api_data(first_5_char)

    return get_hash_leak_count(res, tail)


def main(passwords):
    for password in passwords:
        count = pwned_api_check(password)
        if(count):
            print(
                f'{password} was found {count} times...please change your password.')
        else:
            print(f'{password} was not found...Carry on!')

    return 'done!'


if(__name__ == '__main__'):
    passwords = sys.argv[1:]
    sys.exit(main(passwords))
