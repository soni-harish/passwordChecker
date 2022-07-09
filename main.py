import hashlib
import requests
import sys


def fetch_request_api(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(f'Error in API fetching, status {response.status_code}. Check the API and try again')
    return response


def get_password_leaks_count(response_data, hash_to_check):
    hashes = (line.split(':') for line in response_data.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return int(count)
    return 0


def pwned_api_check(password):
    sha1pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5chars, hash_tail = sha1pass[:5], sha1pass[5:]
    response = fetch_request_api(first5chars)
    breach_count = get_password_leaks_count(response.text, hash_tail)
    return breach_count


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times. You should probably use different password')
        else:
            print(f'{password} was not found')
    return 'Done'


if __name__ == '__main__':
    if len(sys.argv) > 1:
        # Use sys.exit() only to display return message from the main()
        # function at end of work
        sys.exit(main(sys.argv[1:]))
    else:
        print('''Password checker against former breaches via Pwned Passwords API.
Usage: main.py <passwords to check>''')