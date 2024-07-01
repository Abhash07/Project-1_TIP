import sys
import json
import argparse
from requests.exceptions import ConnectionError

from Vulnerabilities.Test1 import active_tests
from files.utils import host, prompt, format_result, extractHeaders, create_url_list, create_stdin_list
from files.colors import bad, end, red, run, good, grey, green, white, yellow

print('''
    %sCors detector  %s{%sv1.0%s}%s
''' % (green, white, grey, white, end))

try:
    import concurrent.futures
    from urllib.parse import urlparse
except ImportError:
    print(' %s Check if Python is installed or not ' % bad)
    quit()

parser = argparse.ArgumentParser()
parser.add_argument('-u', help='target url', dest='target')
parser.add_argument('-o', help='json output file', dest='json_file')
parser.add_argument('-i', help='input file urls/subdomains', dest='inp_file')
parser.add_argument('-t', help='thread count', dest='threads', type=int, default=2)
parser.add_argument('-d', help='request delay', dest='delay', type=float, default=0)
parser.add_argument('-q', help='don\'t print help tips', dest='quiet', action='store_true')
parser.add_argument('--headers', help='add headers', dest='header_dict', nargs='?', const=True)
args = parser.parse_args()

delay = args.delay
quiet = args.quiet
target = args.target
threads = args.threads
inp_file = args.inp_file
json_file = args.json_file
header_dict = args.header_dict

if type(header_dict) == bool:
    header_dict = extractHeaders(prompt())
elif type(header_dict) == str:
    header_dict = extractHeaders(header_dict)
else:
    header_dict = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip',
        'DNT': '1',
        'Connection': 'close',
    }

# Define additional vulnerability test functions guyz. Your part of testing please put it here and create other functions if necessary
def test_vulnerability_1(url, headers, delay):
    # Implement the logic for vulnerability 1
    return {"name": "Vulnerability 1", "result": "Example result 1"}

def test_vulnerability_2(url, headers, delay):
    # Implement the logic for vulnerability 2
    return {"name": "Vulnerability 2", "result": "Example result 2"}

# Add similar functions for other vulnerabilities

# PIPE output from other tools such as httprobe etc
if sys.stdin.isatty():
    urls = create_url_list(target, inp_file)
else:
    urls = create_stdin_list(target, sys.stdin)

def cors(target, header_dict, delay):
    url = target
    root = host(url)
    parsed = urlparse(url)
    netloc = parsed.netloc
    scheme = parsed.scheme
    url = scheme + '://' + netloc + parsed.path
    results = {}
    try:
        results['cors'] = active_tests(url, root, scheme, header_dict, delay)
        results['vulnerability_1'] = test_vulnerability_1(url, header_dict, delay)
        results['vulnerability_2'] = test_vulnerability_2(url, header_dict, delay)
        # Add calls to other vulnerability tests here
    except ConnectionError as exc:
        print('%s Unable to connect to %s' % (bad, root))
    return results

if urls:
    if len(urls) > 1:
        print(' %s Estimated scan time: %i secs' % (run, round(len(urls) * 1.75)))
    results = []
    threadpool = concurrent.futures.ThreadPoolExecutor(max_workers=threads)
    futures = (threadpool.submit(cors, url, header_dict, delay) for url in urls)
    for each in concurrent.futures.as_completed(futures):
        result = each.result()
        results.append(result)
        if result:
            for test_type, test_result in result.items():
                if test_result:
                    print(' %s %s' % (good, test_result["name"]))
                    print('   %s-%s Result: %s' % (yellow, end, test_result["result"]))
                    # Add more details as needed
    results = format_result(results)
    if results:
        if json_file:
            with open(json_file, 'w+') as file:
                json.dump(results, file, indent=4)
    else:
        print(' %s No misconfigurations found.' % bad)
else:
    print(' %s No valid URLs to test.' % bad)
