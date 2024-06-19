import sys
import time

from core.requester import requester
from core.utils import host, load_json 

# Load the details from the JSON file
# need to create the file json and requester file
details = load_json(sys.path[0] + '/db/details.json')

#Conduct passive tests
def passive_tests(url, headers):
    root = host(url)
    acao_header = headers.get('access-control-allow-origin')
    acac_header = headers.get('access-control-allow-credentials')
    
    if acao_header == '*':
        return {url: {**details['wildcard value'], 'acao header': acao_header, 'acac header': acac_header}}

    if root and host(acao_header) and root != host(acao_header):
        return {url: {**details['third party allowed'], 'acao header': acao_header, 'acac header': acac_header}}
    
    #active tests
    
    def active_tests(url, root, scheme, header_dict, delay):
    test_cases = [
        ('websitename.com', 'origin reflected'),
        (f'{root}.websitename.com', 'post-domain wildcard'),
        (f'd3v{root}', 'pre-domain wildcard'),
        ('null', 'null origin allowed'),
        (f'{root}_.websitename.com', 'unrecognized underscore'),
        (f'{root}%60.websitename.com', 'broken parser'),
    ]
    
    if root.count('.') > 1:
        test_cases.append((root.replace('.', 'x', 1), 'unescaped regex'))

    test_cases.append((f'http://{root}', 'http origin allowed'))



