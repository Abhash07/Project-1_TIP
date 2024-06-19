import sys
import time

from core.requester import requester
from core.utils import host, load_json 

# Load the details from the JSON file
# need to create the file
details = load_json(sys.path[0] + '/db/details.json')

