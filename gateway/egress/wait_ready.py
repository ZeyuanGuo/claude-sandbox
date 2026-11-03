"""Wait for the guarded local proxy to return the expected address."""
import argparse
import json
import time
import http.client
import ssl
from urllib.parse import urlsplit

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--proxy',required=True)
parser.add_argument('--expected',required=True)
args=parser.parse_args()
proxy=urlsplit(args.proxy)
if proxy.scheme!='http' or not proxy.hostname or not proxy.port or proxy.username or proxy.password:
    raise SystemExit('Expected an explicit unauthenticated HTTP parent')
deadline=time.monotonic()+40
while time.monotonic()<deadline:
    try:
        connection=http.client.HTTPSConnection(proxy.hostname,proxy.port,timeout=6,context=ssl.create_default_context())
        try:
            connection.set_tunnel('api.ipify.org',443)
            connection.request('GET','/?format=json',headers={'Host':'api.ipify.org'})
            response=connection.getresponse()
            if response.status==200 and json.loads(response.read(4096))['ip']==args.expected:
                raise SystemExit(0)
        finally:
            connection.close()
    except (OSError,ValueError,KeyError,http.client.HTTPException):
        pass
    time.sleep(1)
raise SystemExit('Guarded proxy did not become ready with expected exit')
