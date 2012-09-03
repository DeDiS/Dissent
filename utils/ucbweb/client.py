"""
Read internet trace and make requests to a given 
HTTP server for each line in the trace file

Download trace files here:
http://ita.ee.lbl.gov/html/contrib/UCB.home-IP-HTTP.html

Run using the tracefile as:
zcat TRACEFILE | tools/showtrace | python client.py

"""

import pycurl
import sys
import StringIO
import time

SERVER_IP = "alice.cs.yale.edu"
SERVER_PORT = 9090

#PROXY_IP, PROXY_PORT = (None, None)
PROXY_IP = "10.0.0.2"
PROXY_PORT = 8080

def main():
  for line in sys.stdin:
    make_http_request(line)

def make_http_request(line):
  '''parse a line'''
  parts = line.split()
  d = {}
  d['time_start'] = parts[0]
  d['time_byte_first'] = parts[1]
  d['time_byte_last'] = parts[2]
  d['addr_client'] = parts[3]
  d['addr_server'] = parts[4]
  d['head_client'] = parts[5]
  d['head_server'] = parts[6]
  d['head_ifmodified'] = parts[7]
  d['head_expires'] = parts[8]
  d['head_lastmodified'] = parts[9]
  d['len_head'] = parts[10]
  d['len_body'] = parts[11]
  d['len_url'] = parts[12]
  d['method'] = parts[13]
  d['url'] = parts[14]

  '''
  make an HTTP request containing the
  length of the desired response
  '''

  tstart = time.time()

  buf = StringIO.StringIO()
  curl = pycurl.Curl()

  curl.setopt(pycurl.URL, "http://%s:%s/%s?%s&%s" %
      (SERVER_IP, SERVER_PORT, d['url'], d['len_head'], d['len_body']))

  def writefun(data):
    try:
      buf.write(data)
    except KeyboardInterrupt:
      return 0

  curl.setopt(pycurl.WRITEFUNCTION, buf.write)

  if PROXY_IP is not None and PROXY_PORT is not None:
    curl.setopt(pycurl.PROXY, PROXY_IP)
    curl.setopt(pycurl.PROXYPORT, PROXY_PORT)
    curl.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5)

  curl.perform()

  r = curl.getinfo(pycurl.RESPONSE_CODE)
  if r != 200:
    raise RuntimeError("Request failed on %s with code because %s" \
        % (d['url'], curl.errstr()))

  curl.close()
  tend = time.time()

  sys.stdout.write("%s %s %f %f\n" % (d['len_head'], d['len_body'], tstart, tend))
  sys.stdout.flush()

if __name__ == "__main__":
  main()
  
