#!/usr/bin/python

import os
import shutil
import subprocess
import sys
import tempfile
import time

def main():

  for line in sys.stdin:
    tmpdir = tempfile.mkdtemp()
   
    (rank,url) = line.split(',')
    url = url.strip()
    http = "%s" % url
    sys.stdout.write("%s,%s," % (rank,url))
    sys.stdout.flush()

    '''
    args = ["wget", 
        "-E", "-H", "-p", "-nd", "--no-check-certificate",\
        "-e", "robots=off", "-P", tmpdir, \
        "-U", "\"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:14.0) Gecko/20120405 Firefox/14.0a1\"",
        http]
    '''
    args = ["/tmp/mulk", "-H", #"-q",
      "-p", "5",
      "-m", "50",
      "-U", "\"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:14.0) Gecko/20120405 Firefox/14.0a1\"",
      http if http.startswith("http://") else ("http://www.%s/" % http)]

    tstart = time.time()

    ok = True
    try:
      p = subprocess.Popen(args, cwd=tmpdir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
      sys.stderr.write("%s\n" % e)
      ok = False

    (stdout, stderr) = p.communicate()
    size = stdout.split("Total size downloaded = ")[-1].split()
    units = size[1].strip()
    size = size[0].strip()

    tend = time.time()

    """
    shutil.rmtree(os.path.join(tmpdir, ".tmp-mulk"))

    subprocess.check_call(['find', tmpdir, '-type', 'f', '-exec', 'mv', '{}', tmpdir, ';'])

    (output, stderr) = subprocess.Popen(["du", "-b", "-s", tmpdir], 
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE).communicate()
      
    (size, path) = output.split() 
    """

    sys.stdout.write("%s,%s,%f,%f,%s\n" % (size, units, tstart, tend, "OK" if ok else "Error(s)"))
      
    shutil.rmtree(tmpdir)

if __name__ == "__main__":
  main()
