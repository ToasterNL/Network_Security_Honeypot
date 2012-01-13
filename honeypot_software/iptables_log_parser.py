from datetime import datetime
import re
import subprocess
import pickle
import os
import time
import sys
import operator

whois_db = {}
top_ports = {'tcp': {}, 'udp': {}}
WHOIS_FILE = 'whois_cache'

def iptables_syslog_line_to_datetime_ip_tuple(line):
  start = line[0:15]
  dt = datetime.strptime("%s 2011" % start, "%b %d %H:%M:%S %Y")
  ip = re.search('SRC=([^ ]+)', line).groups()[0]
  dpt = re.search('DPT=([^ ]+)', line).groups()[0]
  country = whois_lookup(ip)
  return (dt, ip, dpt, country)

def whois_lookup(ip):
  if ip not in whois_db:
    try:
      data = subprocess.check_output(['whois', ip])
      whois_db[ip] = re.search('country:\s(.*)', str(data), flags=re.IGNORECASE).groups(0)[0].strip().upper()
    except Exception, e:
      try:
        data = subprocess.check_output(['host', ip])
        whois_db[ip] = data.split('.')[-2].upper()
      except Exception, e:
        whois_db[ip] = '?'
  return whois_db[ip]

def parse_file(filename):
  logs_per_country = {'udp': {}, 'tcp': {}}
  loglines = file(filename).readlines()

  for line in loglines:
    proto = None
    if 'New Connection: IN=eth1' in line and not 'SRC=130.89.145.99' in line and not 'PROTO=ICMP' in line:
      entry = line.strip()
      if 'PROTO=TCP' in line:
        proto = 'tcp'
      if 'PROTO=UDP' in line:
        proto = 'udp'

      if not proto:
        continue

      try:
        (timestamp, ip, port, country) = iptables_syslog_line_to_datetime_ip_tuple(entry)
      except Exception, e:
        print "Error %s" % e
        print entry

      if not country in logs_per_country[proto]:
        logs_per_country[proto][country] = []
      if not port in top_ports[proto]:
        top_ports[proto][port] = 0
      top_ports[proto][port] += 1
      logs_per_country[proto][country].append((timestamp, port))
  return logs_per_country

whois_db = pickle.load(open(WHOIS_FILE, 'rb'))
logs_per_country = parse_file(sys.argv[1])
pickle.dump(whois_db, open(WHOIS_FILE, 'wb'))
top_logs_per_country = {'tcp': {}, 'udp': {}}

#for proto in top_ports.keys():
for proto in top_logs_per_country.keys():
  top_proto = sorted(top_ports[proto].iteritems(), key=operator.itemgetter(1))
  top_proto.reverse()
  print "top %s ports" % proto
  print [x[0] for x in top_proto[0:20]]
#print top_udp

#for proto in top_logs_per_country.keys():
  proto_ranks = sorted(set([(len(logs_per_country[proto][x]), x) for x in logs_per_country[proto].keys()]))
  proto_ranks.reverse()
  for (entries, country) in proto_ranks[0:9]:
    top_logs_per_country[proto][country] = logs_per_country[proto][country]

#for proto in top_logs_per_country.keys():
  #set terminal png size 1920,1080
  gnuplot_string = """
  set terminal png size 1200,900
  set output "%s.png"

  set xdata time
  set timefmt "%%m/%%d/%%Y"
  set xrange ["11/1/2011":"1/1/2012"]
  set xtics 3600*24*10
  set timefmt "%%s"

  set logscale y

  set grid
  set xlabel "Time"
  set ylabel "Port"
  set title "%s connections over time, by most active countries"
  set key outside
  set view map
  """ % (proto, proto.upper())

  if proto == 'tcp':
    gnuplot_string += "set ytics (0, 80, 9988, 1433, 22, 3389, 4899, 8080, 19808, 443, 2222, 1080, 808)\n"
  if proto == 'udp':
    gnuplot_string += "set ytics (0, 138, 67, 5060, 58609, 161, 33434, 10716, 111, 53)\n"

  graph_strings = []

  for country in top_logs_per_country[proto].keys():
    filename = "%s_country_%s" % (proto, country)
    fp = file(filename, 'ab')
    for (timestamp, port) in top_logs_per_country[proto][country]:
      fp.write("%s %s\n" % (int(time.mktime(timestamp.timetuple())), port))
    fp.close()
    graph_strings.append("'%s' using 1:2:0 title '%s'" % (filename, country))

  gnuplot_string += "splot" + ", \\\n".join(sorted(set(graph_strings)))
  config_filename = "gnuplot_%s.conf" % proto
  f = file(config_filename, 'wb')
  f.write(gnuplot_string)
  f.close()

  subprocess.check_call(["gnuplot", config_filename])
