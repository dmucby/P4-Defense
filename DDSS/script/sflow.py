from mininet.net import Mininet
from mininet.log import info
from mininet.util import quietRun
from os import listdir, environ
from json import dumps
from re import match
from fcntl import ioctl
from array import array
from struct import pack, unpack
from sys import maxsize
import socket
import sys

try:
  from urllib.request import build_opener, HTTPHandler, Request
except ImportError:
  from urllib2 import build_opener, HTTPHandler, Request

def wrapper(fn):

  def getIfInfo(dst):
    is_64bits = maxsize > 2**32
    struct_size = 40 if is_64bits else 32
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    max_possible = 8 # initial value
    while True:
      bytes = max_possible * struct_size
      names = array('B')
      for i in range(0, bytes):
        names.append(0)
      outbytes = unpack('iL', ioctl(
        s.fileno(),
        0x8912,  # SIOCGIFCONF
        pack('iL', bytes, names.buffer_info()[0])
      ))[0]
      if outbytes == bytes:
        max_possible *= 2
      else:
        break
    s.connect((dst, 0))
    ip = s.getsockname()[0]
    for i in range(0, outbytes, struct_size):
      addr = socket.inet_ntoa(names[i+20:i+24])
      if addr == ip:
        name = names[i:i+16]
        try:
          name = name.tobytes().decode('utf-8')
        except AttributeError:
          name = name.tostring()
        name = name.split('\0', 1)[0]
        return (name,addr)

  def configSFlow(net,collector,ifname,sampling,polling):
    info("*** Enabling sFlow:\n")
    sflow = 'ovs-vsctl -- --id=@sflow create sflow agent=%s target=%s sampling=%s polling=%s --' % (ifname,collector,sampling,polling)
    for s in net.switches:
      sflow += ' -- set bridge %s sflow=@sflow' % s
    info(' '.join([s.name for s in net.switches]) + "\n")
    quietRun(sflow)

  def sendTopology(net,agent,collector):
    info("*** Sending topology\n")
    topo = {'nodes':{}, 'links':{}}
    for s in net.switches:
      topo['nodes'][s.name] = {'agent':agent, 'ports':{}}
    path = '/sys/devices/virtual/net/'
    for child in listdir(path):
      parts = match('(^.+)-(.+)', child)
      if parts == None: continue
      if parts.group(1) in topo['nodes']:
        ifindex = open(path+child+'/ifindex').read().split('\n',1)[0]
        topo['nodes'][parts.group(1)]['ports'][child] = {'ifindex': ifindex}
    i = 0
    for s1 in net.switches:
      j = 0
      for s2 in net.switches:
        if j > i:
          intfs = s1.connectionsTo(s2)
          for intf in intfs:
            s1ifIdx = topo['nodes'][s1.name]['ports'][intf[0].name]['ifindex']
            s2ifIdx = topo['nodes'][s2.name]['ports'][intf[1].name]['ifindex']
            linkName = '%s-%s' % (s1.name, s2.name)
            topo['links'][linkName] = {'node1': s1.name, 'port1': intf[0].name, 'node2': s2.name, 'port2': intf[1].name}
        j += 1
      i += 1

    opener = build_opener(HTTPHandler)
    request = Request('http://%s:8008/topology/json' % collector, data=dumps(topo).encode('utf-8'))
    request.add_header('Content-Type','application/json')
    request.get_method = lambda: 'PUT'
    url = opener.open(request)

  def result(*args,**kwargs):
    res = fn(*args,**kwargs)
    net = args[0]
    collector = environ.get('COLLECTOR','127.0.0.1')
    sampling = environ.get('SAMPLING','10')
    polling = environ.get('POLLING','10')
    (ifname, agent) = getIfInfo(collector)
    configSFlow(net,collector,ifname,sampling,polling)
    sendTopology(net,agent,collector) 
    return res

  return result

setattr(Mininet, 'start', wrapper(Mininet.__dict__['start']))
