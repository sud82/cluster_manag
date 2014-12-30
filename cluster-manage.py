#!/usr/bin/env python
# short utility program which pings a given host and requests the 'info' about
# either all names or a certain name
#
#
from itertools import izip, chain
from pprint import pprint
import locale
import ConfigParser
import operator
import cmd
import sys, re, getopt
import inspect
from operator import itemgetter
from datetime import datetime
from time import sleep, time
import os, pickle
import shutil
import platform
import StringIO
import argparse
import getpass
import subprocess

try:
        import citrusleaf
except:
        print "citrusleaf.py not in your python path. Set PYTHONPATH!"
        sys.exit(-1)



def node_asd_info(host, port):
	user = None
	password = None
#
# MAINLINE
#	
	try:
		node_id = citrusleaf.citrusleaf_info(host, port, 'node', user, password)
		serv = citrusleaf.citrusleaf_info(host, port, 'services', user, password)
		serv_alu = citrusleaf.citrusleaf_info(host, port, 'services-alumni', user, password)
	except:
		print 'citrusleaf function failed..\n'
	return node_id, serv, serv_alu

def cluster_stat(host, port):
	try:
		node_id, serv, serv_alu = node_asd_info(host, port)
	except:
		print 'Exception in cluster-state'
		return
	if node_id == -1:
        	print "request to ",host,":",port," returned error"
		print host, "-----Node down"
        	return

	if node_id == None:
        	print "request to ",host,":",port," returned no data"
        	return
	services = serv.split(';')
	services_alumni = serv_alu.split(';')
	print host + '-----Node up'

	print "\nService nodes"
	for service in services:
		if service != '':
			print service
	print "\nAlumni nodes" 
	for alumni in services_alumni:
		if alumni !='':
			print alumni
	return

def node_up(host):
	'Start ASD in node'
	user = 'citrusleaf'
	playbook_name = 'server-start.yml'
	if host == '127.0.0.1':
		return subprocess.call('ansible-playbook '+ playbook_name + ' -i local, -e host=all -e user=root -c local',shell=True)
	else:
		return subprocess.call('ansible-playbook ' + playbook_name + ' -i ' + host + ', -e \"host=all\" -e user=' + user , shell=True) 

def node_down(host):
	'Stop ASD in node'
	user = 'citrusleaf'
	playbook_name = 'server-stop.yml'
        if host == '127.0.0.1':
                return subprocess.call('ansible-playbook '+ playbook_name + ' -i local, -e host=all -e user=root -c local',shell=True)
        else:
                return subprocess.call('ansible-playbook ' + playbook_name + ' -i ' + host + ', -e \"host=all\" -e user=' + user , shell=True)

def drop_traffic(host, src, hport=0, sport=0, proto=None, prob=0):
	'Drop traffic coming from src to host '
	playbook_name = 'drop.yml'
	user = 'citrusleaf'
	if( prob == 0 and proto == None):
		return subprocess.call('ansible-playbook ' + playbook_name + ' -i ' + host + ', -e \"host=all\" -e src=' + src + ' -e user=' + user, shell=True)
	elif(prob != 0 and proto == None):
		return subprocess.call('ansible-playbook ' + playbook_name + ' -i ' + host + ', -e \"host=all\" -e src=' + src + ' -e prob=' + prob + ' -e user=' + user,\
                                       shell=True)

	playbook_name = 'drop-proto.yml'
        if( prob == 0 and proto != None):
                return subprocess.call('ansible-playbook ' + playbook_name + ' -i ' + host + ', -e \"host=all\" -e src=' + src + ' -e user=' + user + \
					' -e proto=' + proto, shell=True)
        elif(prob != 0 and proto != None):
                return subprocess.call('ansible-playbook ' + playbook_name + ' -i ' + host + ', -e \"host=all\" -e src=' + src + ' -e prob=' + prob + \
					' -e user=' + user + ' -e proto=' + proto, shell=True)

        playbook_name = 'drop-hport.yml'
        if( prob == 0 and proto != None and hport != 0):
       		return subprocess.call('ansible-playbook ' + playbook_name + ' -i ' + host + ', -e \"host=all\" -e src=' + src + ' -e user=' + user + \
                                        ' -e proto=' + proto + ' -e dport=' + hport , shell=True)
        elif(prob != 0 and proto != None and hport != 0):
                return subprocess.call('ansible-playbook ' + playbook_name + ' -i ' + host + ', -e \"host=all\" -e src=' + src + ' -e prob=' + prob + \
                                        ' -e user=' + user + ' -e proto=' + proto + ' -e dport=' + hport, shell=True)

def remove_filter(host, src, hport=0, sport=0, proto=0, prob=0):
        'Remove filter from host for source '
        user = 'citrusleaf'
        playbook_name = 'rmdrop.yml'
        if( prob == 0 and proto == None):
                return subprocess.call('ansible-playbook ' + playbook_name + ' -i ' + host + ', -e \"host=all\" -e src=' + src + ' -e user=' + user, shell=True)
        elif(prob != 0 and proto == None):
                return subprocess.call('ansible-playbook ' + playbook_name + ' -i ' + host + ', -e \"host=all\" -e src=' + src + ' -e prob=' + prob + ' -e user=' + user,\
                                       shell=True)

        playbook_name = 'rmdrop-proto.yml'
        if( prob == 0 and proto != None):
                return subprocess.call('ansible-playbook ' + playbook_name + ' -i ' + host + ', -e \"host=all\" -e src=' + src + ' -e user=' + user + \
                                        ' -e proto=' + proto, shell=True)       
        elif(prob != 0 and proto != None):
                return subprocess.call('ansible-playbook ' + playbook_name + ' -i ' + host + ', -e \"host=all\" -e src=' + src + ' -e prob=' + prob + \
                                        ' -e user=' + user + ' -e proto=' + proto, shell=True)

        playbook_name = 'rmdrop-hport.yml'
        if( prob == 0 and proto != None and hport != 0):
                return subprocess.call('ansible-playbook ' + playbook_name + ' -i ' + host + ', -e \"host=all\" -e src=' + src + ' -e user=' + user + \
                                        ' -e proto=' + proto + ' -e dport=' + hport , shell=True)
        elif(prob != 0 and proto != None and hport != 0):
                return subprocess.call('ansible-playbook ' + playbook_name + ' -i ' + host + ', -e \"host=all\" -e src=' + src + ' -e prob=' + prob + \
                                        ' -e user=' + user + ' -e proto=' + proto + ' -e dport=' + hport, shell=True)
def node_info(host):
	'Print info about node'
	user = 'citrusleaf'
	playbook_name = 'node-info.yml'
        if host == '127.0.0.1':
                return subprocess.call('ansible-playbook '+ playbook_name + ' -i local, -e host=all -e user=root -c local',shell=True)
        else:
                return subprocess.call('ansible-playbook ' + playbook_name + ' -i ' + host + ', -e \"host=all\" -e user=' + user , shell=True)
	




#######======================================================================================#######
class RunCommand(cmd.Cmd):

        # pretty text...
        # Confirm you are in real console
        if sys.stdout.isatty():
                bold = "\033[1m"
                reset = "\033[0;0m"
        else:
                bold = "\'"
                reset = "\'"

        _VERSION_ = "3.3.26"
        prompt = "Cluster-manager> "
        name = "Aerospike Cluster manager Shell"
        intro = bold + name + ", version " + _VERSION_ + reset
        def __init__(self):
                cmd.Cmd.__init__(self)
                #parse_config(hosts_from_parm)

		#cluster = citrusleaf.CitrusleafCluster()
		#t1 = '192.168.113.203'
		#cluster = citrusleaf.getCluster_byhost(t1, 3000)
		#cluster.crawler_debug = True
		#cluster.getConnection()
		#t1 = '192.168.113.201'
		#cluster.addHost(t1, 3000)
        help = {
                'nodeUp':       {'usage' : bold + 'nodeUp' + reset + \
                                         '\n\t [ -h <comma separated host ip list, ip eg: x.x.x.x>]',
                                 'desc'  : 'Start server in  a single or list of host ip\'s'},
                'nodeDown':         {'usage' : bold + 'nodeDown' + reset + \
                                         '\n\t [-h <comma separated host ip list, ip eg: x.x.x.x>]',
                                      'desc': 'Stop server in a single or list of host ip\'s'},
                'clusterStat':        {'usage' : bold + 'clusterStat' + reset +\
					'\n\t [ -h <host ip:port>]'\
					'\n\t [default host 127.0.0.1 port 3000]',
                		'desc' : 'Statistics of cluster'},
		'nodeInfo':        {'usage': bold + 'nodeInfo' + reset + \
                                         '\n\t [-h <comma separated host ip list, ip eg: x.x.x.x>]',
                                     'desc' : 'Information about a single node or list of host ip\'s'},
		'exit':		{'usage' : bold + 'exit' + reset,
				 'desc' : 'Exit the Cluster manager console'},
                
		'drop_traffic': {'usage': bold + 'drop_traffic' + reset + \
					'\n\t [-h <host ip:port If -p is given then only host port will work>]' + \
					'\n\t [-s <source ip format x.x.x.x>]' + \
					'\n\t [-p <protocol, default all>' + \
					'\n\t [-d <drop probability of traffic >]',
				'desc' : 'Drop Traffic in host coming from source '},
                'remove_filter': {'usage': bold + 'remove_filter' + reset + \
                                        '\n\t [-h <host ip:port If -p is given then only host port will work>]' + \
                                        '\n\t [-s <source ip format x.x.x.x >]' + \
                                        '\n\t [-p <protocol, default all>' + \
                                        '\n\t [-d <drop probability of traffic >]',
                                'desc' : 'Remove filter in host for source '},
		'connect_tocluster': {'usage' : bold + 'connect_tocluster' + reset +\
						'\n\t[-h <Seed host ip to connect cluster eg:x.x.x.x >]'+ \
						'\n\t[-p <port >]',
					'desc': 'To connect with a new cluster enter host ip'},

 		}

        def do_help(self, line):
                ''' print list of commands and their usage '''
                print '' + self.bold + '\n' + self.name + self.reset
                print '' + self.bold + 'Version ' + self._VERSION_ + self.reset + '\n'
                print '' + self.bold + 'Commands:' + self.reset + '\n'
                keys = sorted(self.help)
                for cmd in keys:
                        print '\t' + self.help[cmd]['usage']
                        print '\t' + self.help[cmd]['desc'] + '\n'

        def do_exit(self, line):
               return True

        def do_EOF(self, line):
                return True

        def do_echo(self, line):
                "Print the input, replacing '$out' with the output of the last shell command"
                # Obviously not robust
                print line.replace('$out', self.last_output)

        # Overriding base class which repeats last command
        def emptyline(self):
                return False

        def _getargs(self, line, optstr):
                ''' utility function - get arguments and options from the command line'''
                myargv = line.split()
                opts, args = getopt.gnu_getopt(myargv, optstr)
                return opts, args
        # Utility function to parse the same set of arguments that are used by several commands
        def _getconfigargs(self, line):
                ''' utility function - parse standard arguments used when manipulating hosts'''
                opts, args = self._getargs(line, 'h:v:')
                host = None
                value = None

                for o, a in opts :
                        if o == '-h':
                                host = a
                        elif o == '-v':
                                value = a
		
		hlist = []
                if host != None:
                        hlist = host.split(',')
                else:
                        hlist = arg_machines
		hostlist = []
		for hp in hlist:
			h = hp.split(':')
			hostlist.append(h[0])
		return hostlist, value


	def do_nodeUp(self, line):
		'Starting server in given list of host'
                try:
                        hostlist, value = self._getconfigargs(line)
                        print line
                except (KeyboardInterrupt, SystemExit):
                        raise
                except:
                        print self.help['nodeUp']['usage']
                        return False
		if 0 == len(hostlist):
                        print self.help['nodeUp']['usage']
                        return False
		else:
			for host in hostlist:
				try:
					if node_up(host) == 0:
						print 'ASD Start successful: ' + host + '\n\n'
					else:
						print 'ASD start fail:'					
				except:
					print 'Exception occures, ASD start fail: ' + host + '\n\n'




	def do_nodeDown(self, line):
		'Stoping server in given list of host'
                try:
                        hostlist, value = self._getconfigargs(line)
                        print line
                except (KeyboardInterrupt, SystemExit):
                        raise
                except:
                        print self.help['nodeDown']['usage']
                        return False
                if 0 == len(hostlist):
                        print self.help['nodeDown']['usage']
			return False
                else:
                        for host in hostlist:
                                try:
                                        node_down(host)
                                        print 'ASD Stop successful: ' + host + '\n\n' 
                                except:
					print 'ASD sto fail: '+ host + '\n\n'

	def do_clusterStat(self, line):
		print '\n\n*********** Statistics of cluster nodes **********\n\n'
		host = None
		port = None
		try:
			opts,args = self._getargs(line,'h:')
			for o,a in opts:
				if o == '-h':
					host = a

			hlist = []
			# If multiple comma sapareded host are given then fail
                	if host != None:
                        	hlist = host.split(',')
                	else:
                        	hlist = arg_machines
                        # If multiple comma sapareded host are given then fail
                        if(len(hlist) > 1):
                                print self.help['stat']['usage']
                                return False
			hostport = []
			hostport = hlist[0].split(':')
			# If port is not given with host then take default port 3000
			if(len(hostport) == 2):
				host = hostport[0]
				port = hostport[1]
			else:
				host = hostport[0]
				port = str(arg_port)	
		except (KeyboardInterrupt, SystemExit):
			raise
                except:
                        print self.help['clusterStat']['usage']
                        return False

		try:
			cluster_stat(host, port)
		except:
			print 'Node info failed'

	def do_connect_tocluster(self, line):
		print '\n\n************* connect to cluster ***************\n\n'
		host = None
		port = None

		try:
			opts,args = self._getargs(line,'h:p:')
                        for o,a in opts:
                                if o == '-h':
                                        host = a
				if o == '-p':
					port = a
			if host is None:
				print self.help['connect_tocluster']['usage']
				return False
			else:
				hp = host.split(':')
				
				h = hp[0]
				if(len(hp) == 2 and port is None):
					h,p = host.split(':')
					port = p
				if(len(hp) < 2 and port is None):
					port = arg_port
				#connect with cluster at seed (h:p)
				try:
					cluster_stat(h,port)
					global arg_machines 
					arg_machines = [h + ':' +str(port)]
					
				except:
					print "Exception occured..can not connect to cluster"
		
                except (KeyboardInterrupt, SystemExit):
                        raise
                except:
                        print self.help['connect_tocluster']['usage']
                        return False			

	def do_nodeInfo(self, line):
		'Info about given list of host'
                try:
                        hostlist, value = self._getconfigargs(line)
                        print line
                except (KeyboardInterrupt, SystemExit):
                        raise
                except:
                        print self.help['nodeInfo']['usage']
                        return False
                if 0 == len(hostlist):
                        print self.help['nodeInfo']['usage']
                        return False
                else:
                        for host in hostlist:
                                try:
                                        node_info(host)
                                except:
					print 'Fail in getting info \n\n'

	def do_drop_traffic(self, line):
		'Droping traffic from source to host '
		try:
			opts,args = self._getargs(line, 'h:s:p:d:')
		except:
			print self.help['drop_traffic']['usage']
			return False
		hostport = arg_machines
		srcport = None
		proto = None
		prob = 0
		hport = 0
		sport = 0
		
		try:
			for o, a in opts:
				if o == '-h':
					hostport = a
				if o == '-s':
					srcport = a
                                if o == '-p':
					proto = a
                                if o == '-d':
					prob = a
		except:
                        print self.help['drop_traffic']['usage']
			return False
		#src name is required
		if srcport == None:
                        print self.help['drop_traffic']['usage']
                        return False
		try:
			#print 'host:' + hostport + ' src:' + src + ' proto:' + proto + ' prob:'+prob
			hp = hostport.split(':')
			host = hp[0]
			if len(hp) == 2 :
				hport = hp[1]
			elif len(hp)>2 :
				return False

                        # Goto help when hport is given but proto is not given
                        if hport != 0 and proto == None:
                                print self.help['drop_traffic']['usage']
                                return False

                        sp = srcport.split(':')
                        src = sp[0]

                        if len(sp) == 2 :
                                sport = sp[1]
                        elif len(hp)>2 :
                                return False
				
			print 'trying to add'			
			if drop_traffic(host, src, hport, sport, proto, prob) == 0:
				print 'Filter added in \"' + hostport + '\"'
                        	print prob 
			else:
				print 'Filter addition failed\n\n'
		except:
			print 'Exception occured in drop traffic\n\n'

	def do_remove_filter(self, line):
                'Remove filter from host for source '
                try:
                        opts,args = self._getargs(line, 'h:s:p:d:')
                except:
                        print self.help['remove_filter']['usage']
                        return False
                hostport = arg_machines
                srcport = None
                proto = None
                prob = 0
                hport = 0
                sport = 0

                try:
                        for o, a in opts:
                                if o == '-h':
                                        hostport = a
                                if o == '-s':
                                        srcport = a
                                if o == '-p':
                                        proto = a
                                if o == '-d':
                                        prob = a
                except:
                        print self.help['remove_filter']['usage']
                        return False
                #src name is required
                if srcport == None:
                        print self.help['remove_filter']['usage']
                        return False
                try:
                        #print 'host:' + hostport + ' src:' + src + ' proto:' + proto + ' prob:'+prob
                        hp = hostport.split(':')
                        host = hp[0]
                        if len(hp) == 2 :
                                hport = hp[1]
                        elif len(hp)>2 :
                                return False

                        # Goto help when hport is given but proto is not given
                        if hport != 0 and proto == None:
                                print self.help['drop_traffic']['usage']
                                return False

                        sp = srcport.split(':')
                        src = sp[0]

                        if len(sp) == 2 :
                                sport = sp[1]
                        elif len(hp)>2 :
                                return False

                        print 'trying to add'
                        if remove_filter(host, src, hport, sport, proto, prob) == 0:
                                print 'Filter removed in \"' + hostport + '\"'
                                print prob
                        else:
                                print 'Filter removel failed, check if filter with this specification exit!!!\n\n'
                except:
                        print 'Exception occured in remove filter\n\n'




parser = argparse.ArgumentParser(add_help=False, conflict_handler='resolve')
parser.add_argument("-h", "--Host", default="127.0.0.1", help="Connection info of the host(s). Must be in the 127.0.0.1 or 127.0.0.1:3000 format. Comma separated for multi hosts")
parser.add_argument("-p", "--Port", type=int, default=3000, help="server port (default: %(default)s)")
parser.add_argument("-U", "--User", help="user name")
parser.add_argument("-P", "--Password", nargs="?", const="prompt", help="password")
#parser.add_argument("-c", "--Config", default="filename", help="Location of configuration file (default: %(default)s)")
parser.add_argument("-r", "--OneCommand", help="Deprecated. use -e instead.")
parser.add_argument("-e", "--OneCommand", help="eg1: '-e info' execute the info command in the shell. eg2: '-e help' show the shell help text")
#parser.add_argument("-d", "--Dir", help="Monitor Directory (default: users home directory)")
#parser.add_argument("-n", "--NoDns", action="store_true", help="do not convert ip to FQDN. Defaults to False.")
parser.add_argument("-u", "--Usage", action="store_true", help="show program usage")
args = parser.parse_args()

global arg_machines
global arg_port
arg_port = 3000

if args.Usage:
        printusage(args.Config)
        sys.exit(0)

user = None
password = None

if args.User != None:
        user = args.User
        if args.Password == "prompt":
                args.Password = getpass.getpass("Enter Password:")
        password = citrusleaf.hashpassword(args.Password)

if sys.stdout.isatty():
        print "\nEnter help for commands\n"

hosts_from_parm = []
raw_hosts = []
COLORS = [
        'GREY', 'RED', 'GREEN', 'YELLOW',
        'BLUE', 'MAGENTA', 'CYAN', 'WHITE', 'BLACK'
]

# netstopwatch to measure network performance
g_want_netstopwatch = False
g_netstopwatch_log_fd = None

if args.Host != None:
        raw_hosts = filter(None, args.Host.split(','))
        if len(raw_hosts) < 1:
                print "Host info is malformed. It must be comma separated, and in the format of 127.0.0.1 or 127.0.0.1:3000"
                printusage(args.Config)
                sys.exit(-1)
elif args.Port != None:
        hosts_from_parm.append('127.0.0.1:' + str(args.Port))

# attach the port number to hosts if needed
for hp in raw_hosts:
        # look for the : to assume the port. If not there, add it
        try:
                h, p = hp.split(':')
                hosts_from_parm.append(hp)
        except Exception, ex:
                hosts_from_parm.append(hp + ':' + str(args.Port))

# Print Cluster stat
for host in hosts_from_parm:
	arg_machines = [host]
	print "Overridden host ",host
print"Trying to connect....", host
h,p = arg_machines[0].split(':')
cluster_stat(h,p)

def main():
			if args.OneCommand:

                                RunCommand().onecmd(args.OneCommand)
                        else:
                                RunCommand().cmdloop()



if __name__ == '__main__':
	main()

