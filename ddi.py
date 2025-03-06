import argparse
import datetime
import json
import os
import pprint
import json
import socket
from SOLIDserverRest import SOLIDserverRest
import nmap
import ctypes, os

# Checks if user is a local administrator before continuing
try:
	is_admin = os.getuid() == 0
except AttributeError:
	is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

if is_admin is False:
    pprint.pprint("ERROR:\tUser is not a local admin!\nPlease re-launch script with appropriate privileges")
    exit

class ddi:
	"""ddi

Usage:
	ddi [-h] -a create -s <site>    -i <IP>
	ddi [-h] -a {delete,get}        -i <IP>
	ddi [-h] -a {create,delete,get} -m <MAC>
	ddi [-h] -a {mac,mactrace}      -m <MAC> | -f <FILE>
	ddi [-h] -a scan [-u -s <site>] -i <IP>  | -f <FILE>

Options:
	-h                    Help
	-a|--action <action>  Action to perform: create, delete, get, 
                                           mac, mactrace, scan
	-i|--ip <ip>          IP Address for action
	-m|--mac <mac>        MAC Address for action
	-f|--file <file>      File to process for action
	-u|--update           Update SOLIDServer with results
	-s|--site <site>      Site in SOLIDServer to create records in:
    	                  example-External, example-Internal
	-c|--config <file>    Specify config file to use

Description:

This code will view and update information in SOLIDserver.

The intent of this script is to do two things:

1. process files that contain subnet addresses one per line that is to be
   scanned for any reachable devices and update the SOLIDserver with status.

2. process files that contain MAC addresses one per line and report any ip
   associated with it in SOLIDserver.

The config file this script uses is found using the following rules in
this order:

1. use the --config value passed
2. use environment varialbe DDI_CONFIG value
3. use config.json file in current working directory

Config:

The config file supports the following settings:

  server           dictionary with three values to define access to SOLIDserver
    service        url
    user           user name
    password       user password 
    certs          path to file containing all the CA certificates
  domain           domain to use when creating ip entries
  sites            dictionary of names for SOLIDserver supported with --site
    <altname>      dictionary altname handeling details
      name         SOLIDserver real internal name to map to
      insert       Option can be set to nodns to prevent dns updates

Example

{
  "server" : {
     "service"  : "https://ddi.example.org",
     "user"     : "ddiapi",
     "password" : "mypassword"
  },
  "domain" : "example.org",
  "sites"   : {
     "internal" : {
       "name" : "example-Internal"
     },
     "external" : {
       "name" : "example-External",
       "insert" : "nodns'
     }
  }
}

"""
	def __init__(self):
		"""Parse command line arguments load config file connect to SOLIDserver"""
		self.command()                # initialize self.args from command line
		try: 
			self.load(self.args.config) # initialise self.config with config file
		except Exception as e:
			error = str(e)+"\n"
			os.write(2,error.encode('utf-8'))
			exit() 

		self.df    = "%Y/%m/%d, %H:%M:%S"   # date format
		self.nargs = "-sn"            		# nmap arguments

		# Sets up connection to SolidServer API
		#
		# Main thing that is different is that every request needs to be queried, like 'self.ddi.query("method", "parameters")
		# From here, must decode reply and parse from json. Values can now be accessed via the dictionary
		self.ddi   = SOLIDserverRest(self.config['server']['service'])
		self.ddi.set_ssl_verify(True)
		self.ddi.set_certificate_file(self.config['server']['certs'])
		self.ddi.use_native_sds(user = self.config['server']['user'], password = self.config['server']['password'])

		# validate site if passed
		if self.args.site is not None:
			self.site()
         
	def command(self):
		"""parse command line arguments"""
		ap = argparse.ArgumentParser(description="scan network")
		ap.add_argument('-a','--action',
						choices=['create','delete','get','mac','mactrace','scan'],
						help='Action to perform',
						required=True)
		ap.add_argument('-i','--ip',help='IP Address for action')
		ap.add_argument('-m','--mac',help='MAC Address for action')
		ap.add_argument('-f','--file',help='File to process for file action',
						type=argparse.FileType('r'))
		ap.add_argument('-u','--update',action='store_true',
						help='Update SOLIDserver with results')
		ap.add_argument('-s','--site',
						help='Site in SOLIDserver to create records in')
		ap.add_argument('-c','--config',default='config.json',
						help='Specify config file to use')

		self.args = ap.parse_args()

		# argument rules
		if self.args.update and not self.args.action in ['scan']:
			ap.error("-update requires --action scan")

		if self.args.update and not self.args.site:
			ap.error("-update requires --site <site>")

		if self.args.action == 'create':
			if not self.args.ip and not self.args.mac:
				ap.error("-action create requires --ip or -mac")
			if self.args.site and not self.args.ip:
				ap.error("-action create requires --ip")

		if self.args.file is not None and not self.args.action in ['mac','mactrace','scan']:
			ap.error("-file is only suppored with --action mac|mactrace|scan")

		if self.args.file is None and self.args.ip is None and self.args.action == 'scan':
			ap.error("-action scan requires --file or --ip")

		if self.args.file is None and self.args.mac is None and self.args.action in ['mac','mactrace']:
			ap.error("-action "+self.args.action+" requires --file or --mac")

		if self.args.mac is None and self.args.ip is None and self.args.action in ['get','delete']:
			ap.error("-action "+self.args.action+" requires -ip or -mac")

		if self.args.ip is not None and self.args.action in ['mac','mactrace']:
			ap.error("-ip is not supported with -action mac|mactrace")

		# config file search
		if self.args.config == 'config.json':
			if 'DDI_CONFIG' in os.environ: 
				self.args.config = os.environ['DDI_CONFIG']

	def site(self):
		"""validate site argument against SOLIDserver"""
		msg = 'site "'+self.args.site+'"'
		# translate passed value with config sites
		if self.args.site in self.config['sites']:
			if 'insert' in self.config['sites'][self.args.site]:
				self.args.insert = self.config['sites'][self.args.site]['insert']
			self.args.site = self.config['sites'][self.args.site]['name']
			msg += ' mapped to "'+self.args.site+'"'

		# load all sites from SOLIDserver
		sites = {}
		r1 = self.ddi.query("ip_site_list", {})
		if r1.status_code == 200:
			for j1 in r1.json():
				sites[j1['site_name']]=1

		# verify site is in SOLIDserver
		if not self.args.site in sites:
			msg +=" does not exist in SOLIDserver or config\n"
			exit(msg+
				"Config: "+", ".join(self.config['sites'].keys())+"\n"
				"SOLIDserver: "+", ".join(sites.keys()))

	def load(self,file):
		"""load config file"""
		with open(file,'r') as f:
			self.config = json.load(f)

	def create(self,ip):
		"""create a scan ip entry in SOLIDserver if it doesn't already exist"""
		j = self.get(ip)
		if j is None:
			try:
				self.insert(ip)
				print("create "+ip)
			except Exception as e:
				error = ip+": "+str(e)+"\n"
				os.write(2,error.encode('utf-8'))
		else:
			error = ""+ip+" alread exists in SOLIDserver\n"
			os.write(2,error.encode('utf-8'))

	def insert(self,ip):
		"""Create/insert ip in SOLIDserver"""
		d = datetime.datetime.now()
		sitename=self.args.site
		iphex = socket.inet_aton(ip).hex()
		params = {
				'site_name':sitename,
				'hostaddr':ip,
				'name':'ipscan-'+iphex+'.'+self.config['domain'],
				'ip_class_parameters':'scan_last_seen='+d.strftime(self.df)
		}
  
		if 'insert' in self.args and self.args.insert == 'nodns':
			params['name']='ipscan-nodns-'+iphex+'.'+self.config['domain']
			params['ip_class_parameters']+='&dns_update=0'
			params['ip_class_parameters_properties']='dns_update=set,restrict'
		#pprint.pprint(params)
		r = self.ddi.query("ip_address_create", params)
		r.raise_for_status()
		if r.status_code == 200:
			rj = r.json()
			m = rj[0]
			# if 'errno' in m.keys():
			# 	raise solidserver.SOLIDserverException(m)
			return m

	def update(self,id):
		"""update ip in SOLIDserver"""
		d=datetime.datetime.now()
		params = {
				'ip_id':id,
				'ip_class_parameters':'scan_last_seen='+d.strftime(self.df)
		}
		#pprint.pprint(params)
		r = self.ddi.query("ip_address_update", params)
		r.raise_for_status()
		if r.status_code == 200:
			rj = r.json()
			m = rj[0]
			# if 'errno' in m.keys():
			# 	raise solidserver.SOLIDserverException(m)
			return m

	def delete(self,ip):
		"""delete ip entry in SOLIDserver"""
		print("delete "+ip)
		j = self.ddi.query("ip_address_delete", {"WHERE":"hostaddr='"+ip+"'"})
		pprint.pprint(j)

	def get(self,ip):
		"""get ip entry in SOLIDserver"""
		if (self.args.action == "get"):
			print("get "+ip)
		
		r = self.ddi.query("ip_address_list", {"WHERE":"hostaddr='"+ip+"'"})
		r.raise_for_status()
		if r.status_code != 204:
			j = r.json()
			if (len(j) == 1):
				# If get was the argument action, prints to the screen
				if (self.args.action == "get"):
					pprint.pprint(j)
				else:
					return j[0]		

	def mac(self,mac):
		"""report ip for mac address"""
		ipaddresses={}
		# scan ip_address_list
		r1 = self.ddi.query("ip_address_list", {'WHERE':"mac_addr='"+mac+"'"})
		#pprint.pprint(r1.json())
		if r1.status_code == 200:	
			for j1 in r1.json():
				ipaddresses[socket.inet_ntoa(bytes.fromhex(j1['ip_addr']))]=1

			# process dhcplease_id
			if not j1['dhcplease_id'] == "0":
				# get mac dhcp_range_lease_info
				r2 = self.ddi.query("dhcp_range_lease_info", {'dhcplease_id':j1['dhcplease_id']})
				if r2.status_code == 200:
					for j2 in r2.json():
						m = j2['dhcplease_mac_addr']
				# scan dhcp_range_lease_list
				r2 = self.ddi.query("dhcp_range_lease_list", {'WHERE':"dhcplease_mac_addr='"+m+"'"})
				if r2.status_code == 200:
					for j2 in r2.json():
						#SKI ipaddresses[j2['dhcplease_addr']]=1
						ipaddresses[j2['dhcplease_addr']]=j2['dhcplease_end_time']

			# process dhcphost_id
			if not j1['dhcphost_id'] == "0":
				# get mac from dhcp_static_info
				r2 = self.ddi.query("dhcp_static_info", {'dhcpstatic_id':j1['dhcphost_id']})
				if r2.status_code == 200:
					for j2 in r2.json():
						m = j2['dhcphost_mac_addr']
				# scan dhcp_static_list
				r2 = self.ddi.query("dhcp_static_list", {'WHERE':"dhcphost_mac_addr='"+m+"'"})
				if r2.status_code == 200:
					for j2 in r2.json():
						#SKI ipaddresses[j2['dhcphost_addr']]=1
						ipaddresses[j2['dhcphost_addr']]=j2['dhcplease_end_time']

			# generate desired output for mac
			for ip in ipaddresses.keys():
				ts = datetime.datetime.fromtimestamp(float(ipaddresses[ip]))
				ts_str = ts.strftime('%m-%d-%y')
				print(mac+","+ip+","+ts_str)

	def mactrace(self,mac):
		"""trace mac address"""
		print()
		print("mactrace "+mac)

		r1 = self.ddi.query("ip_address_list", {'WHERE':"mac_addr='"+mac+"'"})
		m = None
		if r1.status_code == 200:
			print("ip_address_list search results:")
			for j1 in r1.json():
				print("  ip_id:          "+j1['ip_id'])
				print("    ip_addr:      "+socket.inet_ntoa(bytes.fromhex(j1['ip_addr'])))
				print("    dhcplease_id: "+j1['dhcplease_id'])
				print("    dhcplease_end: "+j1['dhcplease_end_time'])
				if not j1['dhcplease_id'] == "0":
					r2 = self.ddi.query("dhcp_range_lease_info", {'dhcplease_id':j1['dhcplease_id']})
					if r2.status_code == 200:
						for j2 in r2.json():
							m = j2['dhcplease_mac_addr']
							print("      dhcplease_mac_addr: "+j2['dhcplease_mac_addr'])
				print("    dhcphost_id:  "+j1['dhcphost_id'])
				if not j1['dhcphost_id'] == "0":
					r2 = self.ddi.query("dhcp_static_info", {'dhcpstatic_id':j1['dhcphost_id']})
					if r2.status_code == 200:
						for j2 in r2.json():
							m = j2['dhcphost_mac_addr']
							print("      dhcphost_mac_addr:  "+j2['dhcphost_mac_addr'])
		else:
			print("ip_address_list search results: Not Found")

		if m is not None:
			r1 = self.ddi.query("dhcp_range_lease_list", {'WHERE':"dhcplease_mac_addr='"+m+"'"})
			if r1.status_code == 200:
				print("dhcp_range_lease_list search results:")
				for j1 in r1.json():
					print("  dhcplease_id:          "+j1['dhcplease_id'])
					print("    dhcp_name:           "+j1['dhcp_name'])
					print("    dhcpscope_name:      "+j1['dhcpscope_name'])
					print("    dhcplease_vendor_id: "+j1['dhcplease_vendor_id'])
					print("    dhcplease_addr:      "+j1['dhcplease_addr'])
					print("    dhcplease_end: "+j1['dhcplease_end_time'])
			else:
				print("dhcp_range_lease_list search results: Not Found")

			r1 = self.ddi.query("dhcp_static_list", {'WHERE':"dhcphost_mac_addr='"+m+"'"})
			if r1.status_code == 200:
				print("dhcp_static_list search results:")
				for j1 in r1.json():
					print("  dhcphost_id:       "+j1['dhcphost_id'])
					print("    dhcp_name:       "+j1['dhcp_name'])
					print("    dhcpscope_name:  "+j1['dhcpscope_name'])
					print("    mac_vendor:      "+j1['mac_vendor'])
					print("    dhcphost_addr:   "+j1['dhcphost_addr'])
					print("    dhcplease_end: "+j1['dhcplease_end_time'])
				else:
					print("dhcp_static_list search results: Not Found")

	def scan(self,ip):
		"""scan network for ip"""
		print("scan "+ip)
		self.network(ip)
  
	def file(self,file,action):
		"""perform action for all lines in file"""
		if not action == 'mac':
			print("file "+file.name)
		for line in file:
			item = line.rstrip()
			if action == 'mac':
				self.mac(item)
			elif action == 'mactrace':
				self.mactrace(item)
			elif action == 'scan':
				self.network(item)
  
	def network(self,net):
		"""scan network for devices and update SOLIDserver"""
		nm = nmap.PortScanner()
		nm.scan(hosts=net,arguments=self.nargs)
		for ip in nm.all_hosts():
			# get SOLIDserver information
			try:
				j = self.get(ip)
			except Exception as e:
				error = "get "+ip+": "+str(e)+"\n"
				os.write(2,error.encode('utf-8'))
				return

			if j is None or j['ip_id'] == '0':
				# create
				if self.args.update:
					try:
						self.insert(ip)
						print("Created "+ip)
					except Exception as e:
						error = "create "+ip+": "+str(e)+"\n"
						os.write(2,error.encode('utf-8'))
				else:
					print("Create (not done) "+ip)
			else:
				# update
				if self.args.update:
					try: 
						self.update(j['ip_id'])
						print("Updated "+ip)
					except Exception as e:
						error = "update "+ip+": "+str(e)+"\n"
						os.write(2,error.encode('utf-8'))
				else:
					print("Update (not done) "+ip)
  
	def main(self):
		"""process command line requests"""
		if self.args.action == "create":
			if self.args.ip:
				self.create(self.args.ip)
		elif self.args.action == "delete":
			if self.args.ip:
				self.delete(self.args.ip)
		elif self.args.action == "get":
			if self.args.ip:
				self.get(self.args.ip)
		elif self.args.action == "mac":
			if self.args.mac is None:
				self.file(self.args.file,self.args.action)
			else:
				self.mac(self.args.mac)
		elif self.args.action == "mactrace":
			if self.args.mac is None:
				self.file(self.args.file,self.args.action)
			else:
				self.mactrace(self.args.mac)
		elif self.args.action == "scan":
			if self.args.ip is None:
				self.file(self.args.file,self.args.action)
			else:
				self.scan(self.args.ip)