#!/usr/bin/python3

import sys
import os
import json
import configparser
import urllib.request
import urllib.error
import requests
import validators
import phonenumbers
from pyfiglet import Figlet
from opencnam import Phone
from google import google
import shodan
from dnsdumpster.DNSDumpsterAPI import DNSDumpsterAPI
from fullcontact import FullContact
import censys.ipv4


PWNED_API = 'https://haveibeenpwned.com/api/v2/breachedaccount/'
PWNED_PASTES_API = 'https://haveibeenpwned.com/api/v2/pasteaccount/'
USER_AGENT = 'urllib-example/0.1'
WHATCMS_API = 'https://whatcms.org/APIEndpoint/Detect?key='
CRT_URL = 'https://crt.sh/?q=%25'
TOWERDATA_URL = 'https://api.towerdata.com/v5/ev'
HK_PAGELINKS_URL = 'https://api.hackertarget.com/pagelinks/?q='
HK_ZONETRANSFER_URL = 'https://api.hackertarget.com/zonetransfer/?q='

# Google Hacking queries - adapt as you want - https://www.exploit-db.com/google-hacking-database
DIR_LIST = 'intitle:index.of'
FIL = 'ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini | ext:log | ext:sql | ext:config'
DOC = 'ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv | inurl:scanned & documents intitle:"index of" IT | intitle:"index of" inurl:documents backup'
DBS = 'ext:sql | ext:dbf | ext:mdb | inurl:login.htm "access" database | intext:database inurl:"laravel.log" ext:log'
LOGIN = 'inurl:login | inurl:login/?next=/admin/ | intitle:admin intitle:login | inurl:admin intitle:login | inurl:login.php?referer=profile.php | inurl:.gov/wp-login.php | inurl:.edu/wp-login.php | inurl:.mil/wp-login.php | inurl:.us/wp-login.php'
SQL = 'intitle:index of /.sql.gz intext:/backup/ | inurl:"?db_backup" | inurl:"dbbackup" -site:github.com "sql.gz" | "sql.tgz" | "sql.tar" | "sql.7z" | intitle:index of /.sql.gz intext:/backup/ | "index of" "database.sql.zip" | "Index of" "database.sql"'
SENS = 'ext:log & intext:"admin" | intext:"root" | intext:"administrator" & intext:"password" | intext:"root" | intext:"admin" | intext:"administrator"'
PHP = 'ext:php intitle:phpinfo "published by the PHP Group" | inurl:/signin.php?ret= | inurl:/php-errors.log filetype:log | inurl:/phpMyAdmin/setup/index.php?phpMyAdmin= | inurl:admin.php inurl:admin ext:php | inurl:login.php.bak | intext:define("AUTH_KEY", wp-config.php filetype:txt | inurl:"main.php?action=db"'

def menu_options():
	print("""osintS34rCh v1.0

USAGES
  Email
  ./osintS34rCh -e <target@email>				# All Searches: Pipl, FullContact, Haveibeenpwnded Data Breaches and Credentials Pastes, TowerData - validate e-mail
  ./osintS34rCh -e <target@email> --pipl 			# Pipl
  ./osintS34rCh -e <target@email> --fullcontact 		# FullContact
  ./osintS34rCh -e <target@email> --pwned 			# Haveibeenpwnded Data Breaches and Credentials Pastes
  ./osintS34rCh -e <target@email> --validate			# TowerData - validate e-mail

  Domain
  ./osintS34rCh.py -t <domain>					# All Searches: Shodan Recon, crt.sh, DNSDumpster, All Google Hacking Dorks, HackerTarget - DNS Zonetransfer
  ./osintS34rCh.py -t <domain> --shodan				# Shodan Recon
  ./osintS34rCh.py -t <domain> --crt 				# crt.sh
  ./osintS34rCh.py -t <domain> --dns 				# DNSDumpster, HackerTarget - DNS Zonetransfer
  ./osintS34rCh.py -t <domain> -d <dork> -n <num_pages>		# Google Hacking
  ./osintS34rCh.py -t <domain> -d --all				# All Google Hacking Dorks

  IP
  ./osintS34rCh.py -t <IP>					# All Searchs: Shodan and Censys Recon
  ./osintS34rCh.py -t <IP> --shodan				# Shodan Recon
  ./osintS34rCh.py -t <IP> --censys				# Censys Recon
  ./osintS34rCh.py -t <IP> --torrent				# KnowWhatYouDownload URL

  URL
  ./osintS34rCh.py -u <url>					# WhatCMS Check, HackerTarget - Extract URLs
  ./osintS34rCh.py -u <url> --cms				# WhatCMS Check
  ./osintS34rCh.py -u <url> --extract				# HackerTarget - Extract URLs
  ./osintS34rCh.py -u <url> --facebook 				# Facebook

  Phone
  ./osintS34rCh.py -p <phonenumber> --callerID			# CallerID

OPTIONS:
  -h or --help
  -e <email> [--pipl] [--fullcontact] [--pwned] [--validate]
  -t <target IP or Domain> [--shodan] [--censys] [--torrent] [--crt] [--dns] [-d] [<dork>] [--all] [-n <num_pages>]
  -u [--cms] [--censys] [--extract] [--facebook]
  -p <phone> --callerID

DORKS:
  dir_list
  files
  docs
  db
  login
  sql
  sensitive
  php

CONFIG_FILE:
  /yourdirectory/osintSearch.config.ini""")

def figlet_print():
	f = Figlet(font='slant')
	print (f.renderText('osintS34rCh'))

def menu_bad_execution():
	print ("osintS34rCh: bad execution")
	print ("Try using: ./osintS34rCh -h")
	sys.exit()

def apiFile():

	global pipl_key
	global fullcontact_key
	global caller_sid
	global caller_auth
	global shodan_key
	global cms_key
	global censys_api_id
	global censys_api_secret
	global towerdata_api_key

	pwd = os.path.dirname(os.path.realpath(__file__))
	filename = pwd + '/osintSearch.config.ini'

	config = configparser.ConfigParser()

	if not os.path.isfile(filename):

		figlet_print()

		print ("[-] The following procedure is necessary in order to save your API keys...")
		print ("[-] Hit enter if you don't have the keys.\n[-] The data will be written into a file called [" + filename + "] that can be edited by you after.\n")

		p_api_key = input("[?] What is your PIPL API key?\n")
		f_api_key = input("[?] What is your FullContact API key?\n")
		cnam_sid = input("[?] What is your CNAM SID?\n")
		cnam_at = input("[?] What is your CNAM AUTH_TOKEN?\n")
		s_api_key = input("[?] What is your Shodan API key?\n")
		w_api_key = input("[?] What is your WhatCMS API key?\n")
		c_api_id = input("[?] What is your Censys API id?\n")
		c_api_secret = input("[?] What is your Censys API secret?\n")
		t_api_key = input("[?] What is your TowerData API key?\n")

		
		config['PIPL'] = {}
		config['PIPL']['API_KEY'] = p_api_key
		config['FULLCONTACT'] = {}
		config['FULLCONTACT']['API_KEY'] = f_api_key
		config['CNAM'] = {'SID': cnam_sid, 'AUTH_TOKEN': cnam_at}
		config['SHODAN'] = {}
		config['SHODAN']['API_KEY'] = s_api_key
		config['WHATCMS'] = {}
		config['WHATCMS']['API_KEY'] = w_api_key
		config['CENSYS'] = {'API_ID': c_api_id, 'API_SECRET': c_api_secret}
		config['TOWERDATA'] = {}
		config['TOWERDATA']['API_KEY'] = t_api_key

		with open(filename, 'w') as configfile:
			config.write(configfile)

		print ("\n[-] The data was written into the file - don't forget you can edit it later if you typed any of the fields wrong.\n[-] Please start the script again.")

		return False

	elif os.path.isfile(filename):

		config.read(filename)

		pipl_key = config['PIPL']['API_KEY']
		fullcontact_key = config['FULLCONTACT']['API_KEY']
		caller_sid = config['CNAM']['SID']
		caller_auth = config['CNAM']['AUTH_TOKEN']
		shodan_key = config['SHODAN']['API_KEY']
		cms_key = config['WHATCMS']['API_KEY']
		censys_api_id = config['CENSYS']['API_ID']
		censys_api_secret = config['CENSYS']['API_SECRET']
		towerdata_api_key = config['TOWERDATA']['API_KEY']
		
		return True

	else:
		print ("[!] Something went wrong.")
		return False

def piplSearch(email, key):

	print ("-> Pipl Results")

	if 'email' in locals() and 'key' in locals():

		data = urllib.request.urlopen('https://api.pipl.com/search/?email=' + email + '&no_sponsored=true&key=' + key).read().decode('utf-8')

		j = json.loads(data)

		if j['@http_status_code'] == 200:

			if 'available_data' in j and 'premium' in j['available_data']:

				if 'address' in j['query']['emails'][0]:
					print ("\n[@] Target: " + str(j['query']['emails'][0]['address']))

				if 'person' in j:
					if 'names' in j['person']:
						print ("\n[*] Names found:")
						for i in range(len(j['person']['names'])):
							if 'prefix' in j['person']['names'][i]:
								print ("- Prefix Name - " + j['person']['names'][i]['prefix'])
							if 'first' in j['person']['names'][i]:
								print ("- First Name - " + j['person']['names'][i]['first'])
							if 'last' in j['person']['names'][i]:
								print ("- Last Name - " + j['person']['names'][i]['last'])
							if 'display' in j['person']['names'][i]:
								print ("- Full Name - " + j['person']['names'][i]['display'])
					if 'gender' in j['person']:
						if 'content' in j['person']['gender']:
							print ("\n[*] Gender: " + str(j['person']['gender']['content']))
					if 'dob' in j['person']:
						if 'display' in j['person']['dob']:
							print ("\n[*] Age: " + str(j['person']['dob']['display']))
					if 'languages' in j['person']:
						print ("\n[*] Languages found:")
						for i in range(len(j['person']['languages'])):
							if 'region' in j['person']['languages'][i]:
								print ("- Region - " + j['person']['languages'][i]['region'])
							if 'display' in j['person']['languages'][i]:
								print ("- Language - " + j['person']['languages'][i]['display'])
					if 'phones' in j['person']:
						print ("\n[*] Telephones found:")
						for i in range(len(j['person']['phones'])):
							if 'display_international' in j['person']['phones'][i]:
								print ("- " + j['person']['phones'][i]['display_international'])
					if 'addresses' in j['person']:
						print ("\n[*] Cities/Countries found:")
						for i in range(len(j['person']['addresses'])):
							if 'display' in j['person']['addresses'][i]:
								print ("- " + j['person']['addresses'][i]['display'])
					if 'jobs' in j['person']:
						print ("\n[*] Jobs found:")
						for i in range(len(j['person']['jobs'])):
							if 'organization' in j['person']['jobs'][i]:
								print ("- Organization: " + j['person']['jobs'][i]['organization'])
							if 'industry' in j['person']['jobs'][i]:
								print ("- Industry: " + j['person']['jobs'][i]['industry'])
							if 'data_range' in j['person']['jobs'][i]:
								if 'start' in j['person']['jobs'][i]['data_range']:
									print ("- Started in " + j['person']['jobs'][i]['data_range']['start'])
								if 'end' in j['person']['jobs'][i]['data_range']:
									print ("- Ended in " + j['person']['jobs'][i]['data_range']['end'])
							if 'display' in j['person']['jobs'][i]:
								print ("- Description: " + j['person']['jobs'][i]['display'])
					if 'educations' in j['person']:
						print ("\n[*] Educations found:")
						for i in range(len(j['person']['educations'])):
							if 'degree' in j['person']['educations'][i]:
								print ("- " + j['person']['educations'][i]['degree'])
							if 'school' in j['person']['educations'][i]:
								print ("- School: " + j['person']['educations'][i]['school'])
							if 'data_range' in j['person']['educations'][i]:
								if 'start' in j['person']['educations'][i]['data_range']:
									print ("- Started in " + j['person']['educations'][i]['data_range']['start'])
								if 'end' in j['person']['educations'][i]['data_range']:
									print ("- Ended in " + j['person']['educations'][i]['data_range']['end'])
							if 'display' in j['person']['educations'][i]:
								print ("- Description: " + j['person']['educations'][i]['display'])
					if 'usernames' in j['person']:
						print ("\n[*] Usernames found:")
						for i in range(len(j['person']['usernames'])):
							if 'content' in j['person']['usernames'][i]:
								print ("- " + j['person']['usernames'][i]['content'])
					if 'user_ids' in j['person']:
						print("\n[*] User-IDs found:")
						for i in range(len(j['person']['user_ids'])):
							if 'content' in j['person']['user_ids'][i]:
								print ("- " + j['person']['user_ids'][i]['content'])
					if 'images' in j['person']:
						print ("\n[*] Images found:")
						for i in range(len(j['person']['images'])):
							if 'url' in j['person']['images'][i]:
								print ("- " + j['person']['images'][i]['url'])
					if 'urls' in j['person']:
						print ("\n[*] Associated Networks/URLs:")
						for i in range(len(j['person']['urls'])):
							if '@name' in j['person']['urls'][i] and '@domain' in j['person']['urls'][i] and 'url' in j['person']['urls'][i]:
								print("- " + j['person']['urls'][i]['@name'] + " / " + j['person']['urls'][i]['@domain'] + " / " + j['person']['urls'][i]['url'])
					if 'relationships' in j['person']:
						print ("\n[*] Relationships found:")
						for i in range(len(j['person']['relationships'])):
							if 'names' in j['person']['relationships'][i]:
								for k in range(len(j['person']['relationships'][i]['names'])):
									if 'first' in j['person']['relationships'][i]['names'][k]:
										print ("- First Name: " + j['person']['relationships'][i]['names'][k]['first'])
									if 'middle' in j['person']['relationships'][i]['names'][k]:
										print ("- Middle Name: " + j['person']['relationships'][i]['names'][k]['middle'])
									if 'last' in j['person']['relationships'][i]['names'][k]:
										print ("- Last Name: " + j['person']['relationships'][i]['names'][k]['last'])
									if 'display' in j['person']['relationships'][i]['names'][k]:
										print ("- Full Name: " + j['person']['relationships'][i]['names'][k]['display'] + "\n")
				else:
					print ("[!] No person found.")

				if 'possible_persons' in j:
					print ("\n[*] Possible persons found:")
					for i in range(len(j['possible_persons'])):
						print (str(i + 1) + ".")
						if 'names' in j['possible_persons'][i]:
							for k in range(len(j['possible_persons'][i]['names'])):
								if '@valid_since' in j['possible_persons'][i]['names'][k]:
									print ("- Name Since: " + j['possible_persons'][i]['names'][k]['@valid_since'])
								if 'first' in j['possible_persons'][i]['names'][k]:
									print ("- First Name: " + j['possible_persons'][i]['names'][k]['first'])
								if 'middle' in j['possible_persons'][i]['names'][k]:
									print ("- Middle Name: " + j['possible_persons'][i]['names'][k]['middle'])
								if 'last' in j['possible_persons'][i]['names'][k]:
									print ("- Last Name: " + j['possible_persons'][i]['names'][k]['last'])
								if 'display' in j['possible_persons'][i]['names'][k]:
									print ("- Full Name: " + j['possible_persons'][i]['names'][k]['display'])
						if 'usernames' in j['possible_persons'][i]:
							for k in range(len(j['possible_persons'][i]['usernames'])):
								if 'content' in j['possible_persons'][i]['usernames'][k]:
									print ("- Username: " + j['possible_persons'][i]['usernames'][k]['content'])
								if '@valid_since' in j['possible_persons'][i]['usernames'][k]:
									print ("- Username Since: " + j['possible_persons'][i]['usernames'][k]['@valid_since'])
						if 'gender' in j['possible_persons'][i]:
							if 'content' in j['possible_persons'][i]['gender']:
								print ("- Gender: " + j['possible_persons'][i]['gender']['content'])
						if 'languages' in j['possible_persons'][i]:
							for k in range(len(j['possible_persons'][i]['languages'])):
								if 'region' in j['possible_persons'][i]['languages'][k]:
									print ("- Region: " + j['possible_persons'][i]['languages'][k]['region'])
								if 'display' in j['possible_persons'][i]['languages'][k]:
									print ("- Language: " + j['possible_persons'][i]['languages'][k]['display'])
						if 'dob' in j['possible_persons'][i]:
							if 'display' in j['possible_persons'][i]['dob']:
								print ("- Age: " + str(j['possible_persons'][i]['dob']['display']))
						if 'phones' in j['possible_persons'][i]:
							for k in range(len(j['possible_persons'][i]['phones'])):
								if 'display_international' in j['possible_persons'][i]['phones'][k]:
									print ("- Telephone: " + j['possible_persons'][i]['phones'][k]['display_international'])
						if 'jobs' in j['possible_persons'][i]:
							for k in range(len(j['possible_persons'][i]['jobs'])):
								if 'organization' in j['possible_persons'][i]['jobs'][k]:
									print ("- Organization: " + j['possible_persons'][i]['jobs'][k]['organization'])
								if 'industry' in j['possible_persons'][i]['jobs'][i]:
									print ("- Industry: " + j['possible_persons'][i]['jobs'][k]['industry'])
								if 'data_range' in j['possible_persons'][i]['jobs'][k]:
									if 'start' in j['possible_persons'][i]['jobs'][k]['data_range']:
										print ("- Started in " + j['possible_persons'][i]['jobs'][k]['data_range']['start'])
									if 'end' in j['possible_persons'][i]['jobs'][i]['data_range']:
										print ("- Ended in " + j['possible_persons'][i]['jobs'][k]['data_range']['end'])
								if 'display' in j['possible_persons'][i]['jobs'][k]:
									print ("- Description: " + j['possible_persons'][i]['jobs'][k]['display'])
						if 'educations' in j['possible_persons'][i]:
							for k in range(len(j['possible_persons'][i]['educations'])):
								if 'degree' in j['possible_persons'][i]['educations'][k]:
									print ("- Degree: " + j['possible_persons'][i]['educations'][k]['degree'])
								if 'school' in j['possible_persons'][i]['educations'][k]:
									print ("- School: " + j['possible_persons'][i]['educations'][k]['school'])
								if 'data_range' in j['possible_persons'][i]['educations'][k]:
									if 'start' in j['possible_persons'][i]['educations'][k]['data_range']:
										print ("- Started in " + j['possible_persons'][i]['educations'][k]['data_range']['start'])
									if 'end' in j['possible_persons'][i]['educations'][k]['data_range']:
										print ("- Ended in " + j['possible_persons'][i]['educations'][k]['data_range']['end'])
								if 'display' in j['possible_persons'][i]['educations'][k]:
									print ("- Description: " + j['possible_persons'][i]['educations'][k]['display'])
						if 'user_ids' in j['possible_persons'][i]:
							for k in range(len(j['possible_persons'][i]['user_ids'])):
								if 'content' in j['possible_persons'][i]['user_ids'][k]:
									print ("- User-ID: " + j['possible_persons'][i]['user_ids'][k]['content'])
						if 'images' in j['possible_persons'][i]:
							for k in range(len(j['possible_persons'][i]['images'])):
								if 'url' in j['possible_persons'][i]['images'][k]:
									print ("- Image URL: " + j['possible_persons'][i]['images'][k]['url'])
						if 'urls' in j['possible_persons'][i]:
							for k in range(len(j['possible_persons'][i]['urls'])):
								if '@name' in j['possible_persons'][i]['urls'][k] and '@domain' in j['possible_persons'][i]['urls'][k] and 'url' in j['possible_persons'][i]['urls'][k]:
									print("- Associated Networks/URLs: " + j['possible_persons'][i]['urls'][k]['@name'] + " / " + j['possible_persons'][i]['urls'][k]['@domain'] + " / " + j['possible_persons'][i]['urls'][k]['url'])
						if 'relationships' in j['possible_persons'][i]:
							print ("- Relationships found:")
							for k in range(len(j['possible_persons'][i]['relationships'])):
								if 'names' in j['possible_persons'][i]['relationships'][k]:
									for l in range(len(j['possible_persons'][i]['relationships'][k]['names'])):
										if 'first' in j['possible_persons'][i]['relationships'][k]['names'][l]:
											print ("  - First Name: " + j['possible_persons'][i]['relationships'][k]['names'][l]['first'])
										if 'middle' in j['possible_persons'][i]['relationships'][k]['names'][l]:
											print ("  - Middle Name: " + j['possible_persons'][i]['relationships'][k]['names'][l]['middle'])
										if 'last' in j['possible_persons'][i]['relationships'][k]['names'][l]:
											print ("  - Last Name: " + j['possible_persons'][i]['relationships'][k]['names'][l]['last'])
										if 'display' in j['possible_persons'][i]['relationships'][k]['names'][l]:
											print ("  - Full Name: " + j['possible_persons'][i]['relationships'][k]['names'][l]['display'] + "\n")
		else:
			print("[!] Can't retrieve info from Pipl.")
	else:
		print ("[!] Pipl API Key not inserted.")
	return

def haveibeenpwned(email):
	
	print ("\n-> Data Breaches Results")

	req = urllib.request.Request(PWNED_API + email)
	req.add_header('User-Agent', USER_AGENT)
	r = urllib.request.urlopen(req).read().decode('utf-8')

	j = json.loads(r)

	print ("\n[@] Target: " + email)

	for i in range(len(j)):
		if 'Name' in j[i]:
			print ("\n[*] Data breach: " + j[i]['Name'])
		if 'Title' in j[i]:
			print ("[*] Title: " + j[i]['Title'])
		if 'Domain' in j[i]:
			print ("[*] Domain: " + j[i]['Domain'])
		if 'BreachDate' in j[i]:
			print ("[*] Date of the breach: " + j[i]['BreachDate'])
		if 'PwnCount' in j[i]:
			print ("[*] Number of accounts breached: " + str(j[i]['PwnCount']))
		if 'Description' in j[i]:
			print ("[*] Description: " + j[i]['Description'])
		if 'LogoPath' in j[i]:
			print ("[*] Logo image from " + j[i]['Name'] + ": " + j[i]['LogoPath'])
		if 'DataClasses' in j[i]:
			for k in range(len(j[i]['DataClasses'])):
				print ("[*] Data breached: " + j[i]['DataClasses'][k])

	print ("\n-> Data Pastes Results")

	req = urllib.request.Request(PWNED_PASTES_API + email)
	req.add_header('User-Agent', 'urllib-example/0.1')
	r = urllib.request.urlopen(req).read().decode('utf-8')

	j = json.loads(r)

	for i in range(len(j)):
		if 'Id' in j[i]:
			print ("\n[*] Data breach: " + str(j[i]['Id']))
		if 'Source' in j[i]:
			print ("[*] Source: " + str(j[i]['Source']))
		if 'Title' in j[i]:
			print ("[*] Title: " + str(j[i]['Title']))
		if 'Date' in j[i]:
			print ("[*] Date of the paste: " + str(j[i]['Date']))
		if 'EmailCount' in j[i]:
			print ("[*] Number of accounts: " + str(j[i]['EmailCount']))

def callerID(telephone, sid, a_token):
	
	phone = Phone(telephone, account_sid=sid, auth_token=a_token)

	print ("-> Caller ID Results")
	print ("\n[*] Number: " + phone.number)
	print ("[*] Country: " + phone.cnam)

def googleHacking(domain, dork, numP):

	results = google.search('site:' + domain + ' ' + dork, numP)

	if not len(results) == 0:
		for i in range(len(results)):
			print ("[*] Name: " + str(results[i].name))
			print ("[*] Link: " + str(results[i].link))
			print ("[*] URL: " + str(results[i].google_link))
			print ("[*] Description: " + str(results[i].description))
			print ("[*] Thumb: " + str(results[i].thumb))
			print ("[*] Cached: " + str(results[i].cached))
			print ("[*] Page: " + str(results[i].page))
			print ("[*] Index: " + str(results[i].index))
			print ("[*] Number of Results: " + str(results[i].number_of_results) + "\n")
	else:
		print ("[!] Nothing was retrieved.")

def allGoogleHacking(domain, pages):

	googleHacking(domain, DIR_LIST, pages)
	googleHacking(domain, FIL, pages)
	googleHacking(domain, DOC, pages)
	googleHacking(domain, DBS, pages)
	googleHacking(domain, LOGIN, pages)
	googleHacking(domain, SQL, pages)
	googleHacking(domain, SENS, pages)
	googleHacking(domain, PHP, pages)

def shodan_search(target, api_key):

	print ("\n-> Shodan Results")
	
	api = shodan.Shodan(api_key)

	print ('\n[@] Target: ' + target + '\n')

	if validators.ip_address.ipv4(target):

		host = api.host(target)
		
		print ("""
[*] City: {}
[*] Country: {}
[*] Postal Code: {}
[*] Longitude: {}
[*] Latitude: {}
[*] Operation System: {}
[*] Organization: {}
[*] ISP: {}""".format(host['city'], host['country_name'], host['postal_code'], host.get('longitude', 'N/A'), host.get('latitude', 'N/A'), host['os'], host['org'], host['isp']))

		if len(host['ports']) >= 1:
			for port in host['ports']:
				print ('[*] Port: ' + str(port))

		if len(host['hostnames']) >= 1:
			for hostname in host['hostnames']:
				print ('[*] Hostname: ' + str(hostname))

	elif validators.domain(target):
		
		host = api.search(target)

		if len(host['matches']) > 0:
			for service in host['matches']:
				print ("""
[*] IP: {}
[*] City: {}
[*] Country: {}
[*] Postal Code: {}
[*] Longitude: {}
[*] Latitude: {}
[*] Operation System: {}
[*] Organization: {}
[*] ISP: {}
[*] Port: {}""".format(service['ip_str'], service['location'].get('city', 'N/A'), service['location'].get('country_name', 'N/A'), service['location'].get('postal_code', 'N/A'), service['location'].get('longitude', 'N/A'), service['location'].get('latitude', 'N/A'), service['os'], service['org'], service.get('isp', 'N/A'), service.get('isp', 'N/A'),service.get('port')))
				for hostname in service['hostnames']:
					print ("[*] Hostname: " + hostname + '\n')

		else:
			print ('[!] Shodan: information about ' + target + ' was not found.')

	else:
		print ('[!] Shodan: bad input. Possible reasons:')
		print ('[!] Your target IP was mistyped.\n[!] Your target domain was mistyped.')

def whatCMS(target, api_key):

	print ('\n-> WhatCMS Results\n')

	data = urllib.request.urlopen(WHATCMS_API + api_key + '&url=' + target)
	j = json.load(data)

	if 'code' in j['result']:
		if j['result']['code'] == 200:
			print ("""[*] CMS: {} {}
[*] Accuracy: {}""".format(j['result'].get('name', 'N/A'), j['result'].get('version', 'N/A'), j['result'].get('confidence', 'N/A')))
		if j['result']['code'] == 0:
			print ('[!] whatCMS: ' + j['result']['msg'])
		if j['result']['code'] == 100:
			print ('[!] whatCMS: ' + j['result']['msg'])
		if j['result']['code'] == 101:
			print ('[!] whatCMS: ' + j['result']['msg'])
		if j['result']['code'] == 110:
			print ('[!] whatCMS: ' + j['result']['msg'])
		if j['result']['code'] == 111:
			print ('[!] whatCMS: ' + j['result']['msg'])
		if j['result']['code'] == 113:
			print ('[!] whatCMS: ' + j['result']['msg'])
		if j['result']['code'] == 120:
			print ('[!] whatCMS: ' + j['result']['msg'])
		if j['result']['code'] == 121:
			print ('[!] whatCMS: ' + j['result']['msg'])
		if j['result']['code'] == 123:
			print ('[!] whatCMS: ' + j['result']['msg'])
		if j['result']['code'] == 201:
			print ('[!] whatCMS: ' + j['result']['msg'])
		if j['result']['code'] == 202:
			print ('[!] whatCMS: ' + j['result']['msg'])
	else:
		print ("[!] Error")

def dnsDump(target_domain):

	print ('\n-> DNSdumpster Results\n')
	
	result = DNSDumpsterAPI().search(target_domain)

	if len(result) > 0:

		print ('[@] Target: ' + result['domain'] + '\n')

		print ('[*] DNS Servers')
		for record in result['dns_records']['dns']:
			print("""- Domain: {}
- IP: {}
- Reverse DNS: {}
- AS: {}
- ISP: {}
- Country: {}
- Header: {}
""".format(record['domain'], record['ip'], record['reverse_dns'], record['as'], record['provider'], record['country'], record['header']))

		print ('[*] MX Records')
		for record in result['dns_records']['mx']:
			print("""- Domain: {}
- IP: {}
- Reverse DNS: {}
- AS: {}
- ISP: {}
- Country: {}
- Header: {}
""".format(record['domain'], record['ip'], record['reverse_dns'], record['as'], record['provider'], record['country'], record['header']))

		print ('[*] TXT Records')
		for record in result['dns_records']['txt']:
			print ('- ' + record)

		print ('\n[*] Host Records')
		for record in result['dns_records']['host']:
			print("""- Domain: {}
- IP: {}
- Reverse DNS: {}
- AS: {}
- ISP: {}
- Country: {}
- Header: {}
""".format(record['domain'], record['ip'], record['reverse_dns'], record['as'], record['provider'], record['country'], record['header']))

def face(facebookURL):

	print ('\n-> Facebook Results\n')

	data = urllib.request.urlopen(facebookURL).read().decode('utf-8')
	
	if data.count('entity_id') == 1:
		eindex = int(data.index('entity_id')) + 12
		facebook_id = ''
		for i in data[eindex:]:
			if i == '"':
				break
			else:
				facebook_id = facebook_id + i			
		print ("[*] Facebook ID: " + facebook_id)
		print ("[*] Login to facebook and open: " + 'https://www.facebook.com/search/' + facebook_id + '/photos-of')
	else:
		print ('[!] Facebook ID not found.')

def crt(domain):

	print ('\n-> CRT.sh Results\n')
	
	req = urllib.request.Request(CRT_URL + domain + '&output=json')
	r = urllib.request.urlopen(req).read().decode('utf-8')

	j = json.loads(r)

	print ('[@] Target: ' + domain + '\n')

	if len(j) > 0:

		print ('[-] URL: ' + CRT_URL + domain)

		for cert in j:
			print ("""
[*] Issuer CA ID: {}
[*] Issuer Name: {}
[*] Name: {}
[*] Logged At: {}
[*] Not before: {}
[*] Not after: {}""".format(cert.get('issuer_ca_id', 'N/A'), cert.get('issuer_name', 'N/A'), cert.get('name_value', 'N/A'), cert.get('min_entry_timestamp', 'N/A'), cert.get('not_before', 'N/A'), cert.get('not_after', 'N/A')))

	else:
		print ("[!] crt.sh info not found.")
		sys.exit()

def fullcontact(target, api_key):

	print ("\n-> FullContact Results\n")

	fc = FullContact(api_key)
	r = fc.person(email=target)

	if r.status_code == 404:
		print ("[!] Data about " + target + " not found.")

	elif r.status_code == 200:

		j = r.json()

		print ("""
[*] Name: {}
[*] Family Name: {}
[*] Full Name: {}""".format(j['contactInfo'].get('givenName', 'N/A'), j['contactInfo'].get('familyName', 'N/A'), j['contactInfo'].get('fullName', 'N/A')))

		for site in j['contactInfo']['websites']:
			print ('[*] Website: {}'.format(site.get('url', 'N/A')))
		
		for org in j['organizations']:
			print ('[*] Organization: {} - Started: {} - Title: {} - Current: {}'.format(org.get('name', 'N/A'), org.get('startDate', 'N/A'), org.get('title', 'N/A'), org.get('current', 'N/A')))

		print ("""[*] Location: {}
[*] Continent: {}""".format(j['demographics']['locationDeduced'].get('deducedLocation' 'N/A'), j['demographics']['locationDeduced']['continent'].get('name', 'N/A')))

		for social in j['socialProfiles']:
			print ("""[*] Biography: {}
[*] From: {}
[*] Followers: {}
[*] Following: {}
[*] Username: {}
[*] URL: {}""".format(social.get('bio', 'N/A'), social.get('typeName', 'N/A'), social.get('followers', 'N/A'), social.get('following', 'N/A'), social.get('username', 'N/A'), social.get('url', 'N/A')))


def censysSearch(target, censys_id, censys_secret):

	print ("\n-> Censys Results\n")

	if validators.ip_address.ipv4(target):

		c = censys.ipv4.CensysIPv4(api_id=censys_id, api_secret=censys_secret)

		data = c.view(target)

		print ('[*] IP: ' + data['ip'])

		for protocol in data['protocols']:
			print ('[*] Protocol: ' + protocol)

		print ("""[*] Country: {}
[*] Registered Country: {}
[*] Longitude: {}
[*] Latitude: {}
[*] Continent: {}
[*] Timezone: {}""".format(data['location'].get('country', 'N/A'), data['location'].get('registered_country', 'N/A'), data['location'].get('longitude', 'N/A'), data['location'].get('latitude', 'N/A'), data['location'].get('continent', 'N/A'), data['location'].get('timezone', 'N/A')))

		print ("""[*] AS Name: {}
[*] AS Country Code: {}
[*] AS Description: {}""".format(data['autonomous_system'].get('name', 'N/A'), data['autonomous_system'].get('country_code', 'N/A'), data['autonomous_system'].get('description', 'N/A')))

		if '443' in data.keys():
			print ("\n[*] Service: https/443")

			if 'tls' in data['443']['https'].keys():

				if 'dns_names' in data['443']['https']['tls']['certificate']['parsed']['extensions']['subject_alt_name'].keys():
					print ("[*] Certificate DNS Names: " + str(data['443']['https']['tls']['certificate']['parsed']['extensions']['subject_alt_name']['dns_names']))

				if 'ip_addresses' in data['443']['https']['tls']['certificate']['parsed']['extensions']['subject_alt_name'].keys():
					print ("[*] Certificate IP addresses: " + str(data['443']['https']['tls']['certificate']['parsed']['extensions']['subject_alt_name']['ip_addresses']))

				if 'issuer' in data['443']['https']['tls']['certificate']['parsed'].keys():
					print ("[*] Issued By: " + str(data['443']['https']['tls']['certificate']['parsed']['issuer']))

		if '53' in data.keys():
			print ("\n[*] Service: dns/53")

			if 'lookup' in data['53']['dns'].keys():
				if 'open_resolver' in data['53']['dns']['lookup'].keys():
					print ("[*] Open Resolver: " + str(data['53']['dns']['lookup']['open_resolver']))

				if 'answers' in data['53']['dns']['lookup'].keys():

					for answer in data['53']['dns']['lookup']['answers']:
						print("[*] Lookup Answers: " + str(answer))


		
		print ("\n[*] Updated at: " + data['updated_at'])

def emailValidator(target, key):

	print('\n-> TowerData results\n')

	querystring = {"timeout":"10","email":target,"api_key":key}
	response = requests.request("GET", TOWERDATA_URL, params=querystring)
	
	j = json.loads(response.text)

	if len(j) > 0:
		if 'email_validation' in j.keys():
			print ("""[*] Email: {}
[*] Gender: {}
[*] Status: {}""".format(j['email_validation'].get('address', 'N/A'), j.get('gender', 'N/A'), j['email_validation'].get('status', 'N/A')))
	else: 
		print ('[*] Couldn\'t retrieve information about ' + target + '.')

def dnsZoneTranfers(target):

	print ('\n-> Zone Transfer Results')

	data = urllib.request.urlopen(HK_ZONETRANSFER_URL + target).read().decode('utf-8')

	print (data)

def extractURLs(target):

	print ('\n-> Extract URLs Results\n')

	data = urllib.request.urlopen(HK_PAGELINKS_URL + target).read().decode('utf-8')

	print (data)

def knowWhatYouDownload(target):
	
	print ('\n-> Know What You Download Results\n')

	print ('[*] https://iknowwhatyoudownload.com/en/peer/?ip=' + target)


try:

	pipl_key = ''
	fullcontact_key = ''
	caller_sid = ''
	caller_auth = ''
	shodan_key = ''
	cms_key = ''
	censys_api_id = ''
	censys_api_secret = ''
	towerdata_api_key = ''
	
	if apiFile():

		if sys.argv[1] == '-h' or sys.argv[1] == '--help':
			menu_options()
			sys.exit()

		elif sys.argv[1] == '-e':

			if validators.email(sys.argv[2]) and len(sys.argv) == 3:
				figlet_print()

				if not towerdata_api_key == '':
					emailValidator(sys.argv[2], towerdata_api_key)
				if not pipl_key == '':
					piplSearch(sys.argv[2], pipl_key)
				if not fullcontact_key == '':
					fullcontact(sys.argv[2], fullcontact_key)

				haveibeenpwned(sys.argv[2])
				sys.exit()

			elif validators.email(sys.argv[2]) and '--pipl' == sys.argv[3] and len(sys.argv) == 4:
				if pipl_key == '':
					print ("[*] Pipl API key don't exist.")
					sys.exit()
				else:
					figlet_print()
					piplSearch(sys.argv[2], pipl_key)
					sys.exit()

			elif validators.email(sys.argv[2]) and '--fullcontact' == sys.argv[3] and len(sys.argv) == 4:

				if fullcontact_key == '':
					print ("[*] FullContact API key don't exist.")
					sys.exit()
				else:
					figlet_print()
					fullcontact(sys.argv[2], pipl_key)
					sys.exit()

			elif validators.email(sys.argv[2]) and '--pwned' == sys.argv[3] and len(sys.argv) == 4:
				figlet_print()
				haveibeenpwned(sys.argv[2])
				sys.exit()

			elif validators.email(sys.argv[2]) and '--validate' == sys.argv[3] and len(sys.argv) == 4:
				if towerdata_api_key == '':
					print ("[*] TowerData API key don't exist.")
					sys.exit()
				else:
					figlet_print()
					emailValidator(sys.argv[2], towerdata_api_key)
					sys.exit()
			else:
				menu_bad_execution()

		elif sys.argv[1] == '-p' and sys.argv[3] == '--callerID' and len(sys.argv) == 4:
			
			figlet_print()

			if phonenumbers.is_valid_number(phonenumbers.parse(sys.argv[2], None)):
				if caller_sid == '' or caller_auth == '':
					print ("[!] CallerID or Caller Authenticaton Token doesn't exist.")

				else:
					callerID(sys.argv[2], caller_sid, caller_auth)
			else: 
				print ("[*] Target phone number is incorrect.")
				sys.exit()

		elif sys.argv[1] == '-t':

			if validators.domain(sys.argv[2]):

				if len(sys.argv) == 3:

					figlet_print()
					
					# do everything
					if not shodan_key == '':
						shodan_search(sys.argv[2], shodan_key)

					crt(sys.argv[2])
					dnsDump(sys.argv[2])
					dnsZoneTranfers(sys.argv[2])
					print ("\n-> Google Hacking Resuts\n")
					allGoogleHacking(sys.argv[2], 3)


				elif sys.argv[3] == '-d' and sys.argv[4] == '--all' and len(sys.argv) == 5:
					# All Dorks
					figlet_print()
					print ("\n-> Google Hacking Resuts\n")
					allGoogleHacking(sys.argv[2], 3)

				elif sys.argv[3] == '-d' and sys.argv[5] == '-n' and isinstance(int(sys.argv[6]), int) and len(sys.argv) == 7:

					if sys.argv[6] > '10':
						print ("[!] Too many pages to Google Hacking.")
						sys.exit()
					elif sys.argv[4] == 'dir_list':
						figlet_print()
						print ("\n-> Google Hacking Resuts\n")
						googleHacking(sys.argv[2], DIR_LIST, int(sys.argv[6]))
					elif sys.argv[4] == 'files':
						figlet_print()
						print ("\n-> Google Hacking Resuts\n")
						googleHacking(sys.argv[2], FIL, int(sys.argv[6]))
					elif sys.argv[4] == 'docs':
						figlet_print()
						print ("\n-> Google Hacking Resuts\n")
						googleHacking(sys.argv[2], DOC, int(sys.argv[6]))
					elif sys.argv[4] == 'db':
						figlet_print()
						print ("\n-> Google Hacking Resuts\n")
						googleHacking(sys.argv[2], DBS, int(sys.argv[6]))
					elif sys.argv[4] == 'login':
						figlet_print()
						print ("\n-> Google Hacking Resuts\n")
						googleHacking(sys.argv[2], LOGIN, int(sys.argv[6]))
					elif sys.argv[4] == 'sql':
						figlet_print()
						print ("\n-> Google Hacking Resuts\n")
						googleHacking(sys.argv[2], SQL, int(sys.argv[6]))
					elif sys.argv[4] == 'sensitive':
						figlet_print()
						print ("\n-> Google Hacking Resuts\n")
						googleHacking(sys.argv[2], SENS, int(sys.argv[6]))
					elif sys.argv[4] == 'php':
						figlet_print()
						print ("\n-> Google Hacking Resuts\n")
						googleHacking(sys.argv[2], PHP, int(sys.argv[6]))
					else:
						print ("[!] Bad dork.")
						sys.exit()
				elif sys.argv[3] == '--shodan' and len(sys.argv) == 4:

					if shodan_key == '':
						print ('[!] Shodan API key don\'t exist.')
						sys.exit()
					else:
						figlet_print()
						shodan_search(sys.argv[2], shodan_key)

				elif sys.argv[3] == '--crt' and len(sys.argv) == 4:
					figlet_print()
					crt(sys.argv[2])

				elif sys.argv[3] == '--dns' and len(sys.argv) == 4:
					figlet_print()
					dnsDump(sys.argv[2])
					dnsZoneTranfers(sys.argv[2])

			elif validators.ip_address.ipv4(sys.argv[2]):
				
				if len(sys.argv) == 3:
					
					figlet_print()
					if not shodan_key == '':
						shodan_search(sys.argv[2], shodan_key)

					if not (censys_api_id == '' or censys_api_secret == ''):
						censysSearch(sys.argv[2], censys_api_id, censys_api_secret)

					knowWhatYouDownload(sys.argv[2])

				elif sys.argv[3] == '--shodan' and len(sys.argv) == 4:

					figlet_print()
					if not shodan_key == '':
						shodan_search(sys.argv[2], shodan_key)

				elif sys.argv[3] == '--censys' and len(sys.argv) == 4:

					figlet_print()
					if not (censys_api_id == '' or censys_api_secret == ''):
						censysSearch(sys.argv[2], censys_api_id, censys_api_secret)
					else:
						print ('[!] Censys API ID or Secret don\'t exist.')

				elif sys.argv[3] == '--torrent' and len(sys.argv) == 4:

					figlet_print()
					knowWhatYouDownload(sys.argv[2])

				else:
					menu_bad_execution()

		elif sys.argv[1] == '-u':

			if len(sys.argv) == 3:

				figlet_print()
				if not cms_key == '':
					whatCMS(sys.argv[2], cms_key)

				extractURLs(sys.argv[2])

			elif sys.argv[3] == '--cms' and len(sys.argv) == 4:

				if cms_key == '':
					print ("[*] WhatCMS API key don't exist.")
					sys.exit()

				elif validators.url('http://' + sys.argv[2]):
					figlet_print()
					whatCMS(sys.argv[2], cms_key)
				else:
					print ('[!] Bad URL. Possible reasons:\n[!] The target URL is mistyped or doesn\'t exist.\n[!] The target URL don\'t contain the prefix \'https://\' or \'http://\' - Add it.')
				
			elif sys.argv[3] == '--facebook' and len(sys.argv) == 4:
				if validators.url(sys.argv[2]):
					figlet_print()
					face(sys.argv[2])
				else:
					print ('[!] Bad URL. Possible reasons:\n[!] The target URL is mistyped or doesn\'t exist.\n[!] The target URL don\'t contain the prefix \'https://\' or \'http://\' - Add it.')
				

			elif sys.argv[3] == '--extract' and len(sys.argv) == 4:
				if validators.url(sys.argv[2]):
					figlet_print()
					extractURLs(sys.argv[2])
				else:
					print ('[!] Bad URL. Possible reasons:\n[!] The target URL is mistyped or doesn\'t exist.\n[!] The target URL don\'t contain the prefix \'https://\' or \'http://\' - Add it.')
			else:
				menu_bad_execution()
			
		else:
			menu_bad_execution()

except IndexError:
	menu_bad_execution()

except urllib.error.URLError as e:
	
	if e.code == 404:
		print ('\n[!] Data not found. Possible reasons:')
		print ('[!] Target e-mail is mistyped or doesn\'t exist.\n[!] There aren\'t any data breaches for your target.\n[!] There aren\'t any data pastes results for your target.')

	elif e.code == 403:
		print ('\n[!] Bad request. Possible reasons:')
		print ('[!] Your Pipl API key is mistyped.\n[!] Your OpenCnam Account SID or Auth Token are mistyped.')
	else:
		print (str(e))

except urllib.error.HTTPError as e:
	print (tr(e) + '\n\nPossible reasons:\n[!] Bad Internet connection.\n[!] Resource doesn\'t exist')

except shodan.APIError as e:
	print ('[!] Shodan: ' + str(e))

except phonenumbers.phonenumberutil.NumberParseException as e:
	print (e)

except KeyboardInterrupt:
	sys.exit()
