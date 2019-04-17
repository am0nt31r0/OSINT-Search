#!/usr/bin/python3

import sys
import urllib.request
import urllib.error
import json
from pyfiglet import Figlet
from opencnam import Phone
from google import google
import shodan
import validators



PWNED_API = 'https://haveibeenpwned.com/api/v2/breachedaccount/'
PWNED_PASTES_API = 'https://haveibeenpwned.com/api/v2/pasteaccount/'
USER_AGENT = 'urllib-example/0.1'


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

USAGES: 
  ./osintS34rCh -e <target@email>				# Data Breaches and Credentials Pastes
  ./osintS34rCh -e <target@email> -pk <piplAPIkey>		# People, Data Breaches and Credentials Pastes
  ./osintS34rCh.py -p <telnumber> -sid <SID> -t <auth_token>	# CallerID
  ./osintS34rCh.py -s <domain> -d <dork> -n <num_pages>		# Google Hacking
  ./osintS34rCh.py -t <target> -sk <shodanAPIkey>		# Shodan Recon

OPTIONS:
  -e <email>
  -pk <piplAPIkey>
  -p <telnumber>
  -sid <SID> 
  -t <auth_token> 
  -s <domain>
  -d <dork>
  -n <num_pages>
  -sk <shodanAPIkey>
  -t <target IP or Domain>
  -h or --help

DORKS:
  dir_list
  files
  docs
  db
  login
  sql
  sensitive
  php

MADE BY:
  am0nt31r0
   """)

def figlet_print():
	f = Figlet(font='slant')
	print (f.renderText('osintS34rCh'))

def menu_bad_execution():
	print ("osintS34rCh: bad execution")
	print ("Try using: ./osintS34rCh -h")
	sys.exit()

def piplSearch(email, key):

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

	print ("\n-> Haveibeenpwned Pastes Results")

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

	print ("-> Google Hacking Resuts")

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

def shodan_search(target, api_key):
	
	api = shodan.Shodan(api_key)

	print ('\n[@] Target: ' + target + '\n')

	if validators.ip_address.ipv4(target):

		host = api.host(target)
		
		print ("""[*] City: {}
[*] Country: {}
[*] Postal Code: {}
[*] Longitude: {}
[*] Latitude: {}
[*] Operation System: {}
[*] Organization: {}
[*] ISP: {}""".format(host['city'], host['country_name'], host['postal_code'], host.get('longitude', 'n/a'), host.get('latitude', 'n/a'), host['os'], host['org'], host['isp']))

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
				print ("""[*] IP: {}
[*] City: {}
[*] Country: {}
[*] Postal Code: {}
[*] Longitude: {}
[*] Latitude: {}
[*] Operation System: {}
[*] Organization: {}
[*] ISP: {}
[*] Port: {}""".format(service['ip_str'], service['location'].get('city', 'n/a'), service['location'].get('country_name', 'n/a'), service['location'].get('postal_code', 'n/a'), service['location'].get('longitude', 'n/a'), service['location'].get('latitude', 'n/a'), service['os'], service['org'], service.get('isp', 'n/a'), service.get('isp', 'n/a'),service.get('port')))
				for hostname in service['hostnames']:
					print ("[*] Hostname: " + hostname + '\n')

		else:
			print ('[!] Shodan: information about ' + target + ' was not found.')

	else:
		print ('[!] Shodan: bad input. Possible reasons:')
		print ('[!] Your target IP was mistyped.\n[!] Your target domain was mistyped.')

try:

	if sys.argv[1] == '-h' or sys.argv[1] == '--help':
		menu_options()
		sys.exit()

	elif '-e' == sys.argv[1]:

		if validators.email(sys.argv[2]) and len(sys.argv) == 3:
			figlet_print()
			print ("\n-> Haveibeenpwned Results")
			haveibeenpwned(sys.argv[2])

		elif validators.email(sys.argv[2]) and '-pk' == sys.argv[3] and len(sys.argv) == 5:
			figlet_print()
			print ("-> Pipl Results")
			piplSearch(sys.argv[2], sys.argv[4])
			print ("\n-> Haveibeenpwned Results")
			haveibeenpwned(sys.argv[2])

		else:
			menu_bad_execution()

	elif '-p' == sys.argv[1] and '-sid' == sys.argv[3] and '-t' == sys.argv[5] and len(sys.argv) == 7:
		figlet_print()
		callerID(sys.argv[2], sys.argv[4], sys.argv[6])

	elif '-s' == sys.argv[1] and '-d' == sys.argv[3] and '-n' == sys.argv[5] and validators.domain(sys.argv[2]) and isinstance(int(sys.argv[6]), int) and len(sys.argv) == 7:

		if sys.argv[6] >= '10':
			print ("[!] Too many pages to Google Hacking.")
			sys.exit()
		elif sys.argv[4] == 'dir_list':
			figlet_print()
			googleHacking(sys.argv[2], DIR_LIST, int(sys.argv[6]))
		elif sys.argv[4] == 'files':
			figlet_print()
			googleHacking(sys.argv[2], FIL, int(sys.argv[6]))
		elif sys.argv[4] == 'docs':
			figlet_print()
			googleHacking(sys.argv[2], DOC, int(sys.argv[6]))
		elif sys.argv[4] == 'db':
			figlet_print()
			googleHacking(sys.argv[2], DBS, int(sys.argv[6]))
		elif sys.argv[4] == 'login':
			figlet_print()
			googleHacking(sys.argv[2], LOGIN, int(sys.argv[6]))
		elif sys.argv[4] == 'sql':
			figlet_print()
			googleHacking(sys.argv[2], SQL, int(sys.argv[6]))
		elif sys.argv[4] == 'sensitive':
			figlet_print()
			googleHacking(sys.argv[2], SENS, int(sys.argv[6]))
		elif sys.argv[4] == 'php':
			figlet_print()
			pgoogleHacking(sys.argv[2], PHP, int(sys.argv[6]))
		else:
			print ("[!] Bad dork.")
			sys.exit()
	elif '-t' == sys.argv[1] and '-sk' == sys.argv[3] and len(sys.argv) == 5:
		figlet_print()
		print ("\n-> Shodan Results")
		shodan_search(sys.argv[2], sys.argv[4])
	else:
		menu_bad_execution()

except IndexError:
	menu_bad_execution()

except urllib.error.URLError as e:
	if e.code == 404:
		print ('\n[!] Data not found. Possible reasons:')
		print ('[!] Target e-mail is wrong or doesn\'t exist\n[!] There aren\'t any data breaches for your target.\n[!] There aren\'t any data pastes results for your target.')
	elif e.code == 403:
		print ('\n[!] Bad request. Possible reasons:')
		print ('[!] Your Pipl API key is wrong.\n[!] Your OpenCnam Account SID or Auth Token are wrong.')

except urllib.error.HTTPError as e:
	print (tr(e) + '\n\nPossible reasons:\n[!] Bad Internet connection.\n[!] Resource doesn\'t exist')

except shodan.APIError as e:
	print ('[!] Shodan: ' + str(e))

except KeyboardInterrupt:
	sys.exit()
