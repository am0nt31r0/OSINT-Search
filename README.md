# OSINT-Search Description
- Script in Python that applies OSINT techniques by searching public data using email addresses, phone numbers, domains, IP addresses or URLs.
- Create an account at https://pipl.com/api and get the API key.
- Create an account at https://www.opencnam.com/ and get the Account SID and Auth Token.
- Create an account at https://www.shodan.io/ and get the Shodan API key.
- Create an account at https://whatcms.org/API and get the WhatCMS API key.

# Functionality

- Presents personal information like full name, age, gender, location, languages, social networks, etc...
- Presents information related to data breaches
- Presents information related to pastes of data breaches made public
- Presents which country a phone number belongs to
- Presents results of google hackings searches
- Presents results related to a domain or an IP address
- Presents CMS for a certain website
- Presents DNS Records information for a certain domain
- Presents Facebook ID after getting a facebook profile URL
- Presents digital certificates for a certain domain

More functionalities to be added later.

# Tested On

- Kubuntu 18.04.2 LTS
- Kali Linux 2019.1

# Requirements (Install)

- Python3 - https://docs.python-guide.org/starting/install3/linux/#install3-linux
- pip3 install -r requirements.txt
- pip3 install git+https://github.com/abenassi/Google-Search-API --upgrade
- pip3 install https://github.com/PaulSec/API-dnsdumpster.com/archive/master.zip --user

# Run

- On the first run of the script you need to submit your API fields to get all the functionality of the script. I suggest you create the accounts mentioned in the description.
- A configuration file called 'osintSearch.config.ini' is created with your data and can be edited by you.

# Usage

- ./osintS34rCh --help
