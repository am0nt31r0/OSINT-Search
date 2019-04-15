# OSINT-Search
- Script in Python that uses Pipl, Haveibeenpwned, Opencnam and Google APIs to do OSINT searches using an email address, phone number and domain.
- Create an account at https://pipl.com/api and get the API key.
- Create an account at https://www.opencnam.com/ and get the Account SID and Auth Token.

More functionality to be added later.

# Requirements

- pip3 install -r requirements.txt

# Usage

- ./osintS34rCh -e email@test.com
- ./osintS34rCh -e email@test.com -pk piplAPIkey
- ./osintS34rCh.py -p telenomeNumber -sid account_sid -t auth_token
- ./osintS34rCh.py -s domain.com -d google_dork -n num_pages
