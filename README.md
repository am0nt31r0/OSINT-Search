# OSINT-Search
- Script in Python that uses Pipl, Haveibeenpwned and Opencnam APIs to do OSINT searches using an email address, phone number.
- Create an account at https://pipl.com/api and get the API key.
- Create an account at https://www.opencnam.com/ and get the Account SID and Auth Token.

More functionality to be added later.

# Requirements

- pip3 install -r requirements.txt

# Usage

- ./osintS34rCh -e email@test.com
- ./osintS34rCh -e email@test.com -pk piplAPIkey
- ./osintS34rCh.py -p telenomeNumber -sid account_sid -t auth_token
