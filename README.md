# SMTP tester

## Simple server & tester for SMTP debugging

### Install basic

- clone the repos
- yarn
- in different terminals;
  - node index.js
  - node tester.js -h 127.0.0.1 -p 25

### Install with demo pipe

- clone the repos
- yarn
- in different terminals;
  - node index.js -p ./echojson
  - node tester.js -h 127.0.0.1 -p 25

### Creating servers on 25, 465 (tls), 587 (starttls)

- Let's say you have Let's Encrypt certificates in; /etc/letsencrypt/live/mydomaincom/\*

```
node index.js -P 25 -s mydomain.com
node index.js -P 465 -c /etc/letsencrypt/live/mydomaincom/fullchain.pem -k /etc/letsencrypt/live/mydomaincom/privkey.pem -s mydomain.com
node index.js -P 587 -c /etc/letsencrypt/live/mydomaincom/fullchain.pem -k /etc/letsencrypt/live/mydomaincom/privkey.pem -s mydomain.com -fi true

```

- Testing:

```
telnet localhost 25
openssl s_client -starttls smtp -connect mydomain.com:587 -servername mydomain.com
openssl s_client -connect mydomain.com:465 -servername mydomain.com

swaks --to someone@somewhere.com --from info@mydomain.com --server localhost:25 --auth-user hello --auth-password there
```
