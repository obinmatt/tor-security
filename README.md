# TORSecurity

The Onion Routing (TOR) is an anonymous networking system that protects the identity privacy of source and destination. In this project, I will study the principle of TOR and its related core cryptographic techniques i.e., RSA and AES encryption, and then develop a TOR system in a virtual environment. This will provide myself with a deeper understanding of TOR systems and its potential flaws, along with learning how to better protect one’s online identity.

Steps to run:
## 1. Install requirements
``` bash
pip3 install -r /path/to/requirements.txt
```
## 2. Start directory
``` bash
python3 directory.py
```
## 3. Start router,py in separate terminal
``` bash
python3 router.py localhost 9002
```

## 4. Repeat step 3 for as many hops as you'd like (alice.py is set up to work with three)
``` bash
python3 router.py localhost 9003
python3 router.py localhost 9004
```

## 5. Start op.py
```bash
python3 op.py localhost 9000
```

## 6. Interact with SOCKS5 server
```bash
I used the FoxyProxy extenison on Firefox
```

## 7. Done!
