# POODLE Attack
The Padding Oracle On Downgraded Legacy Encryption (**POODLE**) attack exploits a vulnerability in the SSL 3.0 protocol (CVE-2014-3566). This vulnerability lets an attacker eavesdrop on communication encrypted using SSLv3. The vulnerability is no longer present in the Transport Layer Security protocol (TLS), which is the successor to SSL (Secure Socket Layer). This is a simple proof of concept.

## Dependencies
`pip install -r requirements.txt`
## Usage
`./poodle.py`

or alternatively

`python3 poodle.py`
