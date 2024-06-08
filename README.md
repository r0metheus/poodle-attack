# POODLE Attack Proof of Concept

The Padding Oracle On Downgraded Legacy Encryption (POODLE) attack exploits a vulnerability in the SSL 3.0 protocol (CVE-2014-3566). This vulnerability allows an attacker to eavesdrop on communications encrypted using SSLv3. Although the vulnerability is no longer present in the Transport Layer Security (TLS) protocol, which is the successor to SSL (Secure Socket Layer), this repository provides a simple proof of concept (PoC) for educational purposes.

## Introduction
The POODLE attack exploits SSL 3.0's fallback mechanism and its use of the CBC (Cipher Block Chaining) mode of encryption. By carefully crafting requests and analyzing the responses, an attacker can decrypt the plaintext of an intercepted SSLv3 session byte by byte.

## How It Works
* Padding Oracle: The attack takes advantage of a padding oracle to distinguish between valid and invalid padding. By sending multiple requests and observing the server's responses, an attacker can infer the plaintext.
* Block-wise Decryption: The attacker decrypts the ciphertext block by block. By manipulating the ciphertext and utilizing the padding oracle, each byte of the plaintext can be recovered.

## Installation
To install the necessary dependencies, run:
`pip install -r requirements.txt`

## Usage
To run the POODLE attack proof of concept, execute:

`./poodle.py`

Or alternatively:

`python3 poodle.py`
