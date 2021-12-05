.. _pkce:

***************************
Proof Key for Code Exchange
***************************

------------
Introduction
------------

OAuth 2.0 public clients utilizing the Authorization Code Grant are
susceptible to the authorization code interception attack.  `RFC7636`_
describes the attack as well as a technique to mitigate
against the threat through the use of Proof Key for Code Exchange
(PKCE, pronounced "pixy").

-------------
Configuration
-------------

You can set *code_challenge_length* and *code_challenge_method*.
Both have defaults:

- code_challenge_length: 64 and
- code_challenge_method: S256

*S256* is mandatory to implement so there should be good reasons for
not choosing it. To other defined method is *plain*. *plain* should only
be used when you rely on the operating system and transport
security not to disclose the request to an attacker.

The security model relies on the fact that the code verifier is not
learned or guessed by the attacker.  It is vitally important to
adhere to this principle.  As such, the code verifier has to be
created in such a manner that it is cryptographically random and has
high entropy that it is not practical for the attacker to guess.

The client SHOULD create a "code_verifier" with a minimum of 256 bits
of entropy.  This can be done by having a suitable random number
generator create a 32-octet sequence.

code_challenge_length is the length of that sequence.

-------
Example
-------

.. code:: python

    "add_ons": {
        "pkce": {
            "function": "oidcrp.oauth2.add_on.pkce.add_support",
            "kwargs": {
                "code_challenge_length": 64,
                "code_challenge_method": "S256"
            }
        }
    }

.. _RFC7636: https://datatracker.ietf.org/doc/html/rfc7636