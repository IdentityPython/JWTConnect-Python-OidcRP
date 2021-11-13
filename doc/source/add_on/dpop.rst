.. _dpop:

************************************
Demonstration of Proof-of-possession
************************************

------------
Introduction
------------

In the traditional mechanism, API access is allowed only if the access
token presented by the client application is valid. However, if a
mechanism of PoP (Proof of Possession) such as DPoP is employed,
the API implementation additionally checks whether the client
application presenting the access token is the valid owner of the
access token (= whether the client application is the same one that
the access token has been issued to). If the client is not the valid
owner of the access token, the API access is rejected.

The `DPOP Internet draft`_ describes a mechanism for sender-constraining
OAuth 2.0 tokens via a proof-of-possession mechanism on the application
level. This mechanism allows for the detection of replay attacks with
access and refresh tokens.

-------------
Configuration
-------------

The only thing you can chose is the signing algorithms.
There are no default algorithms.

-------
Example
-------

What you have to do is to add a *dpop* section to an *add_ons* section
in a client configuration.

.. code:: python

    'add_ons': {
        "dpop": {
            "function": "oidcrp.oauth2.add_on.dpop.add_support",
            "kwargs": {
                "signing_algorithms": ["ES256", "ES512"]
            }
        }
    }


.. _DPOP Internet draft: https://datatracker.ietf.org/doc/draft-ietf-oauth-dpop/