.. _oidcrp_rp:

*****************************
The Relying Party Handler API
*****************************

------------
Introduction
------------

Imaging that you have web service where some of the functions that service
provides are protected and should only be accessible to authenticated users or
some of the functions needs access to some user related resources on a
resource server. That's when you need OpenID Connect (OIDC) or Oauth2.

The RPHandler as implemented in :py:class:`oidcrp.RPHandler` is a service within
the web service that handles the authentication/authorization for the web
service.

---------------
Some background
---------------

In the following description I will talk about Relying Party (RP)
and OpenID Connect Provider (OP) but I could have used Oauth2 Client
and OAuth2 Authorization Server instead. There are some differences
in the details between the two sets but overall the entities work much the same
way.

OpenID Connect (OIDC) are build on a request-response paradigm.
The RP issues a request and the OP returns a response.

The OIDC core standard defines a set of such request-responses.
This is the list and the normal sequence in which they occur:

1. Provider discovery (WebFinger)
2. Provider Info Discovery
3. Client registration
4. Authorization/Authentication
5. Access token
6. User info

--------------------
The course of action
--------------------

When a user accessing the web service for some reason needs to be authenticate
or the service needs a access token that allows it to access some resources
at a resource service on behalf of the user a number of things will happen:

Find out which OP to talk to.
    If the RP handler is configured to only communicate to a defined set of OPs
    then the user is probable presented a list to chose from.
    If the OP the user wants to authenticated at is unknown to the RP Handler
    it will use some discovery service to, given some information provided by
    the user, find out where to learn more about the OP.

Gather information about the OP
    This can be done out-of-band in which case the administrator of the service
    has gathered the information by contacting the administrator of the OP.
    In most cases this is done by reading the necessary information on a web
    page provided by the organization responsible for the OP.
    One can also chose to gather the information on-the-fly by using the
    provider info discovery service provided by OIDC.

Register the client with the OP
    Again this can be done before hand or it can be done on-the-fly when needed.
    If it's done before you will have to use a registration service provided by
    the organization responsible for the OP.
    If it's to be done on-the-fly you will have to use the dynamic client
    registration service OIDC provides

Authentication/Authorization
    This is done by the user at the OP.

What happens after this depends on which *response_type* is used. If the
*response_type* is **code** then the following step is done:

Access token request
    Base on the information received in the authorization response a request
    for an access token is made to the OP

And if the web service wants user information it might also have to do:

Obtain user info
    Using the access token received above a userinfo request will be sent to the
    OP.


