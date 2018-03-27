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

Which of the above listed services that your RP will use when talking to an OP
are usually decided by the OP. Just to show you how it can differ between
different OPs I'll give you a couple of examples below:

Google
    If you want to use the Google OP as authentication service you should know
    that it is a true OIDC OP `certified`_ by the OpenID Foundation. You will
    have to manually register you RP at Google but getting Provider info can be
    done dynamically using the OIDC service. With Google you will use the
    response_type *code*. This means that you will need services 2,4,5 and 6
    from the list above. More about how you will accomplish this below

Microsoft
    Microsoft have chosen to only support response_type *id_token* and to
    return all the user information in the **id_token**. Microsoft's OP
    supports dynamic Provider info discovery but client registration is
    done manual. What it comes down to is that you will only need services
    2 and 4.

Github
    Now, to begin with Github is not running an OP they basically have an
    Oauth2 AS with some additions. It doesn't support dynamic provider info
    discovery or client registration. If expects response_type to be *code*
    so services 4,5 and 6 are needed.

.. _certified : http://openid.net/certification/

After this background you should now be prepared to dive into how the RP handler
should be used.

--------------
RP handler API
--------------

A session is defined as the services used to cope with authorization/authentication
for one user starting with the authorization request.

The high level methods you have access to (in the order they are to be
used) are:

:py:meth:`oidcrp.RPHandler.begin`
    This method will initiate a RP/Client instance if none exists for the
    OP/AS in question. It will then run service 1 if needed, services 2 and 3
    according to configuration and finally will construct the authorization
    request.

:py:meth:`oidcrp.RPHandler.get_session_information`
    In the authorization response there MUST be a state parameter. The value
    of that parameter is the key into a data store that will provide you
    with information about the session so far.

:py:meth:`oidcrp.RPHandler.finalize`
    Will parse the authorization response and depending on the configuration
    run the services 5 and 6.


------------------------
RP handler configuration
------------------------

As you may have guessed by now a lot of the work you have to do to use this
packages lies in the RP configuration.

The configuration parameters fall into 2 groups, one about the RP/client and
the other about the OP/AS

RP configuration parameters
---------------------------

Disregarding if doing everything dynamically or statically you **MUST**
define which services the RP/Client should be able to use.

services
    A specification of the usable services which possible changes to the
    default configuration of those service.

If you have done manual client registration you will have to fill in these:

client_id
    The client identifier.

client_secret
    The client secret

redirect_uris
    A set of URLs from which the RP can chose one to be added to the
    authorization request. The expectation is that the OP/AS will redirect
    the use back to this URL after the authorization/authentication has
    completed.

behavior
    Information about how the RP should behave towards the OP/AS

If the provider info discovery is done dynamically you need this

client_prefs
    How the RP should prefer to behave against the OP/AS

OP configuration parameters
---------------------------

issuer
    The Issuer ID of the OP.

allow
    If there is a deviation from the standard as to how the OP/AS behaves this
    gives you the possibility to say you are OK with the deviation.
    Presently there is only one thing you can allow and that is the *issuer*
    in the provider info is not the same as the URL you used to fetch the
    information.

RP configuration - Google
-------------------------

A working configuration where the client_id and client_secret is replaced
with dummy values::

    {
        "issuer": "https://accounts.google.com/",
        "client_id": "xxxxxxxxx.apps.googleusercontent.com",
        "client_secret": "2222222222",
        "redirect_uris": ["{}/authz_cb/google".format(BASEURL)],
        "client_prefs": {
            "response_types": ["code"],
            "scope": ["openid", "profile", "email"],
            "token_endpoint_auth_method": ["client_secret_basic",
                                           'client_secret_post']
        },
        "services": {
            'ProviderInfoDiscovery': {},
            'Authorization': {},
            'AccessToken': {},
            'RefreshAccessToken': {},
            'UserInfo': {}
        }
    }

