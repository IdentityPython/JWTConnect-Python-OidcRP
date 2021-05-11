.. _oidcrp_rp:

*************************
The Relying Party Handler
*************************

------------
Introduction
------------

Imaging that you have a web service where some of the functions that service
provides are protected and should only be accessible to authenticated users or
that some of the functions the service provides needs access to some user
related resources on a resource server. That's when you need OpenID Connect
(OIDC) or Oauth2.

The RPHandler as implemented in :py:class:`oidcrp.rp_handler.RPHandler` is a
service within
the web service that handles user authentication and access authorization on
behalf of the web service.

---------------
Some background
---------------

In the following description I will talk about Relying Party (RP)
and OpenID Connect Provider (OP) but I could have talked about Oauth2 Client
and OAuth2 Authorization Server instead. There are some differences
in the details between the two sets but overall the entities work much the same
way.

OAuth2 and thereby OpenID Connect (OIDC) are built on a request-response paradigm.
The RP issues a request and the OP returns a response.

The OIDC core standard defines a set of such request-responses.
This is a basic list of request-responses and the normal sequence in which they
occur:

1. Provider discovery (WebFinger)
2. Provider Info Discovery
3. Client registration
4. Authorization/Authentication
5. Access token
6. User info

When a user accessing the web service for some reason needs to be authenticate
or the service needs an access token that allows it to access some resources
at a resource service on behalf of the user a number of things will happen:

Find out which OP to talk to.
    If the RP handler is configured to only communicate to a defined set of OPs
    then the user is probable presented a list to choose from.
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
    Again, this can be done beforehand or it can be done on-the-fly when needed.
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
    done dynamically using an OIDC service. With Google you will use the
    response_type *code*. This means that you will need services 2,4,5 and 6
    from the list above. More about how you will accomplish this below

Microsoft
    Microsoft have chosen to only support response_type *id_token* and to
    return all the user information in the **id_token**. Microsoft's OP
    supports dynamic Provider info discovery but client registration is
    done manual. What it comes down to is that you will only need services
    2 and 4.

GitHub
    Now, to begin with GitHub is not running an OP they basically have an
    Oauth2 AS with some additions. It doesn't support dynamic provider info
    discovery or client registration. If expects response_type to be *code*
    so services 4,5 and 6 are needed.

.. _certified : http://openid.net/certification/

After this background you should now be prepared to dive into how the RP handler
should be used.

--------------
RP handler API
--------------

A session is defined as a sequence of services used to cope with
authorization/authentication for one user starting with the authorization request.

Tier 1 API
----------

The high-level methods you have access to (in the order they are to be
used) are:

:py:meth:`oidcrp.rp_handler.RPHandler.begin`
    This method will initiate a RP/Client instance if none exists for the
    OP/AS in question. It will then run service 1 if needed, services 2 and 3
    according to configuration and finally will construct the authorization
    request.

    Usage example::

        $ from oidcrp import RPHandler
        $ rph = RPHandler()
        $ issuer_id = "https://example.org/"
        $ info = rph.begin(issuer_id)
        $ print(info['url'])
        https://example.org/op/authorization?state=Oh3w3gKlvoM2ehFqlxI3HIK5&nonce=UvudLKz287YByZdsY3AJoPAlEXQkJ0dK&redirect_uri=https%3A%2F%2Fexample.com%2Frp%2Fauthz_cb&response_type=code&scope=openid&client_id=zls2qhN1jO6A

What happens next is that the user is redirected to the URL shown above.
After the user has authenticated, handled consent and access management
the user will be redirect back to the URL provided as value to the
redirect_uri parameter in the URL above. The query part may look something
like this::

    state=Oh3w3gKlvoM2ehFqlxI3HIK5&scope=openid&code=Z0FBQUFBQmFkdFFjUVpFWE81SHU5N1N4N01&iss=https%3A%2F%2Fexample.org%2Fop&client_id=zls2qhN1jO6A

After the RP has received this response the processing continues with:

:py:meth:`oidcrp.rp_handler.RPHandler.get_session_information`
    In the authorization response there MUST be a state parameter. The value
    of that parameter is the key into a data store that will provide you
    with information about the session so far.

    Usage example (kwargs are the set of claims in the authorization response)::

        session_info = rph.state_db_interface.get_state(kwargs['state'])

:py:meth:`oidcrp.rp_handler.RPHandler.finalize`
    Will parse the authorization response and depending on the configuration
    run the services 5 and 6.

    Usage example::

        res = rph.finalize(session_info['iss'], kwargs)


Tier 2 API
----------

The tier 1 API is good for getting you started with authenticating a user and
getting user information but if you're look at a long-term engagement you need
a finer grained set of methods. These I call the tier 2 API:

:py:meth:`oidcrp.rp_handler.RPHandler.do_provider_info`
    Either get the provider info from configuration or through dynamic
    discovery. Will overwrite previously saved provider metadata.

:py:meth:`oidcrp.rp_handler.RPHandler.do_client_registration`
    Do dynamic client registration is configured to do so and the OP supports it.

:py:meth:`oidcrp.rp_handler.RPHandler.init_authorization`
    Initialize an authorization/authentication event. If the user has a
    previous session stored this will not overwrite that but will create a new
    one.

    Usage example (note that you can modify what would be used by default)::

        res = self.rph.init_authorization(state_key,
                                          {'scope': ['openid', 'email']})

The state_key you see mentioned here and below is the value of the state
parameter in the authorization request.

:py:meth:`oidcrp.rp_handler.RPHandler.get_access_token`
    Will use an access code received as the response to an
    authentication/authorization to get an access token from the OP/AS.
    Access codes can only be used once.

    Usage example::

        res = self.rph.get_access_token(state_key)

:py:meth:`oidcrp.rp_handler.RPHandler.refresh_access_token`
    If the client has received a refresh token this method can be used to get
    a new access token.

    Usage example::

        res = self.rph.refresh_access_token(state_key, scope='openid email')

You may change the set of scopes that are bound to the new access token but
that change can only be a downgrade from what was specified in the
authorization request and accepted by the user.

:py:meth:`oidcrp.rp_handler.RPHandler.get_user_info`
    If the client is allowed to do so, it can refresh the user info by
    requesting user information from the userinfo endpoint.

    Usage example::

        resp = self.rph.get_user_info(state_key)

:py:meth:`oidcrp.rp_handler.RPHandler.has_active_authentication`
    After a while when the user returns after having been away for a while
    you may want to know if you should let her reauthenticate or not.
    This method will tell you if the last done authentication is still
    valid or of it has timed out.

    Usage example::

        resp = self.rph.has_active_authentication(state_key)

    response will be True or False depending in the state of the authentication.

:py:meth:`oidcrp.rp_handler.RPHandler.get_valid_access_token`
    When you are issued a access token it normally comes with a life time.
    After that time you are expected to use the refresh token to get a new
    access token. There are 2 ways of finding out if the access token you have is
    past its life time. You can use this method or you can just try using
    the access token and see what happens.

    Now, if you use this method and it tells you that you have an access token
    that should still be usable, that is no guarantee it is still usable.
    Things may have happened on the OPs side that makes the access token
    invalid. So if this method only returns a hint as to the usability of the
    access token.

    Usage example::

        resp = self.rph.get_valid_access_token(state_key)

    Response will be a tuple containing with the access token and the
    expiration time (in epoch) if there is a valid access token otherwise an
    exception will be raised.

----------------
RP configuration
----------------

As you may have guessed by now a lot of the work you have to do to use this
packages lies in the RP configuration.

The configuration parameters fall into 2 groups, one general that is the
same for all RP/clients and one which is specific for a specific
OP/AS

General RP configuration parameters
-----------------------------------

Among the general parameters you have to define:

port
    Which port the RP is listening on

domain
    The domain the RP belongs to

these 2 together then defines the base_url. which is normally defined as::

    base_url: "https://{domain}:{port}"


logging
    How the process should log

httpc_params
    Defines how the process performs HTTP requests to other entities.
    Parameters here are typically **verify** which controls whether the http
    client will verify the server TLS certificate or not.
    Other parameters are **client_cert**/**client_key** which are needed only
    if you expect the TLS server to ask for the clients TLS certificate.
    Something that happens if you run in an environment where mutual TLS is
    expected.

rp_keys
    Definition of the private keys that all RPs are going to use in the OIDC
    protocol exchange.

There might be other parameters that you need dependent on which web framework
you chose to use.

OP/AS specific configuration parameters
---------------------------------------

The client configuration is keyed to an OP/AS name. This name should
be something human readable it does not have to in anyway be linked to the
issuer ID of the OP/AS.

The key **""** (the empty string) is chosen to represent all OP/ASs that
are dynamically discovered.

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
    completed. These URLs should be OP/AS specific.

behaviour
    Information about how the RP should behave towards the OP/AS. This is
    a set of attributes with values. The attributes taken from the
    `client metadata`_ specification. *behaviour* is used when the client
    has been registered statically and it is know what the client wants to
    use and the OP supports.

    Usage example::

        "behaviour": {
            "response_types": ["code"],
            "scope": ["openid", "profile", "email"],
            "token_endpoint_auth_method": ["client_secret_basic",
                                           'client_secret_post']
        }


rp_keys
    If the OP doesn't support dynamic provider discovery it may still want to
    have a way of distributing keys that allows it to rotate them at anytime.
    To accomplish this some providers have chosen to publish a URL to where
    you can find their OPs key material in the form of a JWKS.

    Usage example::

        'keys': {'url': {<issuer_id> : <jwks_url>}}


If the provider info discovery is done dynamically you need this

client_preferences
    How the RP should prefer to behave against the OP/AS. The content are the
    same as for *behaviour*. The difference is that this is specified if the
    RP is expected to do dynamic client registration which means that at the
    point of writing the configuration it is only known what the RP can and
    wants to do but unknown what the OP supports.

issuer
    The Issuer ID of the OP.

allow
    If there is a deviation from the standard as to how the OP/AS behaves this
    gives you the possibility to say you are OK with the deviation.
    Presently there is only one thing you can allow and that is the *issuer*
    in the provider info is not the same as the URL you used to fetch the
    information.

.. _client metadata: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata

-------------------------
RP configuration - Google
-------------------------

A working configuration where the client_id and client_secret is replaced
with dummy values::

    {
        "issuer": "https://accounts.google.com/",
        "client_id": "xxxxxxxxx.apps.googleusercontent.com",
        "client_secret": "2222222222",
        "redirect_uris": ["{}/authz_cb/google".format(BASEURL)],
        "behaviour": {
            "response_types": ["code"],
            "scope": ["openid", "profile", "email"],
            "token_endpoint_auth_method": ["client_secret_basic",
                                           'client_secret_post']
        },
        "services": {
            'ProviderInfoDiscovery': {},
            'Authorization': {},
            'AccessToken': {},
            'UserInfo': {}
        }
    }


Now piece by piece

Information provided by Google::

        "issuer": "https://accounts.google.com/",

Information about the client. When you register your RP with Google you will
in return get a client_id and client_secret::

        "client_id": "xxxxxxxxx.apps.googleusercontent.com",
        "client_secret": "2222222222",
        "redirect_uris": ["{}/authz_cb/google".format(BASEURL)],

Now to the behaviour of the client. Google specifies response_type *code* which
is reflected here. The scopes are picked form the set of possible scopes that
Google provides. And lastly the *token_endpoint_auth_method*, where Google
right now supports 2 variants both listed here. The RP will by default pick
the first if a list of possible values. Which in this case means the RP will
authenticate using the *client_secret_basic* if allowed by Google::

        "behaviour": {
            "response_types": ["code"],
            "scope": ["openid", "profile", "email"],
            "token_endpoint_auth_method": ["client_secret_basic",
                                           'client_secret_post']
        },

And lastly, which service the RP has access to. *ProviderInfoDiscovery* since
Google supports dynamic provider info discovery. *Authorization* always must be
there. *AccessToken* and *UserInfo* since response_type is *code* and Google
return the user info at the userinfo endpoint::


        "services": {
            'ProviderInfoDiscovery': {},
            'Authorization': {},
            'AccessToken': {},
            'UserInfo': {}
        }


----------------------------
RP configuration - Microsoft
----------------------------

Configuration that allows you to use a Microsoft OP as identity provider::

    {
        'issuer': 'https://login.microsoftonline.com/<tenant_id>/v2.0',
        'client_id': '242424242424',
        'client_secret': 'ipipipippipipippi',
        "redirect_uris": ["{}/authz_cb/microsoft".format(BASEURL)],
        "behaviour": {
            "response_types": ["id_token"],
            "scope": ["openid"],
            "token_endpoint_auth_method": ['client_secret_post'],
            "response_mode": 'form_post'
        },
        "allow": {
            "issuer_mismatch": True
        },
        "services": {
            'ProviderInfoDiscovery':{},
            'Authorization': {}
        }
    }

One piece at the time. Microsoft has something called a tenant. Either you
specify your RP to only one tenant in which case the issuer returned
as *iss* in the id_token will be the same as the *issuer*. If our RP
is expected to work in a multi-tenant environment then the *iss* will **never**
match issuer. Let's assume our RP works in a single-tenant context::

        'issuer': 'https://login.microsoftonline.com/<tenant_id>/v2.0',
        "allow": {
            "issuer_mismatch": True
        },

Information about the client. When you register your RP with Microsoft you will
in return get a client_id and client_secret::

        'client_id': '242424242424',
        'client_secret': 'ipipipippipipippi',
        "redirect_uris": ["{}/authz_cb/microsoft".format(BASEURL)],

Regarding the behaviour of the RP, Microsoft have chosen to only support the
response_type *id_token*. Microsoft have also chosen to return the authorization
response not in the fragment of the redirect URL which is the default but
instead using the response_mode *form_post*. *client_secret_post* is a
client authentication that Microsoft supports at the token enpoint::

        "behaviour": {
            "response_types": ["id_token"],
            "scope": ["openid"],
            "token_endpoint_auth_method": ['client_secret_post'],
            "response_mode": 'form_post'
        },

And lastly, which service the RP has access to. *ProviderInfoDiscovery* since
Microsoft supports dynamic provider info discovery. *Authorization* always must be
there. And in this case this is it. All the user info will be included in the
*id_token* that is returned in the authorization response::

        "services": {
            'ProviderInfoDiscovery':{},
            'Authorization': {}
        }


-------------------------
RP configuration - GitHub
-------------------------

As mentioned before GitHub runs an OAuth2 AS not an OP.
Still we can talk to it using this configuration::

    {
        "issuer": "https://github.com/login/oauth/authorize",
        'client_id': 'eeeeeeeee',
        'client_secret': 'aaaaaaaaaaaaa',
        "redirect_uris": ["{}/authz_cb/github".format(BASEURL)],
        "behaviour": {
            "response_types": ["code"],
            "scope": ["user", "public_repo"],
            "token_endpoint_auth_method": ['']
        },
        "provider_info": {
            "authorization_endpoint":
                "https://github.com/login/oauth/authorize",
            "token_endpoint":
                "https://github.com/login/oauth/access_token",
            "userinfo_endpoint":
                "https://api.github.com/user"
        },
        'services': {
            'Authorization': {},
            'AccessToken': {'response_body_type': 'urlencoded'},
            'UserInfo': {'default_authn_method': ''}
        }
    }

Part by part.
Like with Google and Microsoft, GitHub expects you to register your client in
advance. You register the redirect_uris and in return will get *client_id* and
*client_secret*::

        'client_id': 'eeeeeeeee',
        'client_secret': 'aaaaaaaaaaaaa',
        "redirect_uris": ["{}/authz_cb/github".format(BASEURL)],

Since GitHub doesn't support dynamic provder info discovery you have to enter
that information in the configuration::

        "issuer": "https://github.com/login/oauth/authorize",
        "provider_info": {
            "authorization_endpoint":
                "https://github.com/login/oauth/authorize",
            "token_endpoint":
                "https://github.com/login/oauth/access_token",
            "userinfo_endpoint":
                "https://api.github.com/user"
        },

Regarding the client behaviour the GitHub AS expects response_type *code*.
The number of scope values is rather large I've just chose 2 here.
No client authentication at the token endpoint is expected::

        "behaviour": {
            "response_types": ["code"],
            "scope": ["user", "public_repo"],
            "token_endpoint_auth_method": ['']
        },

And about services, *Authorization* as always, *AccessToken* to convert the
received *code* in the authorization response into an access token which later
can be used to access user info at the userinfo endpoint.
GitHub deviates from the standard in a number of way. First the Oauth2
standard doesn't mention anything like an userinfo endpoint, that is OIDC.
So GitHub has implemented something that is in between OAuth2 and OIDC.
What's more disturbing is that the access token response by default is not
encoded as a JSON document which the standard say but instead it's
urlencoded. Lucky for us, we can deal with both these things by configuration
rather then writing code.::

        'services': {
            'Authorization': {},
            'AccessToken': {'response_body_type': 'urlencoded'},
            'UserInfo': {'default_authn_method': ''}
        }

