"""A database interface for storing state information."""
import json

from oidcmsg.impexp import ImpExp
from oidcmsg.message import Message
from oidcmsg.message import SINGLE_OPTIONAL_JSON
from oidcmsg.message import SINGLE_REQUIRED_STRING
from oidcmsg.oidc import verified_claim_name

from oidcrp.util import rndstr


class State(Message):
    """A structure to keep information about previous events."""
    c_param = {
        'iss': SINGLE_REQUIRED_STRING,
        'auth_request': SINGLE_OPTIONAL_JSON,
        'auth_response': SINGLE_OPTIONAL_JSON,
        'token_response': SINGLE_OPTIONAL_JSON,
        'refresh_token_request': SINGLE_OPTIONAL_JSON,
        'refresh_token_response': SINGLE_OPTIONAL_JSON,
        'user_info': SINGLE_OPTIONAL_JSON
    }


KEY_PATTERN = {
    'nonce': '__{}__',
    'logout state': '::{}::',
    'session id': '..{}..',
    'subject id': '=={}=='
}


class InMemoryStateDataBase:
    """The simplest possible implementation of the state database."""

    def __init__(self):
        self._db = {}

    def set(self, key, value):
        """Assign a value to a key."""
        self._db[key] = value

    def get(self, key):
        """Return the value bound to a key."""
        try:
            return self._db[key]
        except KeyError:
            return None

    def delete(self, key):
        """Delete a key and its value."""
        try:
            del self._db[key]
        except KeyError:
            pass

    def __setitem__(self, key, value):
        """Assign a value to a key."""
        self._db[key] = value

    def __getitem__(self, key):
        """Return the value bound to a key."""
        try:
            return self._db[key]
        except KeyError:
            return None

    def __delitem__(self, key):
        """Delete a key and its value."""
        try:
            del self._db[key]
        except KeyError:
            pass


class StateInterface(ImpExp):
    """A more powerful interface to a state DB."""

    parameter = {
        "_db": None
    }

    def __init__(self):
        ImpExp.__init__(self)
        self._db = {}

    def get_state(self, key):
        """
        Get the state connected to a given key.

        :param key: Key into the state database
        :return: A :py:class:´oidcrp.state_interface.State` instance
        """
        _data = self._db.get(key)
        if not _data:
            raise KeyError(key)

        return State().from_json(_data)

    def store_item(self, item, item_type, key):
        """
        Store a service response.

        :param item: The item as a :py:class:`oidcmsg.message.Message`
            subclass instance or a JSON document.
        :param item_type: The type of request or response
        :param key: The key under which the information should be stored in
            the state database
        """
        try:
            _state = self.get_state(key)
        except KeyError:
            _state = State()

        try:
            _state[item_type] = item.to_json()
        except AttributeError:
            _state[item_type] = item

        self._db[key] = _state.to_json()

    def get_iss(self, key):
        """
        Get the Issuer ID

        :param key: Key to the information in the state database
        :return: The issuer ID
        """
        _state = self.get_state(key)
        if not _state:
            raise KeyError(key)
        return _state['iss']

    def get_item(self, item_cls, item_type, key):
        """
        Get a piece of information (a request or a response) from the state
        database.

        :param item_cls: The :py:class:`oidcmsg.message.Message` subclass
            that described the item.
        :param item_type: Which request/response that is wanted
        :param key: The key to the information in the state database
        :return: A :py:class:`oidcmsg.message.Message` instance
        """
        _state = self.get_state(key)
        try:
            return item_cls(**_state[item_type])
        except TypeError:
            return item_cls().from_json(_state[item_type])

    def extend_request_args(self, args, item_cls, item_type, key,
                            parameters, orig=False):
        """
        Add a set of parameters and their value to a set of request arguments.

        :param args: A dictionary
        :param item_cls: The :py:class:`oidcmsg.message.Message` subclass
            that describes the item
        :param item_type: The type of item, this is one of the parameter
            names in the :py:class:`oidcrp.state_interface.State` class.
        :param key: The key to the information in the database
        :param parameters: A list of parameters who's values this method
            will return.
        :param orig: Where the value of a claim is a signed JWT return
            that.
        :return: A dictionary with keys from the list of parameters and
            values being the values of those parameters in the item.
            If the parameter does not a appear in the item it will not appear
            in the returned dictionary.
        """
        try:
            item = self.get_item(item_cls, item_type, key)
        except KeyError:
            pass
        else:
            for parameter in parameters:
                if orig:
                    try:
                        args[parameter] = item[parameter]
                    except KeyError:
                        pass
                else:
                    try:
                        args[parameter] = item[verified_claim_name(parameter)]
                    except KeyError:
                        try:
                            args[parameter] = item[parameter]
                        except KeyError:
                            pass

        return args

    def multiple_extend_request_args(self, args, key, parameters, item_types,
                                     orig=False):
        """
        Go through a set of items (by their type) and add the attribute-value
        that match the list of parameters to the arguments
        If the same parameter occurs in 2 different items then the value in
        the later one will be the one used.

        :param args: Initial set of arguments
        :param key: Key to the State information in the state database
        :param parameters: A list of parameters that we're looking for
        :param item_types: A list of item_type specifying which items we
            are interested in.
        :param orig: Where the value of a claim is a signed JWT return
            that.
        :return: A possibly augmented set of arguments.
        """
        _state = self.get_state(key)

        for typ in item_types:
            try:
                _item = Message(**_state[typ])
            except KeyError:
                continue

            for parameter in parameters:
                if orig:
                    try:
                        args[parameter] = _item[parameter]
                    except KeyError:
                        pass
                else:
                    try:
                        args[parameter] = _item[verified_claim_name(parameter)]
                    except KeyError:
                        try:
                            args[parameter] = _item[parameter]
                        except KeyError:
                            pass

        return args

    def store_x2state(self, value, state, xtyp):
        """
        Store the connection between some value (x) and a state value.
        This allows us later in the game to find the state if we have x.

        :param value: The value
        :param state: The state value
        :param xtyp: The type of value x is (e.g. nonce, ...)
        """
        self._db[KEY_PATTERN[xtyp].format(value)] = state
        try:
            _val = self._db.get("ref{}ref".format(state))
        except KeyError:
            _val = None

        if _val is None:
            refs = {xtyp: value}
        else:
            refs = json.loads(_val)
            refs[xtyp] = value
        self._db["ref{}ref".format(state)] = json.dumps(refs)

    def get_state_by_x(self, value, xtyp):
        """
        Find the state value by providing the x value.
        Will raise an exception if the x value is absent from the state
        data base.

        :param value: The value
        :return: The state value
        """
        _state = self._db.get(KEY_PATTERN[xtyp].format(value))
        if _state:
            return _state

        raise KeyError('Unknown {}: "{}"'.format(xtyp, value))

    def store_nonce2state(self, nonce, state):
        """
        Store the connection between a nonce value and a state value.
        This allows us later in the game to find the state if we have the nonce.

        :param nonce: The nonce value
        :param state: The state value
        """
        self.store_x2state(nonce, state, 'nonce')

    def get_state_by_nonce(self, nonce):
        """
        Find the state value by providing the nonce value.
        Will raise an exception if the nonce value is absent from the state
        data base.

        :param nonce: The nonce value
        :return: The state value
        """
        return self.get_state_by_x(nonce, 'nonce')

    def store_logout_state2state(self, logout_state, state):
        """
        Store the connection between a logout state value and a state value.
        This allows us later in the game to find the state if we have the
        logout state value.

        :param logout_state: The logout state value
        :param state: The state value
        """
        self.store_x2state(logout_state, state, 'logout state')

    def get_state_by_logout_state(self, logout_state):
        """
        Find the state value by providing the logout state value.
        Will raise an exception if the logout state value is absent from the
        state data base.

        :param logout_state: The logout state value
        :return: The state value
        """
        return self.get_state_by_x(logout_state, 'logout state')

    def store_sid2state(self, sid, state):
        """
        Store the connection between a session id (sid) value and a state value.
        This allows us later in the game to find the state if we have the
        sid value.

        :param sid: The session ID value
        :param state: The state value
        """
        self.store_x2state(sid, state, 'session id')

    def get_state_by_sid(self, sid):
        """
        Find the state value by providing the logout state value.
        Will raise an exception if the logout state value is absent from the
        state data base.

        :param sid: The session ID value
        :return: The state value
        """
        return self.get_state_by_x(sid, 'session id')

    def store_sub2state(self, sub, state):
        """
        Store the connection between a subject id (sub) value and a state value.
        This allows us later in the game to find the state if we have the
        sub value.

        :param sub: The Subject ID value
        :param state: The state value
        """
        self.store_x2state(sub, state, 'subject id')

    def get_state_by_sub(self, sub):
        """
        Find the state value by providing the subject id value.
        Will raise an exception if the subject id value is absent from the
        state data base.

        :param sub: The Subject ID value
        :return: The state value
        """
        return self.get_state_by_x(sub, 'subject id')

    def create_state(self, iss, key=''):
        """
        Create a State and assign some value to it.

        :param iss: The issuer
        :param key: A key to use to access the state
        """
        if not key:
            key = rndstr(32)
        else:
            if key.startswith('__') and key.endswith('__'):
                raise ValueError(
                    'Invalid format. Leading and trailing "__" not allowed')

        _state = State(iss=iss)
        self._db[key] = _state.to_json()
        return key

    def remove_state(self, state):
        """
        Remove a state.

        :param state: Key to the state
        """
        del self._db[state]
        refs = json.loads(self._db_db.get("ref{}ref".format(state)))
        if refs:
            for xtyp, _val in refs.items():
                del self._db[KEY_PATTERN[xtyp].format(_val)]
