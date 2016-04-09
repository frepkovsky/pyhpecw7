"""Errors for pyhpecw7 library.
"""
from pyhpecw7.utils.xml.lib import remove_namespaces, get_text


class PYHPError(Exception):
    """General base class for all errors in the pyhpecw7 library.
    """
    pass


class FeatureError(PYHPError):
    """Base class for all errors related to features.
    """
    pass

##################################
#       NETCONF RPC ERRORS       #
##################################


class NCError(PYHPError):
    """Wrapper for ncclient RPC errors.
    """
    def __init__(self, rpc_error=None):
        super(NCError, self).__init__()
        self.tag = ''
        if rpc_error:
            self.rpc_error = rpc_error
            self.xml = remove_namespaces(rpc_error.xml)
            self.msg = rpc_error.message
            self.tag = rpc_error.tag
            self.bad_element = get_text(self.xml, 'error-info/bad-element') or ''

    def __repr__(self):
        rep = '{0}: NETCONF Protocol error ({1}).'.format(self.__class__.__name__, self.msg)

        if hasattr(self, 'rpc_error'):
            rep += ' Tag: {0}'.format(self.tag)
            if self.bad_element:
                rep += ' Bad Element: {0}'.format(self.bad_element)

        if self.tag == 'access-denied':
            rep += ' It is possible the device is'\
                + ' locked by another NETCONF connection.'

        if self.tag == 'invalid-value':
            rep += ' Message: {0}'.format(self.msg)

        return rep

    __str__ = __repr__


class LockConflictError(PYHPError):
    """When there's an attempt to lock, and NETCONF lock is not available.
    """
    def __repr__(self):
        return '{0}: Couldn\'t obtain NETCONF lock.'.format(
            self.__class__.__name__) +\
            ' Another connection holds the lock.'

    __str__ = __repr__


class UnlockConflictError(PYHPError):
    """When there's an attempt to unlock, and NETCONF lock is not available.
    """
    def __repr__(self):
        return '{0}: Couldn\'t unlock NETCONF lock.'.format(
            self.__class__.__name__) +\
            ' Another connection holds the lock.'

    __str__ = __repr__

##################################
#       TIMEOUT ERRORS         #
##################################


class NCTimeoutError(PYHPError):
    """When there is no response from the device within the timeout range.
    """
    def __repr__(self):
        return '{0}: The NETCONF RPC timed out.'.format(
            self.__class__.__name__)

    __str__ = __repr__


##################################
#       CONNECTION ERRORS        #
##################################


class ConnectionError(PYHPError):
    """When there is an error in the SSH/NETCONF connection.
    """
    def __init__(self, dev, msg=None):
        super(ConnectionError, self).__init__()
        self.dev = dev
        self.msg = msg
        self.host = dev.host
        self.port = dev.port

    def __repr__(self):
        rep = '{0}: host: {1}, port: {2}'.format(
            self.__class__.__name__, self.host, self.port)
        if self.msg:
            rep += ' msg: {0}'.format(self.msg)

        return rep

    __str__ = __repr__


class ConnectionAuthenticationError(ConnectionError):
    """When there's an authentication error.
    """
    pass


class ConnectionSSHError(ConnectionError):
    """When there's an SSH error.
    """
    pass


class ConnectionUknownHostError(ConnectionError):
    """When there's an uknown host error.
    """
    pass


class ConnectionClosedError(ConnectionError):
    """When there's a connection closed error.
    """
    pass