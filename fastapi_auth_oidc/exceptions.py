class FastAPIAuthOIDCException(Exception):
    pass


class UnauthenticatedException(FastAPIAuthOIDCException):
    pass
