class FastAPIAuthOIDCException(Exception):
    pass


class InvalidCredentialsException(FastAPIAuthOIDCException):
    pass



class UnauthenticatedException(FastAPIAuthOIDCException):
    pass
