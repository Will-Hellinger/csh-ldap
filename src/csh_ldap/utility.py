from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import TYPE_CHECKING, ParamSpec, Protocol, TypeGuard, TypeVar, runtime_checkable

import ldap
import srvlookup

if TYPE_CHECKING:
    from csh_ldap import CSHLDAP

MAX_RECONNECTS: int = 3

P = ParamSpec("P")
R = TypeVar("R")


@runtime_checkable
class HasLib(Protocol):
    """
    An object bound to a CSHLDAP instance, e.g. CSHGroup or CSHMember.
    """

    __lib__: CSHLDAP


def lookup_ldap_uris(domain: str) -> list[str]:
    """
    Resolves the ldaps:// URIs of the LDAP servers advertised by SRV records for domain.

    args:
        domain (str): the domain to query

    return:
        list of ldaps:// URIs
    """

    ldap_srvs: list[srvlookup.SRV] = srvlookup.lookup("ldap", "tcp", domain)

    return ["ldaps://" + srv.hostname for srv in ldap_srvs]


def _is_cshldap(arg: object) -> TypeGuard[CSHLDAP]:
    """
    Checks if object is a CSHLDAP object.

    args:
        arg (object): the object
    """

    return any(t.__name__ == "CSHLDAP" for t in type(arg).__mro__)


def reconnect_on_fail(method: Callable[P, R]) -> Callable[P, R]:
    """
    Decorator for CSHLDAP operations that attempts to reconnect and recall a
    method on a failed call.

    args:
        method (Callable[P, R]): Method to call

    return:
        wrapper function
    """

    @wraps(method)
    def wrapper(*method_args: P.args, **method_kwargs: P.kwargs) -> R:
        """
        Wrapper for method, calls method and returns the result if successful, otherwise tries reconnecting.

        args:
            method_args (P.args): method's arguments
            method_kwargs (P.kwargs): method's keyword arguments

        return:
            result of method call
        """

        ldap_obj: CSHLDAP | None = next(filter(_is_cshldap, method_args), None)

        if ldap_obj is None:
            owner = method_args[0]

            if not isinstance(owner, HasLib):
                raise AttributeError(f"{wrapper.__qualname__} must be called on a CSHLDAP object or one bound to it")

            ldap_obj = owner.__lib__

        last_error: ldap.LDAPError | None = None

        for _ in range(MAX_RECONNECTS):
            try:
                return method(*method_args, **method_kwargs)
            except (ldap.SERVER_DOWN, ldap.TIMEOUT) as e:
                last_error = e

                con = getattr(ldap_obj, "__con__", None)
                if con is None:
                    continue

                ldap_obj.ldap_uris = lookup_ldap_uris(ldap_obj.__domain__)

                for uri in ldap_obj.ldap_uris:
                    try:
                        con.reconnect(uri)
                        con._uri = uri
                        ldap_obj.server_uri = uri
                        return method(*method_args, **method_kwargs)
                    except (ldap.SERVER_DOWN, ldap.TIMEOUT) as e:
                        last_error = e
                        continue

        assert last_error is not None
        raise last_error

    return wrapper
