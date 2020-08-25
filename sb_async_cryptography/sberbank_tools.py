"""
Sberbank webhook params functions
"""

import codecs
from copy import copy
from itertools import chain

from sb_async_cryptography.signature import public_key_verify_signature


def params_get_checksum(params):
    return params.get('checksum')


def params_string_to_dict(params):
    # 1. split by &
    #    result: "key=value" items
    # 2. split "key=value" items by =
    #    result: [[key1, value], [key2, value2], ...]
    # 3. turn key-value pairs to dict
    #    result: {key1: value, key2: value2, ...}
    return {param.split('=')[0]: param.split('=')[1] for param in params.split('&')}


def params_get_message(params):
    _params = copy(params)
    # remove checksum params
    _params.pop('sign_alias', '')
    _params.pop('checksum', '')
    # 1. getting params in [["orderNumber", "1234-1234-1237"], ["status", "1"], ...] view
    # 2. sort inner lists by key
    # 3. unwind inner lists to outer list: ["orderNumber", "1234-1234-1237", "status", "1", ...]
    # 4. join items by ';': "orderNumber;1234-1234-1237;status;1";..."
    # 5. encode string to bytes
    message = ";".join(chain.from_iterable(sorted(_params.items())))
    return f'{message};'.encode()


def verify_signature(public_key, signature, params=None, raise_exception=False, **kwargs):
    if not params:
        params = {}
    params.update(kwargs)
    message = params_get_message(params)
    try:
        signature = codecs.decode(signature.lower(), 'hex')
    except Exception as exc:
        if raise_exception:
            raise exc
        return False
    return public_key_verify_signature(public_key, signature, message)
