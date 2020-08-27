# Sberbank signature verification using async cryptography

The code of keys generation and message signing and signature verification is universal, 
it is not only Sberbank-compatible. You can use it for your own purposes. 
However there is a `sberbank_tools` module that consist sberbank-specific functions.
 
The repo is open for pull requests. The author will be glad to hear some good feedback from you.
 
## Python version

Python version that has been used while coding is 3.8. Other versions has not been tested but they might work.

## Installation

```bash
pip install -i sberbank_async_cryptography
```

## Flask example

```python
import os
from dotenv import load_dotenv

from flask import request
from flask_restful import Resource
from sb_async_cryptography.sberbank_tools import verify_signature, params_get_checksum
from sb_async_cryptography.signature import public_key_import_from_x509_certificate_file as import_pub_key

load_dotenv()
SBERBANK_PUBLIC_KEY_FILE = os.getenv('SBERBANK_PUBLIC_KEY_FILE')
pub_key = import_pub_key(SBERBANK_PUBLIC_KEY_FILE)


class Notification(Resource):

    def get(self):
        """Status change notification from Sberbank"""
        params = request.args
        signature = params_get_checksum(params)
        if not verify_signature(pub_key, signature, params):
            return {"errors": "Signature verification failed."}, 400
        
        # some other code here
```

## FastAPI example

```python
import os
from dotenv import load_dotenv

from fastapi import Request
from sb_async_cryptography.sberbank_tools import verify_signature, params_get_checksum
from sb_async_cryptography.signature import public_key_import_from_x509_certificate_file as import_pub_key 
from starlette.responses import JSONResponse

load_dotenv()
SBERBANK_PUBLIC_KEY_FILE = os.getenv('SBERBANK_PUBLIC_KEY_FILE')
pub_key = import_pub_key(SBERBANK_PUBLIC_KEY_FILE)


async def notification(request: Request):
    """Status change notification from Sberbank"""
    params = dict(request.query_params)
    signature = params_get_checksum(params)
    if not verify_signature(pub_key, signature, params):
        return JSONResponse(status_code=400, content={"errors": "Signature verification failed."})
    
    # some other code here
```
