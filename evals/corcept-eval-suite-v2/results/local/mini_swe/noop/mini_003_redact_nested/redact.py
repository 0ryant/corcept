SENSITIVE = {'secret', 'token', 'password', 'api_key'}

def redact(value):
    if isinstance(value, dict):
        return {k: ('<redacted>' if k in SENSITIVE else v) for k, v in value.items()}
    return value
