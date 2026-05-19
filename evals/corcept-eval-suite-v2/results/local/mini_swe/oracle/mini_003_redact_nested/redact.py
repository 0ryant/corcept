SENSITIVE = {'secret', 'token', 'password', 'api_key'}

def redact(value):
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if str(k).lower() in SENSITIVE:
                out[k] = '<redacted>'
            else:
                out[k] = redact(v)
        return out
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value
