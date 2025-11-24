# -*- encoding: utf-8 -*-
'''
@Time     :   2025/11/19 17:51:56
@Author   :   QuYue
@File     :   utils.py
@Email    :   quyue1541@gmail.com
@Desc:    :   utils
'''

#%% AttrDict
class AttrDict(dict):
    """
    Dictionary that supports attribute-style access and
    recursively wraps nested dicts/lists into AttrDict.
    """
    def __init__(self, *args, **kwargs):
        super().__init__()
        self.update(*args, **kwargs)

    @classmethod
    def _wrap(cls, value):
        if isinstance(value, dict) and not isinstance(value, AttrDict):
            return cls(value)
        elif isinstance(value, list):
            return [cls._wrap(v) for v in value]
        else:
            return value

    def __setitem__(self, key, value):
        super().__setitem__(key, self._wrap(value))

    def update(self, *args, **kwargs):
        other = dict(*args, **kwargs)
        for k, v in other.items():
            self[k] = v

    def __getattr__(self, item):
        try:
            return self[item]
        except KeyError:
            raise AttributeError(item)

    def __setattr__(self, key, value):
        if key.startswith("_"):
            return super().__setattr__(key, value)
        self[key] = value

    def __delattr__(self, key):
        if key.startswith("_"):
            return super().__delattr__(key)
        try:
            del self[key]
        except KeyError:
            raise AttributeError(key)


#%% Proxy
def parse_proxy(proxy_str: str,
                default_port: int = 1080,
                default_type: str = "http") -> tuple[str, str, int]:
    """
    Parse proxy string and return (proxy_type, host, port).
    Supported formats:
        - "127.0.0.1:1080"
        - "http://127.0.0.1:1080"
        - "socks5://127.0.0.1:1080"
        - "socks4://127.0.0.1:1080"
        - "127.0.0.1"
        - "localhost"
    """
    proxy = proxy_str.strip()
    proxy_type = default_type.lower()

    # Check proxy type
    if "://" in proxy:
        proto, proxy = proxy.split("://", 1)
        proxy_type = proto.lower()

    # normalize acceptable type values
    if proxy_type not in ["http", "https", "socks", "socks4", "socks5"]:
        proxy_type = default_type
    # "socks" should be treated as "socks5"
    if proxy_type == "socks":
        proxy_type = "socks5"

    # Extract host and port
    if ":" in proxy:
        host, port = proxy.split(":", 1)
        port = int(port)
    else:
        host = proxy
        port = default_port

    return proxy_type, host, port

