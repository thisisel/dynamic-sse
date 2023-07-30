def str_to_bytes(*args):
    def checker(func):
        def wrapper(**kwargs):
            for a in args:
                if val := kwargs.get(a):
                    if type(val) is str:
                        val = val.encode()
                        kwargs[a] = val
            func(**kwargs)
        return wrapper
    return checker
