def load_settings(path):
    import json
    with open(path) as f:
        return json.load(f)


def merge_settings(a, b):
    out = dict(a)
    out.update(b)
    return out
