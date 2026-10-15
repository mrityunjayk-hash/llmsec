import json
import urllib.request
import urllib.error


class TargetError(Exception):
    pass


class Target:
    def __init__(self, url, template, path, headers=None, timeout=30):
        self.url = url
        self.template = template
        self.path = path
        self.headers = {"Content-Type": "application/json"}
        self.headers.update(headers or {})
        self.timeout = timeout

    def send(self, prompt):
        # strip the quotes json.dumps adds, template already has them
        body = self.template.replace("{{PROMPT}}", json.dumps(prompt)[1:-1])
        req = urllib.request.Request(self.url, body.encode(), self.headers)
        try:
            raw = urllib.request.urlopen(req, timeout=self.timeout).read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            raise TargetError("http %d" % e.code)
        except Exception as e:
            raise TargetError(str(e))

        try:
            data = json.loads(raw)
            for key in self.path.split("."):
                data = data[int(key)] if isinstance(data, list) else data[key]
        except (ValueError, KeyError, IndexError, TypeError):
            raise TargetError("couldn't find %r in response: %s" % (self.path, raw[:100]))
        return data if isinstance(data, str) else json.dumps(data)
