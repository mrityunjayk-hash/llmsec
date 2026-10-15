import argparse
import sys

from .target import Target
from .runner import scan
from .report import write


def main(argv=None):
    ap = argparse.ArgumentParser(prog="llmsec", description="poke LLM apps for prompt injection, leaks and tool abuse")
    ap.add_argument("--url", required=True)
    ap.add_argument("--template", default='{"message": "{{PROMPT}}"}',
                    help="json body, {{PROMPT}} gets replaced (default %(default)s)")
    ap.add_argument("--path", default="reply", help="where the reply text is, e.g. choices.0.message.content")
    ap.add_argument("--header", action="append", default=[], help="'Name: value', can repeat")
    ap.add_argument("--known", action="append", default=[], help="fragment of the real system prompt/secret to look for in replies")
    ap.add_argument("--tries", type=int, default=2)
    ap.add_argument("--delay", type=float, default=0)
    ap.add_argument("--only", action="append", help="probe id prefix or category")
    ap.add_argument("--out", default="report")
    ap.add_argument("--authorized", action="store_true", help="you own this app or have permission to test it")
    a = ap.parse_args(argv)

    if not a.authorized:
        print("only run this on apps you own or have permission to test. pass --authorized to confirm.")
        return 2

    headers = {}
    for h in a.header:
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()

    def show(r):
        tag = {"VULNERABLE": "FAIL", "SAFE": "ok", "ERROR": "ERR"}[r["verdict"]]
        print("%-4s %-8s %-9s %s (%s)" % (tag, r["id"], r["severity"], r["title"], r["hits"]))

    results = scan(Target(a.url, a.template, a.path, headers), a.known, a.tries, a.delay, a.only, show)
    n = write(results, a.url, a.out)
    print("\n%d/%d probes worked, see %s.md" % (n, len(results), a.out))
    return 1 if n else 0


if __name__ == "__main__":
    sys.exit(main())
