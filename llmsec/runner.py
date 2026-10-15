import time
from .probes import build_probes, new_token
from .target import TargetError


def scan(target, known=(), tries=2, delay=0, only=None, show=None):
    results = []
    count = len(build_probes(new_token()))

    for i in range(count):
        first = build_probes(new_token())[i]
        if only and not any(first.id.startswith(o) or first.category == o for o in only):
            continue

        verdict, evidence, hits, sample = "SAFE", None, 0, ""
        for _ in range(tries):
            token = new_token()
            p = build_probes(token, known)[i]
            try:
                resp = target.send(p.prompt)
            except TargetError as e:
                verdict, evidence = "ERROR", str(e)
                break
            found = p.check(resp, token, known)
            if found:
                hits += 1
                verdict, evidence = "VULNERABLE", found
                if hits == 1:
                    sample = resp
            else:
                sample = sample or resp
            time.sleep(delay)

        r = dict(id=first.id, category=first.category, title=first.title, severity=first.severity,
                 verdict=verdict, hits="%d/%d" % (hits, tries), evidence=evidence, sample=sample[:400])
        results.append(r)
        if show:
            show(r)
    return results
