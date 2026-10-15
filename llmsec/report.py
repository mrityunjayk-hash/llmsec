import json
from datetime import datetime

RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def write(results, url, prefix):
    bad = [r for r in results if r["verdict"] == "VULNERABLE"]
    bad.sort(key=lambda r: RANK[r["severity"]])
    when = datetime.now().strftime("%Y-%m-%d %H:%M")

    with open(prefix + ".json", "w") as f:
        json.dump({"target": url, "time": when, "results": results}, f, indent=2)

    md = ["# llmsec report", "", "target: %s" % url, "time: %s" % when,
          "%d of %d probes worked" % (len(bad), len(results)), ""]
    for r in bad:
        md += ["## [%s] %s %s" % (r["severity"], r["id"], r["title"]),
               "%s, hit %s" % (r["evidence"], r["hits"]), "", "```", r["sample"], "```", ""]
    for r in results:
        if r["verdict"] == "ERROR":
            md.append("error on %s: %s" % (r["id"], r["evidence"]))
    with open(prefix + ".md", "w") as f:
        f.write("\n".join(md) + "\n")
    return len(bad)
