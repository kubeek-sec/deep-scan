# CWE-918: Server-Side Request Forgery (SSRF)
# A user-supplied URL is fetched server-side with no allowlist or validation.
# Expected detecting family: sast
from urllib.request import urlopen


def fetch(url):
    # VULNERABLE SINK: urlopen on attacker-controlled URL, can hit internal hosts
    with urlopen(url) as resp:
        return resp.read()


def fetch_metadata(host):
    # VULNERABLE SINK: builds URL from user input, reachable cloud metadata
    return urlopen("http://" + host + "/latest/meta-data/").read()


if __name__ == "__main__":
    import sys
    print(fetch(sys.argv[1] if len(sys.argv) > 1 else "https://kubeek.com/info/"))
