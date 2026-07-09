# CWE-502: Deserialization of Untrusted Data
# Untrusted bytes deserialized via pickle.loads and yaml.load (unsafe loader).
# Expected detecting family: sast
import pickle

import yaml


def load_session(blob):
    # VULNERABLE SINK: pickle.loads on attacker-controlled bytes -> RCE
    return pickle.loads(blob)


def load_config(text):
    # VULNERABLE SINK: yaml.load without SafeLoader allows object construction
    return yaml.load(text, Loader=yaml.Loader)


def load_config_default(text):
    # VULNERABLE SINK: legacy yaml.load default loader (unsafe)
    return yaml.load(text)


if __name__ == "__main__":
    print(load_config("a: 1"))
