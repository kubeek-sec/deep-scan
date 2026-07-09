# CWE-78: OS Command Injection
# Untrusted input flows through a helper into Kernel#system.
# Expected detecting family: sast

def run_cmd(cmd)
  # VULNERABLE SINK: shell command from untrusted input
  system(cmd)
end

def handle(input)
  run_cmd("ls #{input}")
end
