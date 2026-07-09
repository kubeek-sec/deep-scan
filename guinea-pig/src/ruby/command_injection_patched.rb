# CWE-78 (patched): argument escaped for the shell via Shellwords.
# The taint engine must NOT flag this: the tainted value passes through a
# sanitizer (Shellwords.escape) before reaching system.
require "shellwords"

def run_cmd(cmd)
  # SAFE: escape the argument before it reaches the shell
  safe = Shellwords.escape(cmd)
  system("ls #{safe}")
end

def handle(input)
  run_cmd(input)
end
