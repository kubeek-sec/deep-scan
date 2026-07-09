"""Multi-language taint knowledge base: SOURCES, SINKS, SANITIZERS, REMEDIATION.

Deliberately small, explicit and auditable - a reviewer can read exactly what is
treated as dangerous (sink), as untrusted (source) and as neutralising
(sanitizer), per language family. The tables list names purely as *strings to
match* against parsed code; nothing here is ever imported or executed.

A "kind" groups sinks by vulnerability class so severity and remediation can be
specific. Severity is the inherent danger of the class *before* reachability /
sanitization is taken into account; the engine adjusts it from graph evidence.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..models import Severity


@dataclass(frozen=True)
class SinkSpec:
    kind: str
    cwe: str
    severity: Severity


# Vulnerability classes → (CWE, baseline severity, remediation).
KINDS: dict[str, tuple[str, Severity, str]] = {
    "command-injection": (
        "CWE-78", Severity.CRITICAL,
        "Avoid the shell: pass an argument list (shell=False / exec-array) and "
        "validate/allowlist the value; if a shell is unavoidable, quote each "
        "argument (shlex.quote / equivalent).",
    ),
    "code-injection": (
        "CWE-95", Severity.CRITICAL,
        "Never eval/exec untrusted input. Parse data with a safe parser "
        "(ast.literal_eval, JSON) or dispatch on an explicit allowlist.",
    ),
    "deserialization": (
        "CWE-502", Severity.HIGH,
        "Do not deserialize untrusted data with pickle/yaml.load/native "
        "deserializers. Use JSON or a schema-validated, type-safe format.",
    ),
    "sql-injection": (
        "CWE-89", Severity.HIGH,
        "Use parameterized queries (placeholders + a params list). Never build "
        "SQL by string concatenation or interpolation.",
    ),
    "path-traversal": (
        "CWE-22", Severity.HIGH,
        "Resolve the path and confirm it stays within an allowed base directory "
        "(realpath + prefix check); reject '..' and absolute paths.",
    ),
    "ssrf": (
        "CWE-918", Severity.HIGH,
        "Validate the URL against an allowlist of hosts/schemes; block private, "
        "loopback and link-local ranges; disable redirects to internal targets.",
    ),
    "xss": (
        "CWE-79", Severity.HIGH,
        "Never write untrusted data into HTML/DOM unescaped. Use textContent / "
        "auto-escaping templates; sanitize HTML with a vetted library.",
    ),
    "xxe": (
        "CWE-611", Severity.HIGH,
        "Disable external entity and DTD processing in the XML parser.",
    ),
    "ldap-injection": (
        "CWE-90", Severity.MEDIUM,
        "Escape LDAP special characters / use a parameterized filter API.",
    ),
    "template-injection": (
        "CWE-94", Severity.HIGH,
        "Never render untrusted input as a template. Pass it as data to a "
        "sandboxed, auto-escaping engine.",
    ),
    "open-redirect": (
        "CWE-601", Severity.MEDIUM,
        "Do not redirect to a user-supplied URL. Redirect only to a fixed "
        "allowlist of paths, or validate the target is same-origin/relative.",
    ),
}


# A sanitizer mapped to ALL_KINDS neutralises taint for every vuln class (e.g.
# casting to int/float, or a generically-named validate()/sanitize() helper a
# reviewer cannot attribute to one class). A sanitizer mapped to a *subset* only
# clears those classes, so an HTML-escaped value still trips a SQL-injection
# sink (mirrors Pysa's ``Sanitize[TaintSink[...]]``).
ALL_KINDS: frozenset[str] = frozenset(KINDS)


def spec(kind: str) -> SinkSpec:
    cwe, sev, _ = KINDS[kind]
    return SinkSpec(kind=kind, cwe=cwe, severity=sev)


def remediation(kind: str) -> str:
    return KINDS.get(kind, ("", Severity.MEDIUM, ""))[2]


# --------------------------------------------------------------------------- #
# Per-language-family tables. The key is a "family" (python, js, java, go,
# ruby, php, c, csharp). The treesitter scanner maps file extensions to a
# family; the Python AST engine uses the "python" family directly.
# --------------------------------------------------------------------------- #

# Calls whose return value / read introduces untrusted data.
SOURCES: dict[str, set[str]] = {
    "python": {
        "input", "os.getenv", "os.environ", "request.args.get", "request.form.get",
        "request.values.get", "request.get_json", "request.args",
        "request.form", "request.values", "request.data", "request.cookies",
        "request.json", "request.files", "request.headers", "request.GET", "request.POST",
        "self.rfile.read", "parse_qs", "sys.argv", "sys.stdin", "raw_input", "flask.request",
    },
    "js": {
        "req.query", "req.body", "req.params", "req.cookies", "req.headers",
        "process.argv", "process.env", "url.parse", "location.search",
        "location.hash", "document.location", "document.URL", "document.referrer",
        "window.name", "localStorage", "sessionStorage", "URLSearchParams",
    },
    "java": {
        "request.getParameter", "request.getParameterValues",
        "request.getHeader", "request.getQueryString", "request.getCookies",
        "getParameter", "getHeader", "System.getenv", "args",
    },
    "go": {
        "r.URL.Query", "r.FormValue", "r.PostFormValue", "r.Header.Get",
        "os.Args", "os.Getenv", "r.Body",
    },
    "ruby": {"params", "request.params", "ENV", "ARGV", "gets", "cookies"},
    "php": {"$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER", "file_get_contents"},
    "csharp": {
        "Request.Query", "Request.Form", "Request.QueryString", "Request.Params",
        "Request.Headers", "Console.ReadLine", "Environment.GetEnvironmentVariable",
    },
    "c": {"getenv", "scanf", "gets", "fgets", "read", "recv"},
    "rust": {"web::Query", "web::Form", "web::Path", "web::Json", "std::env::var", "std::env::args"},
}

# Substrings in an attribute/identifier path that mark a value as request-derived.
SOURCE_ATTRS: dict[str, tuple[str, ...]] = {
    "python": ("request.args", "request.form", "request.values", "query_params", "request.json"),
    "js": ("req.query", "req.body", "req.params", "req.cookies", "req.headers"),
    "java": ("getParameter", "getHeader"),
    "go": ("URL.Query", "FormValue", "Header.Get"),
    "ruby": ("params",),
    "php": ("$_GET", "$_POST", "$_REQUEST"),
    "csharp": ("Request.",),
    "c": (),
}

# Dangerous calls grouped by kind. Matched against the full dotted callee and
# its last segment (so both ``os.system`` and a bare ``system`` match).
SINKS: dict[str, dict[str, str]] = {
    "python": {
        "os.system": "command-injection", "os.popen": "command-injection",
        "subprocess.call": "command-injection", "subprocess.run": "command-injection",
        "subprocess.Popen": "command-injection", "subprocess.check_output": "command-injection",
        "subprocess.check_call": "command-injection", "commands.getoutput": "command-injection",
        "subprocess.getoutput": "command-injection", "subprocess.getstatusoutput": "command-injection",
        "asyncio.create_subprocess_shell": "command-injection",
        "asyncio.create_subprocess_exec": "command-injection",
        "os.popen2": "command-injection", "os.popen3": "command-injection",
        "os.popen4": "command-injection", "commands.getstatusoutput": "command-injection",
        "pty.spawn": "command-injection", "exec_command": "command-injection",
        "eval": "code-injection", "exec": "code-injection", "compile": "code-injection",
        "importlib.import_module": "code-injection", "__import__": "code-injection",
        "pickle.loads": "deserialization", "pickle.load": "deserialization",
        "cPickle.loads": "deserialization", "cPickle.load": "deserialization",
        "yaml.load": "deserialization", "yaml.unsafe_load": "deserialization",
        "marshal.loads": "deserialization", "marshal.load": "deserialization",
        "shelve.open": "deserialization", "pickle.Unpickler": "deserialization",
        "dill.loads": "deserialization", "dill.load": "deserialization",
        "dill.Unpickler": "deserialization",
        "jsonpickle.decode": "deserialization", "jsonpickle.loads": "deserialization",
        "pandas.read_pickle": "deserialization", "pd.read_pickle": "deserialization",
        "read_pickle": "deserialization",
        "torch.load": "deserialization", "torch.serialization.load": "deserialization",
        "logging.config.listen": "deserialization",
        "cursor.execute": "sql-injection", "execute": "sql-injection",
        "executemany": "sql-injection", "raw": "sql-injection", "RawSQL": "sql-injection",
        "open": "path-traversal", "send_file": "path-traversal", "io.open": "path-traversal",
        "shutil.copy": "path-traversal", "shutil.copyfile": "path-traversal",
        "shutil.move": "path-traversal", "os.remove": "path-traversal", "os.unlink": "path-traversal",
        "tarfile.open": "path-traversal", "zipfile.ZipFile": "path-traversal",
        "read_text": "path-traversal", "write_text": "path-traversal",
        "urlopen": "ssrf", "requests.get": "ssrf", "requests.post": "ssrf",
        "requests.put": "ssrf", "requests.delete": "ssrf", "requests.patch": "ssrf",
        "httpx.get": "ssrf", "httpx.post": "ssrf",
        "aiohttp.ClientSession.get": "ssrf", "aiohttp.ClientSession.post": "ssrf",
        "urllib.request.urlopen": "ssrf", "urllib.request.urlretrieve": "ssrf",
        "render_template_string": "template-injection",
        "jinja2.Template": "template-injection",
        "jinja2.Environment.from_string": "template-injection",
        "mako.template.Template": "template-injection",
        "etree.parse": "xxe", "etree.fromstring": "xxe",
        "xml.sax.parse": "xxe", "xml.sax.parseString": "xxe", "xml.sax.make_parser": "xxe",
        "xml.dom.minidom.parse": "xxe", "xml.dom.minidom.parseString": "xxe",
        "xml.dom.pulldom.parse": "xxe",
        "lxml.etree.parse": "xxe", "lxml.etree.fromstring": "xxe",
        "mark_safe": "xss", "Markup": "xss", "flask.Markup": "xss",
        "redirect": "open-redirect", "flask.redirect": "open-redirect",
        "werkzeug.utils.redirect": "open-redirect",
    },
    "js": {
        "child_process.exec": "command-injection", "child_process.execSync": "command-injection",
        "exec": "command-injection", "execSync": "command-injection",
        "child_process.spawn": "command-injection", "child_process.spawnSync": "command-injection",
        "child_process.execFile": "command-injection", "child_process.fork": "command-injection",
        "eval": "code-injection", "Function": "code-injection",
        "vm.runInContext": "code-injection", "vm.runInNewContext": "code-injection",
        "vm.runInThisContext": "code-injection",
        "query": "sql-injection", "raw": "sql-injection",
        "knex.raw": "sql-injection", "sequelize.query": "sql-injection",
        "fs.readFile": "path-traversal", "fs.readFileSync": "path-traversal",
        "fs.writeFile": "path-traversal", "fs.writeFileSync": "path-traversal",
        "fs.unlink": "path-traversal",
        "fs.createReadStream": "path-traversal", "res.sendFile": "path-traversal",
        "innerHTML": "xss", "outerHTML": "xss", "insertAdjacentHTML": "xss",
        "document.write": "xss", "dangerouslySetInnerHTML": "xss",
        "http.get": "ssrf", "http.request": "ssrf", "axios.get": "ssrf",
        "axios.post": "ssrf", "fetch": "ssrf", "got": "ssrf",
    },
    "java": {
        "Runtime.exec": "command-injection", "getRuntime.exec": "command-injection",
        "exec": "command-injection", "ProcessBuilder": "command-injection",
        "createStatement": "sql-injection", "executeQuery": "sql-injection",
        "executeUpdate": "sql-injection", "execute": "sql-injection",
        "createNativeQuery": "sql-injection",
        "ObjectInputStream": "deserialization", "readObject": "deserialization",
        "XMLDecoder": "deserialization", "XStream.fromXML": "deserialization",
        "ScriptEngine.eval": "code-injection", "GroovyShell.evaluate": "code-injection",
        "new File": "path-traversal", "Files.newInputStream": "path-traversal",
        "Files.readAllBytes": "path-traversal", "Files.write": "path-traversal",
        "DocumentBuilderFactory": "xxe", "SAXParserFactory": "xxe",
        "openConnection": "ssrf", "HttpURLConnection": "ssrf",
    },
    "go": {
        "exec.Command": "command-injection", "exec.CommandContext": "command-injection",
        "os/exec.Command": "command-injection", "syscall.Exec": "command-injection",
        "os.StartProcess": "command-injection",
        "db.Query": "sql-injection", "db.Exec": "sql-injection",
        "db.QueryRow": "sql-injection", "tx.Query": "sql-injection",
        "tx.Exec": "sql-injection", "stmt.Query": "sql-injection",
        "os.Open": "path-traversal", "os.OpenFile": "path-traversal",
        "os.Create": "path-traversal", "os.WriteFile": "path-traversal",
        "ioutil.ReadFile": "path-traversal", "ioutil.WriteFile": "path-traversal",
        "os.ReadFile": "path-traversal", "http.ServeFile": "path-traversal",
        "http.Get": "ssrf", "http.Post": "ssrf",
        "template.HTML": "xss",
    },
    "ruby": {
        "system": "command-injection", "exec": "command-injection", "spawn": "command-injection",
        "Open3.capture2": "command-injection", "Open3.capture3": "command-injection",
        "IO.popen": "command-injection", "Kernel.system": "command-injection",
        "eval": "code-injection", "instance_eval": "code-injection",
        "class_eval": "code-injection", "module_eval": "code-injection",
        "Marshal.load": "deserialization", "YAML.load": "deserialization",
        "execute": "sql-injection", "find_by_sql": "sql-injection", "exec_query": "sql-injection",
        "File.open": "path-traversal", "File.read": "path-traversal", "File.write": "path-traversal",
        "send_file": "path-traversal",
        "Net::HTTP.get": "ssrf", "open": "ssrf",
    },
    "php": {
        "system": "command-injection", "exec": "command-injection",
        "shell_exec": "command-injection", "passthru": "command-injection",
        "popen": "command-injection", "proc_open": "command-injection",
        "pcntl_exec": "command-injection",
        "eval": "code-injection", "assert": "code-injection",
        "create_function": "code-injection", "call_user_func": "code-injection",
        "call_user_func_array": "code-injection", "preg_replace": "code-injection",
        "unserialize": "deserialization",
        "mysqli_query": "sql-injection", "mysql_query": "sql-injection",
        "pg_query": "sql-injection", "query": "sql-injection",
        "fopen": "path-traversal", "file_get_contents": "path-traversal",
        "include": "path-traversal", "require": "path-traversal",
        "echo": "xss", "print": "xss",
    },
    "csharp": {
        "Process.Start": "command-injection", "ProcessStartInfo": "command-injection",
        "SqlCommand": "sql-injection", "ExecuteReader": "sql-injection",
        "ExecuteNonQuery": "sql-injection", "ExecuteScalar": "sql-injection",
        "BinaryFormatter": "deserialization", "Deserialize": "deserialization",
        "SoapFormatter": "deserialization", "LosFormatter": "deserialization",
        "Assembly.Load": "code-injection",
        "File.Open": "path-traversal", "File.ReadAllText": "path-traversal",
        "XmlDocument": "xxe",
        "WebClient": "ssrf", "HttpClient": "ssrf",
    },
    # Rust callees are normalized "::"→"." by the tree-sitter scanner, so keys
    # are dotted; common qualified prefixes are listed too.
    "rust": {
        "Command.new": "command-injection", "process.Command.new": "command-injection",
        "std.process.Command.new": "command-injection",
        "sqlx.query": "sql-injection", "diesel.sql_query": "sql-injection",
        "fs.read": "path-traversal", "fs.read_to_string": "path-traversal",
        "fs.write": "path-traversal", "std.fs.read_to_string": "path-traversal",
        "File.open": "path-traversal", "File.create": "path-traversal",
        "reqwest.get": "ssrf", "reqwest.blocking.get": "ssrf",
    },
    "c": {
        "system": "command-injection", "popen": "command-injection",
        "execve": "command-injection", "execl": "command-injection",
        "strcpy": "code-injection", "sprintf": "code-injection",
        "fopen": "path-traversal", "open": "path-traversal",
    },
}


# The *argument* of a sink that actually carries the danger, by 0-based position
# and/or keyword name. A tainted value in any *other* argument is not the vuln:
# ``requests.get(SAFE_URL, params=tainted)`` is not SSRF, ``cursor.execute(sql,
# tainted_params)`` is not SQL-injection. A sink absent here keeps the default
# "any tainted argument counts" (mirrors Pysa's per-parameter sink ports). Only
# the precise Python engine is constrained for now; other families keep the
# any-arg default.
SINK_ARGS: dict[str, dict[str, frozenset]] = {
    "python": {
        # SSRF lives in the URL, never the body/params/headers/timeout.
        "urlopen": frozenset({0, "url"}),
        "urllib.request.urlopen": frozenset({0, "url"}),
        "urllib.request.urlretrieve": frozenset({0, "url"}),
        "requests.get": frozenset({0, "url"}), "requests.post": frozenset({0, "url"}),
        "requests.put": frozenset({0, "url"}), "requests.delete": frozenset({0, "url"}),
        "requests.patch": frozenset({0, "url"}), "httpx.get": frozenset({0, "url"}),
        "httpx.post": frozenset({0, "url"}),
        # The command/argv, not cwd/env/timeout.
        "os.system": frozenset({0}), "os.popen": frozenset({0}),
        "subprocess.call": frozenset({0, "args"}), "subprocess.run": frozenset({0, "args"}),
        "subprocess.Popen": frozenset({0, "args"}),
        "subprocess.check_output": frozenset({0, "args"}),
        "subprocess.check_call": frozenset({0, "args"}),
        # The SQL text, not the bound parameters.
        "cursor.execute": frozenset({0, "sql", "query", "statement"}),
        "execute": frozenset({0, "sql", "query", "statement"}),
        "executemany": frozenset({0, "sql", "query", "statement"}),
        # The path, not the mode/encoding.
        "open": frozenset({0, "file", "name"}), "io.open": frozenset({0, "file"}),
        "send_file": frozenset({0, "filename_or_fp", "path"}),
    },
}


# Calls that neutralise taint, mapped to the vuln *kinds* they actually clear.
# Membership (``name in SANITIZERS[fam]``) still works because iterating/`in` a
# dict tests its keys, so existing call sites are unchanged; only the kind-aware
# logic reads the values. Python (the precise engine) is kind-specific; the other
# families map every sanitizer to ALL_KINDS, preserving their prior all-or-
# nothing behaviour exactly (kind-specificity can be tightened per family later).
_C = "command-injection"
SANITIZERS: dict[str, dict[str, frozenset[str]]] = {
    "python": {
        "shlex.quote": frozenset({_C}), "shlex.split": frozenset({_C}),
        "pipes.quote": frozenset({_C}),
        "html.escape": frozenset({"xss"}), "markupsafe.escape": frozenset({"xss"}),
        "escape": frozenset({"xss"}),
        "os.path.realpath": frozenset({"path-traversal"}),
        "os.path.abspath": frozenset({"path-traversal"}),
        "os.path.basename": frozenset({"path-traversal"}),
        "os.path.normpath": frozenset({"path-traversal"}),
        "secure_filename": frozenset({"path-traversal"}),
        "int": ALL_KINDS, "float": ALL_KINDS, "bool": ALL_KINDS,
        "quote": frozenset({"ssrf", "xss"}),
        "urllib.parse.quote": frozenset({"ssrf", "xss"}),
        "re.escape": frozenset({"ldap-injection", "xss"}),
        "is_safe_url": frozenset({"ssrf", "open-redirect"}),
        # generically-named validators - reviewer cannot attribute one class.
        "parameterize": ALL_KINDS, "sanitize": ALL_KINDS, "validate": ALL_KINDS,
        "allowlist": ALL_KINDS,
        "yaml.safe_load": frozenset({"deserialization"}),
        "ast.literal_eval": frozenset({"deserialization", "code-injection"}),
    },
    "js": dict.fromkeys((
        "encodeURIComponent", "encodeURI", "escape", "DOMPurify.sanitize",
        "sanitizeHtml", "validator.escape", "parseInt", "parseFloat",
        "path.basename", "path.normalize", "shellEscape",
    ), ALL_KINDS),
    "java": dict.fromkeys((
        "ESAPI.encoder", "encodeForHTML", "StringEscapeUtils.escapeHtml4",
        "Integer.parseInt", "getCanonicalPath", "Pattern.quote",
    ), ALL_KINDS),
    "go": dict.fromkeys((
        "html.EscapeString", "template.HTMLEscapeString", "url.QueryEscape",
        "filepath.Clean", "filepath.Base", "strconv.Atoi",
    ), ALL_KINDS),
    "ruby": dict.fromkeys((
        "Shellwords.escape", "CGI.escape", "CGI.escapeHTML", "ERB::Util.html_escape",
        "File.basename", "Integer", "sanitize",
    ), ALL_KINDS),
    "php": dict.fromkeys((
        "escapeshellarg", "escapeshellcmd", "htmlspecialchars", "htmlentities",
        "intval", "basename", "realpath", "mysqli_real_escape_string",
        "filter_var",
    ), ALL_KINDS),
    "csharp": dict.fromkeys((
        "HttpUtility.HtmlEncode", "Uri.EscapeDataString", "Path.GetFileName",
        "int.Parse", "Regex.Escape",
    ), ALL_KINDS),
    "c": dict.fromkeys(("snprintf", "strncpy", "realpath"), ALL_KINDS),
    "rust": dict.fromkeys(("parse", "shell_escape", "PathBuf::from"), ALL_KINDS),
}


# Map a source-file extension to a knowledge-base family.
EXT_TO_FAMILY: dict[str, str] = {
    ".py": "python", ".pyw": "python",
    ".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js",
    ".ts": "js", ".tsx": "js", ".vue": "js", ".svelte": "js",
    ".java": "java", ".kt": "java", ".kts": "java", ".scala": "java", ".groovy": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".rs": "rust",
    ".c": "c", ".h": "c", ".cpp": "c", ".cc": "c", ".cxx": "c", ".hpp": "c",
}


def family_for_ext(ext: str) -> str | None:
    return EXT_TO_FAMILY.get(ext.lower())
