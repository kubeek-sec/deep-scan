// CWE-94, CWE-95: Code Injection / Eval Injection
// User-controlled input is passed straight into eval() and Function().
// Expected detecting family: sast

function calculate(req, res) {
  // VULNERABLE SINK: eval of request input -> arbitrary code execution
  const result = eval(req.query.expr);
  res.send(String(result));
}

function runRule(userRule) {
  // VULNERABLE SINK: Function constructor builds code from user input
  const fn = new Function("ctx", "return " + userRule);
  return fn({});
}

module.exports = { calculate, runRule };
