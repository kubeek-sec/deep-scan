// CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)
// User input is concatenated into an HTML response without escaping.
// Expected detecting family: sast

function greet(req, res) {
  const name = req.query.name;
  // VULNERABLE SINK: reflected user input written into HTML response
  res.send("<h1>Hello " + name + "</h1>");
}

function profile(req, res) {
  // VULNERABLE SINK: template literal injects unescaped input into markup
  res.send(`<div class="bio">${req.body.bio}</div>`);
}

module.exports = { greet, profile };
