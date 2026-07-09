// CWE-1321: Improperly Controlled Modification of Object Prototype (Prototype Pollution)
// A recursive merge copies keys (incl. __proto__) from untrusted input.
// Expected detecting family: sast

function merge(target, source) {
  for (const key in source) {
    // VULNERABLE SINK: no guard on __proto__ / constructor / prototype keys
    if (typeof source[key] === "object" && source[key] !== null) {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

function applyConfig(userConfig) {
  return merge({}, userConfig);
}

module.exports = { merge, applyConfig };
