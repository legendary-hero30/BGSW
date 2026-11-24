"use strict";
const _ = require("underscore");

// Renders a greeting from a template string. Uses a runtime dependency (underscore).
function greet(name, template = "Hello, <%= who %>!") {
  return _.template(template)({ who: name });
}

function unique(list) {
  return _.uniq(list);
}

module.exports = { greet, unique };
