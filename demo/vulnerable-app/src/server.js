"use strict";
// Uses the other dependencies so they are real, reachable parts of the app.
const _ = require("lodash");
const ejs = require("ejs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const fetch = require("node-fetch");
const colours = require("colour-utils");

const SECRET = process.env.JWT_SECRET || "dev-only"; // demo value, not a real secret

function render(name) {
  return ejs.render("<h1>Hello <%= name %></h1>", { name });
}
function token(user) {
  return jwt.sign({ user }, SECRET, { expiresIn: "1h" });
}
function merge(a, b) {
  return _.merge({}, a, b);
}
async function ping(url) {
  const viaAxios = await axios.get(url);
  const viaFetch = await fetch(url);
  return [viaAxios.status, viaFetch.status];
}

module.exports = { render, token, merge, ping, colour: colours.hex };
