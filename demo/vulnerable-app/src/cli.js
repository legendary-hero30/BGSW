"use strict";
const minimist = require("minimist");
const { greet } = require("./index");

const args = minimist(process.argv.slice(2), { string: ["name"], default: { name: "world" } });
console.log(greet(args.name));
