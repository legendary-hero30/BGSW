"use strict";
const test = require("node:test");
const assert = require("node:assert");
const minimist = require("minimist");
const { greet, unique } = require("../src/index");

test("greet fills the template", () => {
  assert.strictEqual(greet("Ada"), "Hello, Ada!");
});

test("unique removes duplicates", () => {
  assert.deepStrictEqual(unique([1, 1, 2, 3, 3]), [1, 2, 3]);
});

test("minimist parses flags", () => {
  assert.deepStrictEqual(minimist(["--name", "x", "-v"]).name, "x");
});

test("server helpers", () => {
  const s = require("../src/server");
  assert.ok(s.render("Ada").includes("Ada"));
  assert.strictEqual(typeof s.token("ada"), "string");
  assert.deepStrictEqual(s.merge({ a: 1 }, { b: 2 }), { a: 1, b: 2 });
  assert.strictEqual(s.colour(255, 0, 0), "#ff0000");
});
