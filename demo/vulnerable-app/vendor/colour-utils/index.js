"use strict";
module.exports = { hex: (r, g, b) => "#" + [r, g, b].map((n) => n.toString(16).padStart(2, "0")).join("") };
