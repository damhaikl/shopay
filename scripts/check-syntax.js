const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const ignoreDirs = new Set(["node_modules", ".git"]);
const files = [];

function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (ignoreDirs.has(entry.name)) continue;

    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      walk(fullPath);
    } else if (entry.isFile() && entry.name.endsWith(".js")) {
      files.push(fullPath);
    }
  }
}

walk(process.cwd());

if (files.length === 0) {
  console.error("No JavaScript files found.");
  process.exit(1);
}

for (const file of files) {
  const result = spawnSync(process.execPath, ["--check", file], {
    stdio: "inherit"
  });

  if (result.status !== 0) {
    process.exit(result.status);
  }
}

console.log(`Syntax check passed for ${files.length} JavaScript files.`);
