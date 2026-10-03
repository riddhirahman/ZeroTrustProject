const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const projectRoot = path.join(__dirname, "..");
const envPath = path.join(projectRoot, ".env");
const examplePath = path.join(projectRoot, ".env.example");

const sourcePath = fs.existsSync(envPath) ? envPath : examplePath;
let envContents = fs.existsSync(sourcePath)
    ? fs.readFileSync(sourcePath, "utf8")
    : "";
const newSecret = crypto.randomBytes(32).toString("hex");

envContents = envContents.replace(/^\s*JWT_SECRET\s*=.*(?:\r?\n|$)/gm, "");

if (envContents && !envContents.endsWith("\n")) {
    envContents += "\n";
}

fs.writeFileSync(envPath, `${envContents}JWT_SECRET=${newSecret}\n`, {
    mode: 0o600
});

console.log("Generated a fresh local JWT secret.");
