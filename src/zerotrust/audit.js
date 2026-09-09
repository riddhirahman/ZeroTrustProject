const fs = require("fs");
const path = require("path");

const logDirectory = path.join(__dirname, "../../logs");
const logFile = path.join(logDirectory, "access.log");

function auditLog({
    username,
    role,
    action,
    resource,
    decision,
    reason
}) {

    // Create logs directory if it doesn't exist
    if (!fs.existsSync(logDirectory)) {
        fs.mkdirSync(logDirectory, { recursive: true });
    }

    const entry = {
        timestamp: new Date().toISOString(),
        username,
        role,
        action,
        resource,
        decision,
        reason
    };

    fs.appendFileSync(
        logFile,
        JSON.stringify(entry) + "\n"
    );
}

module.exports = {
    auditLog
};