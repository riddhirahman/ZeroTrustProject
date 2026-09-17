const fs = require("fs");
const path = require("path");

const logDirectory = path.join(__dirname, "../../logs");
const logFile = path.join(logDirectory, "access.log");

function buildAuditEntry({
    user,
    role,
    action,
    resource,
    decision,
    reason
}) {
    return {
        timestamp: new Date().toISOString(),
        username: user,
        role,
        action,
        resource,
        decision,
        reason
    };
}

function auditLog(decision) {
    // Create logs directory if it doesn't exist
    if (!fs.existsSync(logDirectory)) {
        fs.mkdirSync(logDirectory, { recursive: true });
    }

    const entry = buildAuditEntry(decision);

    fs.appendFileSync(
        logFile,
        JSON.stringify(entry) + "\n"
    );
}

module.exports = {
    auditLog,
    buildAuditEntry
};
