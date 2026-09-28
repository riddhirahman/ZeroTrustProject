const express = require("express");
const fs = require("fs");
const path = require("path");
const pep = require("../middleware/pep");

const router = express.Router();

const securityEventFile = path.join(
    __dirname,
    "../../logs/security-events.log"
);

function readSecurityEvents() {
    if (!fs.existsSync(securityEventFile)) {
        return [];
    }

    return fs.readFileSync(
        securityEventFile,
        "utf8"
    )
    .split("\n")
    .filter(line => line.trim() !== "")
    .map(line => JSON.parse(line));
}

router.get("/security/events", pep, (req, res) => {
    const events = readSecurityEvents();

    return res.json({
        events
    });
});

router.get("/security/stats", pep, (req, res) => {
    const events = readSecurityEvents();

    const repeatedDenials = events.filter(
        event => event.type === "REPEATED_DENIAL"
    ).length;

    const rateLimitEscalations = events.filter(
        event => event.type === "RATE_LIMIT_ESCALATED"
    ).length;

    return res.json({
        totalEvents: events.length,
        repeatedDenials,
        rateLimitEscalations
    });
});

module.exports = router;