const express = require("express");
const fs = require("fs");
const path = require("path");
const pep = require("../middleware/pep");

const router = express.Router();

const securityEventFile = path.join(
    __dirname,
    "../../logs/security-events.log"
);

router.get("/security/events", pep, (req, res) => {

    if (!fs.existsSync(securityEventFile)) {
        return res.json({
            events: []
        });
    }

    const events = fs.readFileSync(
        securityEventFile,
        "utf8"
    )
    .split("\n")
    .filter(line => line.trim() !== "")
    .map(line => JSON.parse(line));

    return res.json({
        events
    });
});

module.exports = router;