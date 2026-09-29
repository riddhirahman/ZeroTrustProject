const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");

const router = express.Router();

const DUMMY_PASSWORD_HASH =
    "$2b$10$S283OTgCJMQzzEtKu5pmPO7b4z3gaZNgCB.pu/FAn77V3a/UOga4q"; // bcrypt hash for "dummyPassword"

//rate limiter for login route to prevent brute force attacks (pre PEP) #Vulnerability #3
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: {
        decision: "RATE_LIMITED",
        reason: "Too many login attempts. Please try again later."
    }
});

// Temporary users for development.
// replace this with MongoDB later.
const users = [
    {
        id: 1,
        username: "Riddhi",
        password: bcrypt.hashSync("user123", 10),
        role: "USER"
    },
    {
        id: 2,
        username: "admin",
        password: bcrypt.hashSync("admin123", 10),
        role: "ADMIN"
    }
];

router.post("/login", loginLimiter, async (req, res) => {
    const { username, password } = req.body || {};

    if (!username || !password) {
        return res.status(400).json({
            message: "Username and password are required"
        });
    }

const user = users.find(u => u.username === username);

// Always perform bcrypt comparison. VULNERABILITY #2
// This prevents username enumeration through timing differences.

    const passwordHash = user
        ? user.password
        : DUMMY_PASSWORD_HASH;

    const passwordMatch = await bcrypt.compare(
        password,
        passwordHash
    );

    if (!user || !passwordMatch) {
        return res.status(401).json({
            message: "Invalid username or password"
        });
    }

    const token = jwt.sign(
        {
            userId: user.id,
            username: user.username,
            role: user.role
        },
        process.env.JWT_SECRET,
        {
            expiresIn: "1h"
        }
    );

    res.json({
        message: "Login successful",
        token
    });
});

module.exports = router;