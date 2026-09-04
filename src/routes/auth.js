const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const router = express.Router();

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

router.post("/login", async (req, res) => {
    const { username, password } = req.body;

    const user = users.find(u => u.username === username);

    if (!user) {
        return res.status(401).json({
            message: "Invalid username or password"
        });
    }

    const passwordValid = await bcrypt.compare(password, user.password);

    if (!passwordValid) {
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