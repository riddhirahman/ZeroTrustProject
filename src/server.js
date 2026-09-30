require("dotenv").config();

const express = require("express");
const helmet = require("helmet");

const authRoutes = require("./routes/auth");
const protectedRoutes = require("./routes/protected");
const securityEventsRoutes = require("./routes/security-events");

const app = express();

// Disable Express framework fingerprinting
app.disable("x-powered-by");

// Add security-related HTTP headers
app.use(helmet());

app.use(express.json());

app.use("/auth", authRoutes);
app.use("/api", protectedRoutes);
app.use("/api", securityEventsRoutes);

app.get("/", (req, res) => {
    res.json({
        message: "Zero Trust Security API",
        status: "running"
    });
});

// Centralized error-handling middleware
app.use((err, req, res, next) => {
    // Log detailed error information server-side only
    console.error("[Server Error]", err);

    // Handle malformed JSON
    if (
        err instanceof SyntaxError &&
        err.status === 400 &&
        err.type === "entity.parse.failed"
    ) {
        return res.status(400).json({
            error: "Bad request"
        });
    }

    // Handle other unexpected errors
    return res.status(500).json({
        error: "Internal server error"
    });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});