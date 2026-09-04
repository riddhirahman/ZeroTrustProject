require("dotenv").config();

const express = require("express");
const authRoutes = require("./routes/auth");
const protectedRoutes = require("./routes/protected");

const app = express();

app.use(express.json());
app.use("/auth", authRoutes);
app.use("/api", protectedRoutes);

app.get("/", (req, res) => {
    res.json({
        message: "Zero Trust Security API",
        status: "running"
    });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});