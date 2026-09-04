const express = require("express");
const pep = require("../middleware/pep");

const router = express.Router();

router.get("/profile", pep, (req, res) => {
    res.json({
        message: "Access granted to protected profile",
        user: req.user
    });
});

router.post("/profile", pep, (req, res) => {

    res.json({
        message: "POST access granted to protected profile",
        user: req.user
    });

});

router.get("/admin", pep, (req, res) => {
    res.json({
        message: "Access granted to admin resource",
        user: req.user
    });
});

module.exports = router;