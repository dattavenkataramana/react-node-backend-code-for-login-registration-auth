 
const express = require("express");
const path = require("path");
const cors = require("cors");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const app = express();
app.use(express.json());
app.use(cors());
const dbPath = path.join(__dirname, "database.db");

let db = null;

const initializeDbAndServer = async () => {
    try {
        db = await open({ filename: dbPath, driver: sqlite3.Database });
        app.listen(3000, () => {
            console.log(`Server Running at http://localhost:3000`);
        });
    } catch (e) {
        console.log(`DB Error: ${e.message}`);
        process.exit(-1);
    }
};

initializeDbAndServer();

app.post("/register", async (req, res) => {
    const { username, password, email } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const searchQuery = `SELECT * FROM users WHERE username = ? OR email = ?`;
        const dbUser = await db.get(searchQuery, [username, email]);
        if (dbUser === undefined) {
            const insertUserData = `
                INSERT INTO users (username, password, email)
                VALUES (?, ?, ?)
            `;
            const dbResponse = await db.run(insertUserData, [username, hashedPassword, email]);
            const userId = dbResponse.lastID;
            res.status(200).json({ status: "success", message: `User registered successfully with ID: ${userId}` });
        } else {
            res.status(400).json({ status: "error", message: "Username or email already registered" });
        }
    } catch (e) {
        res.status(500).json({ status: "error", message: e.message });
    }
});

app.get("/data", async (req, res) => {
    const dataQuery = `SELECT * FROM users`;
    const dataResponse = await db.all(dataQuery);
    res.send(dataResponse);
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const searchQuery = `SELECT * FROM users WHERE email = ?`;
        const dbUser = await db.get(searchQuery, [email]);
        if (dbUser === undefined) {
            res.status(400).json({ status: "error", message: "Invalid User" });
        } else {
            const validPassword = await bcrypt.compare(password, dbUser.password);
            if (validPassword) {
                const payload = { email: email };
                const token = jwt.sign(payload, "JWT_SECRET");
                res.status(200).json({ status: "success", token: token });
            } else {
                res.status(400).json({ status: "error", message: "Invalid Password" });
            }
        }
    } catch (e) {
        res.status(500).json({ status: "error", message: e.message });
    }
});
