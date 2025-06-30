// JavaScript test file with vulnerabilities

const express = require('express');
const app = express();

// XSS vulnerability
app.get('/search', (req, res) => {
    const query = req.query.q;
    // VULNERABLE: Direct HTML rendering without escaping
    res.send(`<h1>Search results for: ${query}</h1>`);
});

// SQL Injection 
app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    // VULNERABLE: Direct string concatenation
    db.query(`SELECT * FROM users WHERE id = ${userId}`, (err, results) => {
        res.json(results);
    });
});

// Hardcoded secrets
const API_SECRET = "super-secret-key-123";
const JWT_SECRET = "jwt-secret-key";

// Path traversal
app.get('/file', (req, res) => {
    const filename = req.query.name;
    // VULNERABLE: No path validation
    res.sendFile(`/uploads/${filename}`);
});

// Insecure randomness
function generateToken() {
    // VULNERABLE: Using Math.random() for security
    return Math.random().toString(36).substring(7);
}