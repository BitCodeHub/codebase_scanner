// Sample vulnerable JavaScript code for testing the security scanner
// This file intentionally contains security vulnerabilities for demonstration

const express = require('express');
const mysql = require('mysql');
const crypto = require('crypto');
const fs = require('fs');
const { exec } = require('child_process');

const app = express();
app.use(express.json());

// SQL Injection vulnerability
app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    // VULNERABLE: Direct concatenation in SQL query
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    connection.query(query, (err, results) => {
        res.json(results);
    });
});

// Command Injection vulnerability
app.post('/execute', (req, res) => {
    const command = req.body.command;
    // VULNERABLE: Direct execution of user input
    exec(command, (error, stdout, stderr) => {
        res.send(stdout);
    });
});

// Insecure Random Token Generation
function generateToken() {
    // VULNERABLE: Using Math.random() for security tokens
    return Math.random().toString(36).substring(2);
}

// Hardcoded Secrets
const API_SECRET = 'super-secret-key-123'; // VULNERABLE: Hardcoded secret
const DB_PASSWORD = 'password123'; // VULNERABLE: Hardcoded password

// Path Traversal vulnerability
app.get('/download', (req, res) => {
    const filename = req.query.file;
    // VULNERABLE: No path validation
    res.sendFile(filename);
});

// XSS vulnerability
app.get('/search', (req, res) => {
    const query = req.query.q;
    // VULNERABLE: Reflecting user input without sanitization
    res.send(`<h1>Search results for: ${query}</h1>`);
});

// Weak Cryptography
function hashPassword(password) {
    // VULNERABLE: Using MD5 for passwords
    return crypto.createHash('md5').update(password).digest('hex');
}

// Prototype Pollution vulnerability
app.post('/merge', (req, res) => {
    const obj = {};
    const userInput = req.body;
    // VULNERABLE: Deep merge without validation
    Object.assign(obj, userInput);
    res.json(obj);
});

// Insecure JWT Implementation
const jwt = require('jsonwebtoken');
app.post('/login', (req, res) => {
    // VULNERABLE: Weak secret and no expiration
    const token = jwt.sign({ user: req.body.username }, 'secret');
    res.json({ token });
});

// Directory Listing
app.get('/files/*', (req, res) => {
    const path = req.params[0];
    // VULNERABLE: Exposing directory contents
    fs.readdir(path, (err, files) => {
        res.json(files);
    });
});

app.listen(3000);