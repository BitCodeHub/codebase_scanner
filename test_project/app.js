const express = require('express');
const _ = require('lodash');
const $ = require('jquery');

const app = express();

// Command injection vulnerability with lodash dependency
app.post('/execute', (req, res) => {
    const command = req.body.command;
    const processedCommand = _.template(command)({});
    
    // VULNERABLE: Direct execution of user input
    exec(processedCommand, (error, stdout, stderr) => {
        res.send(stdout);
    });
});

// XSS vulnerability with jQuery
app.get('/search', (req, res) => {
    const query = req.query.q;
    // VULNERABLE: Using innerHTML with user input
    res.send(`<div id="results">${query}</div>`);
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});