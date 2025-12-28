
const express = require('express');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 5001;

// Serve static files
app.use(express.static('public'));

// Route for phpMyAdmin interface
app.get('/phpmyadmin', (req, res) => {
    const phpFile = path.join(__dirname, 'phpmyadmin-setup.php');
    
    if (!fs.existsSync(phpFile)) {
        return res.status(404).send('phpMyAdmin setup file not found');
    }
    
    // Execute PHP file
    const php = spawn('php', [phpFile]);
    let output = '';
    let error = '';
    
    php.stdout.on('data', (data) => {
        output += data.toString();
    });
    
    php.stderr.on('data', (data) => {
        error += data.toString();
    });
    
    php.on('close', (code) => {
        if (code !== 0) {
            return res.status(500).send(`PHP Error: ${error}`);
        }
        res.send(output);
    });
});

// Database query endpoint
app.get('/api/query', async (req, res) => {
    try {
        const { db } = require('./server/db.js');
        const { sql } = require('drizzle-orm');
        
        const query = req.query.q;
        if (!query) {
            return res.status(400).json({ error: 'Query parameter required' });
        }
        
        const result = await db.execute(sql.raw(query));
        res.json({ success: true, data: result });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`phpMyAdmin interface available at http://0.0.0.0:${PORT}/phpmyadmin`);
    console.log(`Access it via your Replit preview URL on port ${PORT}`);
});
