import 'dotenv/config';

import express from 'express';
import mysql from 'mysql2/promise';
import cors from 'cors';
import morgan from 'morgan';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';
import axios from 'axios';

const requiredEnvVars = [
    'DB_HOST',
    'DB_USER',
    'DB_PASSWORD',
    'DB_NAME',
    'JWT_SECRET',
    'HCAPTCHA_SECRET_KEY'
];
const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingVars.length > 0) {
    console.error('[FATAL ERROR] Missing required environment variables:');
    console.error(missingVars.join('\n'));
    console.error('Please create and configure your backend/.env file.');
    process.exit(1); 
}


const HCAPTCHA_SECRET_KEY = process.env.HCAPTCHA_SECRET_KEY;
const JWT_SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 3001;


const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
};


// Create a connection pool
let db;
try {
    db = await mysql.createPool(dbConfig);
    // Test database connection
    await db.query('SELECT 1');
    console.log('Database connected successfully.');
} catch (err) {
    console.error('[FATAL ERROR] Database connection failed:', err.message);
    console.error('Please check your backend/.env file and ensure MySQL is running.');
    process.exit(1);
}

const app = express();

// --- Middleware ---
// CORS (Cross-Origin Resource Sharing)
app.use(cors()); // Allows all origins for ngrok. For production, restrict this.

// Logging
app.use(morgan('dev'));

// JSON parsing
app.use(express.json());

// --- Authentication Middleware ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (token == null) {
        return res.status(401).send('No token provided.');
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).send('Token is invalid or expired.');
        }
        req.user = user;
        next();
    });
};

// --- Authorization Middleware ---
const authorizeRole = (role) => {
    return (req, res, next) => {
        if (req.user.role !== role) {
            return res.status(403).send('You do not have permission for this action.');
        }
        next();
    };
};

const authorizeRoles = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).send('You do not have permission for this action.');
        }
        next();
    };
};

// --- hCaptcha Middleware ---
const verifyCaptcha = async (req, res, next) => {
    const { captchaToken } = req.body;
    if (!captchaToken) {
        return res.status(400).send('Captcha token is missing.');
    }

    try {
        const params = new URLSearchParams();
        params.append('response', captchaToken);
        params.append('secret', HCAPTCHA_SECRET_KEY);

        const verifyURL = 'https://api.hcaptcha.com/siteverify';
        const response = await axios.post(verifyURL, params, {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
        });

        if (response.data.success) {
            next(); // Captcha is valid
        } else {
            console.warn('Captcha verification failed:', response.data['error-codes']);
            return res.status(400).send('Captcha verification failed.');
        }
    } catch (error) {
        console.error('Captcha verification error:', error.message);
        return res.status(500).send('Error verifying captcha.');
    }
};
// --- END MIDDLEWARE ---

// --- API ROUTES ---

// User Login
app.post('/api/login', verifyCaptcha, async (req, res) => {
    const { email, password, loginType } = req.body;

    if (!email || !password || !loginType) {
        return res.status(400).send('Email, password, and loginType are required.');
    }

    try {
        const [users] = await db.query(
            'SELECT * FROM users WHERE email = ?',
            [email]
        );

        if (users.length === 0) {
            return res.status(400).send('Invalid credentials.');
        }

        const user = users[0];

        // Check login type vs user role
        if (loginType === 'main' && user.role === 'superuser') {
            return res.status(403).send('Super User login is only allowed on the admin portal.');
        }
        if (loginType === 'superuser' && user.role !== 'superuser') {
            return res.status(403).send('This portal is for Super Users only.');
        }

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(400).send('Invalid credentials.');
        }

        // Create JWT
        const payload = {
            id: user.id,
            name: user.name,
            role: user.role,
        };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });

        res.json({ user: payload, token });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).send('Server error during login.');
    }
});

// Create a new User (Manager or Superuser)
app.post('/api/users', authenticateToken, authorizeRoles('manager', 'superuser'), verifyCaptcha, async (req, res) => {
    const { name, email, password, role } = req.body;
    const requestingUser = req.user;

    // Server-side validation
    if (requestingUser.role === 'manager' && role !== 'employee') {
        return res.status(403).send('Managers can only create Employee accounts.');
    }

    if (!['employee', 'manager', 'superuser'].includes(role)) {
        return res.status(400).send('Invalid user role specified.');
    }

    // Superuser-only check (only a superuser can create another superuser)
    if (role === 'superuser' && requestingUser.role !== 'superuser') {
        return res.status(403).send('Only Super Users can create other Super Users.');
    }

    try {
        // Check if user already exists
        const [existing] = await db.query('SELECT id FROM users WHERE email = ?', [email]);
        if (existing.length > 0) {
            return res.status(400).send('User with this email already exists.');
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const password_hash = await bcrypt.hash(password, salt);
        const id = uuidv4();

        // Insert into database
        await db.query(
            'INSERT INTO users (id, name, email, password_hash, role) VALUES (?, ?, ?, ?, ?)',
            [id, name, email, password_hash, role]
        );

        const newUser = { id, name, email, role };
        res.status(201).json(newUser);

    } catch (error) {
        console.error('Create user error:', error);
        res.status(500).send('Server error creating user.');
    }
});


// Get all users (Superuser) or only employees (Manager)
app.get('/api/users', authenticateToken, authorizeRoles('manager', 'superuser'), async (req, res) => {
    try {
        let query = 'SELECT id, name, email, role FROM users';
        let params = [];

        if (req.user.role === 'manager') {
            // Managers should only see employees
            query += ' WHERE role = ?';
            params.push('employee');
        }
        // Superusers see everyone (no "WHERE" clause needed)

        const [users] = await db.query(query, params);
        res.json(users);
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).send('Server error fetching users.');
    }
});

// --- Project Routes ---

// Get all projects (Manager/Superuser) or assigned projects (Employee)
app.get('/api/projects', authenticateToken, async (req, res) => {
    try {
        let query = `
      SELECT p.id, p.name, p.status, p.assignedTo, u.name as assignedToName
      FROM projects p
      LEFT JOIN users u ON p.assignedTo = u.id
    `;
        let params = [];

        if (req.user.role === 'employee') {
            query += ' WHERE p.assignedTo = ?';
            params.push(req.user.id);
        }

        const [projects] = await db.query(query, params);
        res.json(projects);
    } catch (error) {
        console.error('Get projects error:', error);
        res.status(500).send('Server error fetching projects.');
    }
});

// Create new project (Manager/Superuser)
app.post('/api/projects', authenticateToken, authorizeRoles('manager', 'superuser'), async (req, res) => {
    const { name, status, assignedTo } = req.body;
    const id = uuidv4();

    try {
        await db.query(
            'INSERT INTO projects (id, name, status, assignedTo) VALUES (?, ?, ?, ?)',
            [id, name, status, assignedTo || null]
        );

        // Fetch the newly created project with user name
        const [newProject] = await db.query(
            `SELECT p.id, p.name, p.status, p.assignedTo, u.name as assignedToName
        FROM projects p
        LEFT JOIN users u ON p.assignedTo = u.id
        WHERE p.id = ?`,
            [id]
        );

        res.status(201).json(newProject[0]);
    } catch (error) {
        console.error('Create project error:', error);
        res.status(500).send('Server error creating project.');
    }
});

// Update a project (Manager/Superuser)
app.put('/api/projects/:id', authenticateToken, authorizeRoles('manager', 'superuser'), async (req, res) => {
    const { id } = req.params;
    const { name, status, assignedTo } = req.body;

    try {
        await db.query(
            'UPDATE projects SET name = ?, status = ?, assignedTo = ? WHERE id = ?',
            [name, status, assignedTo || null, id]
        );

        // Fetch the updated project with user name
        const [updatedProject] = await db.query(
            `SELECT p.id, p.name, p.status, p.assignedTo, u.name as assignedToName
        FROM projects p
        LEFT JOIN users u ON p.assignedTo = u.id
        WHERE p.id = ?`,
            [id]
        );

        res.json(updatedProject[0]);
    } catch (error) {
        console.error('Update project error:', error);
        res.status(500).send('Server error updating project.');
    }
});

// Delete a project (Manager/Superuser)
app.delete('/api/projects/:id', authenticateToken, authorizeRoles('manager', 'superuser'), async (req, res) => {
    const { id } = req.params;

    try {
        await db.query('DELETE FROM projects WHERE id = ?', [id]);
        res.json({ message: 'Project deleted successfully.' });
    } catch (error) {
        console.error('Delete project error:', error);
        res.status(500).send('Server error deleting project.');
    }
});

// --- END API ROUTES ---

// Start the server
app.listen(PORT, () => {
    console.log(`Backend server running on http://localhost:${PORT}`);
});

