const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const User = require('../model/user');

// Create an Express Router to handle authentication-related routes
const router = express.Router();
const secretKey = process.env.SECRET_KEY;  // The secret key for signing JWT (should be stored securely)


// POST /login - Login route
router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).send('Email and password are required');
    }

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(400).send('User not found');
        }

        // Compare password with the stored hashed password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).send('Invalid password');
        }

        // Generate a JWT token
        const token = jwt.sign({ id: user._id, username: user.username }, secretKey, {
            expiresIn: '1h',  // Token expiration (optional)
        });

        // Send the token to the client (you can choose to send it in a cookie or response body)
        res.json({ token });

    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).send('Server error');
    }
});


// POST /register - Registration route
router.post('/register', async (req, res) => {
    const { email, username, password } = req.body;

    if (!email || !username || !password) {
        return res.status(400).send('Email, username, and password are required');
    }

    try {
        const existingUser = await User.findOne({ email });

        if (existingUser) {
            return res.status(400).send('User already exists');
        }

        // Hash the password before saving
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({
            email,
            username,
            password: hashedPassword,
        });

        await newUser.save();

        res.status(201).send('User registered successfully');

    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).send('Server error');
    }
});


// GET /protected - Example of a protected route
router.get('/protected', (req, res) => {
    // Here, you'd normally verify the JWT to authenticate the user
    const token = req.headers['authorization']?.split(' ')[1]; // Expecting 'Bearer <token>'

    if (!token) {
        return res.status(401).send('Authorization token required');
    }

    // Verify the JWT token
    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
            return res.status(401).send('Invalid token');
        }

        // If token is valid, allow access to protected resource
        res.json({ message: 'Welcome to the protected route!', user: decoded });
    });
});

module.exports = router;
