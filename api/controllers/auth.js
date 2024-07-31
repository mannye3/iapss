
import { db } from './../connect.js';
import bcrypt from "bcryptjs"
import jwt from "jsonwebtoken"
import nodemailer from 'nodemailer';
import { v4 as uuidv4 } from 'uuid';
const secretKey = process.env.JWT_SECRET; // Use the secret key from environment variables




const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        user: process.env.EMAIL, // Your email address
        pass: process.env.EMAIL_PASSWORD // Your email password
    }
});




export const register = (req, res) => {
    const { name, email, password, roles } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    const q = "SELECT * FROM users WHERE email = ?";
    db.query(q, [email], (err, data) => {
        if (err) return res.status(500).json(err);
        if (data.length > 0) {
            return res.status(409).json({ error: 'User already exists' });
        }

        const salt = bcrypt.genSaltSync(10);
        const hashedPassword = bcrypt.hashSync(password, salt);

        const insertUserQuery = "INSERT INTO users (`name`, `email`, `password`) VALUES (?, ?, ?)";
        db.query(insertUserQuery, [name, email, hashedPassword], (err, result) => {
            if (err) return res.status(500).json(err);

            const userId = result.insertId;
            const roleIds = roles.map(role => `(?, (SELECT id FROM roles WHERE name = ?))`).join(', ');
            const roleValues = roles.flatMap(role => [userId, role]);

            const insertRolesQuery = `INSERT INTO user_roles (user_id, role_id) VALUES ${roleIds}`;
            db.query(insertRolesQuery, roleValues, (err, result) => {
                if (err) return res.status(500).json(err);
                res.status(201).json({ message: 'User registered successfully' });
            });
        });
    });
};




export const login = async (req, res) => {
    try {
        // Validate request body
        if (!req.body.email || !req.body.password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        // Check if the user exists in the database
        const checkUserQuery = "SELECT * FROM users WHERE email = ?";
        db.query(checkUserQuery, [req.body.email], async (err, data) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            if (data.length === 0) {
                return res.status(401).json({ error: 'Invalid email or password' });
            }

            const user = data[0];

            // Compare the password with the hashed password in the database
            const isPasswordValid = await bcrypt.compare(req.body.password, user.password);
            if (!isPasswordValid) {
                return res.status(401).json({ error: 'Invalid email or password' });
            }

            // Generate a JWT token
            const token = jwt.sign({ id: user.id, name: user.name, email: user.email }, process.env.JWT_SECRET, {
            expiresIn: '1h'
        });

            res.status(200).json({ message: 'Login successful', token });
        });
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
};




// Request password reset
export const requestPasswordReset = (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: 'Email is required' });
    }

    const query = "SELECT id FROM users WHERE email = ?";
    db.query(query, [email], (err, data) => {
        if (err) return res.status(500).json(err);
        if (data.length === 0) return res.status(404).json({ error: 'User not found' });

        const userId = data[0].id;
        const token = jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: '1h' });

        const insertTokenQuery = "INSERT INTO password_reset_tokens (user_id, token) VALUES (?, ?)";
        db.query(insertTokenQuery, [userId, token], (err, result) => {
            if (err) return res.status(500).json(err);

             const resetLink = `${process.env.CLIENT_URL}/reset-password/${token}`;
        const mailOptions = {
            from: process.env.EMAIL,
            to: email,
            subject: 'Password Reset',
            text: `Click on the following link to reset your password: ${resetLink}`
        };


        
            

            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    return res.status(500).json({ error: 'Error sending email', details: error });
                }
                res.status(200).json({ message: 'Password reset link sent' });
            });
        });
    });
};




// Reset password
export const resetPassword = (req, res) => {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
        return res.status(400).json({ error: 'Token and new password are required' });
    }

    const verifyTokenQuery = "SELECT * FROM password_reset_tokens WHERE token = ?";
    db.query(verifyTokenQuery, [token], (err, data) => {
        if (err) return res.status(500).json(err);
        if (data.length === 0 || data[0].used) {
            return res.status(400).json({ error: 'Invalid or expired token' });
        }

        jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
            if (err) return res.status(400).json({ error: 'Invalid or expired token' });

            const userId = decoded.id;

            const salt = bcrypt.genSaltSync(10);
            const hashedPassword = bcrypt.hashSync(newPassword, salt);

            const updatePasswordQuery = "UPDATE users SET password = ? WHERE id = ?";
            db.query(updatePasswordQuery, [hashedPassword, userId], (err, result) => {
                if (err) return res.status(500).json(err);

                const markTokenUsedQuery = "UPDATE password_reset_tokens SET used = TRUE WHERE token = ?";
                db.query(markTokenUsedQuery, [token], (err, result) => {
                    if (err) return res.status(500).json(err);

                    res.status(200).json({ message: 'Password reset successful' });
                });
            });
        });
    });
};




