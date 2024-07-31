import bcrypt from 'bcryptjs';
import { db } from '../connect.js';
import transporter from '../config/nodemailer.js';


export const onboardUser = (req, res) => {
    const { name, email, password, roles } = req.body;

    // Validate request body
    if (!name || !email || !password || !roles || !Array.isArray(roles)) {
        return res.status(400).json({ error: 'All fields are required and roles must be an array' });
    }

    // Check if email already exists in the database
    const queryCheckUser = "SELECT * FROM users WHERE email = ?";
    db.query(queryCheckUser, [email], (err, data) => {
        if (err) return res.status(500).json(err);
        if (data.length > 0) {
            return res.status(409).json({ error: 'User already exists' });
        }

        // Hash the password using bcrypt
        const salt = bcrypt.genSaltSync(10);
        const hashedPassword = bcrypt.hashSync(password, salt);

        // Store the hashed password and email in the database
        const queryInsertUser = "INSERT INTO users (`name`, `email`, `password`) VALUES (?, ?, ?)";
        db.query(queryInsertUser, [name, email, hashedPassword], (err, result) => {
            if (err) return res.status(500).json(err);

            const userId = result.insertId;
            const roleQueries = roles.map(role => `(?, (SELECT id FROM roles WHERE name = ?))`).join(', ');
            const roleValues = roles.flatMap(role => [userId, role]);

            const queryInsertRoles = `INSERT INTO user_roles (user_id, role_id) VALUES ${roleQueries}`;
            db.query(queryInsertRoles, roleValues, (err) => {
                if (err) return res.status(500).json(err);

                // Send email with login details
                const mailOptions = {
                    from: process.env.EMAIL_USER,
                    to: email,
                    subject: 'Your Account Details',
                    text: `Hello ${name},\n\nYour account has been created.\n\nLogin Details:\nEmail: ${email}\nPassword: ${password}\n\nPlease change your password after your first login.\n\nBest regards,\nAdmin Team`
                };

                transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        console.error('Error sending email:', error);
                        return res.status(500).json({ error: 'Error sending email' });
                    }
                    console.log('Email sent:', info.response);
                    res.status(201).json({ message: 'User onboarded successfully and email sent' });
                });
            });
        });
    });
};
