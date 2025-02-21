const express = require('express');
const app = express();
const usermodel = require("./models/user");

const cookieparser = require('cookie-parser');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

app.set('view engine', 'ejs');
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieparser());

app.get('/', (req, res) => {
    res.render('index');
});

app.post('/create',
    [
        body('username').isLength({ min: 3 }).withMessage('Username must be at least 3 characters long'),
        body('email').isEmail().withMessage('Invalid email format'),
        body('password')
            .isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
            .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
            .matches(/[\W_]/).withMessage('Password must contain at least one special character'),
        body('age').optional().isInt({ min: 1, max: 120 }).withMessage('Age must be a valid number between 1 and 120')
    ],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        let { username, email, password, age } = req.body;

        bcrypt.genSalt(10, (err, salt) => {
            bcrypt.hash(password, salt, async (err, hash) => {
                let createduser = await usermodel.create({
                    username,
                    email,
                    password: hash,
                    age
                });

                let token = jwt.sign({ email }, "secret");
                res.cookie("token", token);
                res.send(createduser);
            });
        });
    }
);

app.get("/login", (req, res) => {
    res.render('login');
});

app.post('/login',
    [
        body('email').isEmail().withMessage('Invalid email format'),
        body('password').notEmpty().withMessage('Password is required')
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        let user = await usermodel.findOne({ email: req.body.email });
        if (!user) return res.send("something went wrong");

        bcrypt.compare(req.body.password, user.password, (err, result) => {
            if (result) {
                let token = jwt.sign({ email: user.email }, "secret");
                res.cookie("token", token);
                res.send("You can login ☺");
            } else {
                res.send("No no, Bad manners 😡");
            }
        });
    }
);

app.get('/logout', (req, res) => {
    res.cookie("token", "");
    res.redirect('/');
});

app.listen(3000);
