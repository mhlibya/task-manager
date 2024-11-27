// init project
var express = require('express');
const { body } = require('express-validator');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const User = require(__dirname + '/model/user');
const jwt = require('jsonwebtoken');
const authRoutes = require(__dirname + '/routes/auth');

require('dotenv').config();
var app = express();
const dbUri = process.env.DB_URI;
const secretKey = process.env.SECRET_KEY;

// connecting to the database
mongoose.connect(dbUri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB successfully'))
.catch(err => console.error('Failed to connect to MongoDB:', err));

app.use(express.static('public'));

//defining the home route '/'
app.get("/", function (req, res) {
  res.sendFile(__dirname + '/views/home.html');
});

//defining the registration rout
app.get("/register", function (req, res) {
    res.sendFile(__dirname + '/views/register.html');
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use('/auth', authRoutes);

//handling the data coming from thte registration page
app.post("/register", function (req, res) {
    const email = req.body.email;
    const username = req.body.username;
    const password = req.body.password;
//handling registing already registered email
    const alreadyRegistered = User.findOne({email: email});
    if(alreadyRegistered.email === email){return res.send('The Email is already registered')};
// handling empty submessions
    if(!email || !username || !password){
        return res.status(400).send("Username and password are required");
    }
//crypting the password before saving it in the database
    bcrypt.hash(password, 10, function(err, hash) {
        if (err){console.log(err)};
        const user = new User({
            email: email,
            username: username,
            password: hash
        });
//saving a new user
        user.save()
            .then(() => console.log("User saved successfully"))
            .catch(saveErr => console.log('Error saving the user:', saveErr));
    });
    res.redirect("/login");
});

//defining the login route
app.get("/login", function (req, res) {
    res.sendFile(__dirname + '/views/login.html');
});

//handling the user's login
app.post("/login", function (req, res) {
    User.findOne({email: `${req.body.email}`}).then((user) => {
        
//handling wrong email entry
        if(!user){
        res.send('you are not registered')
    }
//checking the password
    bcrypt.compare(req.body.password, user.password, function(err, result) {
        if(err){console.log(err)}
        if(result === true){
            const token = jwt.sign({userId: user._id, userName: user.username}, secretKey);
            res.cookie('token', token, {
                httpsOnly: true,
                source: process.env.NODE_ENV === 'production', //only send over HTTP in production
                maxAge: 3600000,
                sameSite: 'Strict' //prevent the cookie from being sent with cross-site requests
            });
            res.redirect("/index");
        }
        else{
            res.status(401).send('the password is incorrect');
        }
    });
    
    });
});

//handling the logout by returning the user to the '/' route after clearing the cookie
app.get("/logout", function (req, res){
    res.cookie('token', '', {
        expires: new Date(0), //setting the expiration date to a date in the past
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'Strict'
    });
    res.redirect("/");
});

//defining the index route
app.get("/index", function (req, res) {
    res.sendFile(__dirname + '/views/index.html');
});

// Listen on port set in environment variable or default to 3000
var listener = app.listen(process.env.PORT || 3000, function () {
  console.log('Your app is listening on port ' + listener.address().port);
});