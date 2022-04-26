require('dotenv').config();
const express = require("express");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");
const SHA256 = require("crypto-js/sha256");
const passport = require("passport");
const LocalStrategy = require("passport-local");
const passportLocalMongoose = require("passport-local-mongoose");
const bcrypt = require("bcrypt");
const saltRounds = 10;

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(passport.initialize());
app.use(passport.session());
app.set("view engine", "ejs");
const port = 3000

const mongoosePasscode = process.env.mongoosePasscode;
mongoose.connect("mongodb+srv://danielshaby:" + mongoosePasscode + "@authcluster.yrmin.mongodb.net/AuthDB?retryWrites=true&w=majority");

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: [true, "You need a 'username' "]
    },
    password: {
        type: String,
        required: [true, "This user needs a 'password' "]
    }
});

userSchema.plugin(passportLocalMongoose);

const User = mongoose.model("User", userSchema);

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

// passport.use(User.createStrategy());


app.get("/", (req, res) => {
    res.render("home")
});

app.route("/login")
    .get((req, res) => {
        res.render("login", {
            errMessage: ""
        })
    })
    .post((req, res) => {
        const username = req.body.username;
        const typedPassword = req.body.password

        User.findOne({ email: username }, (err, foundUsername) => {
            if (foundUsername) {
                bcrypt.compare(typedPassword, foundUsername.password, function (err, result) {
                    if (err) {
                        console.log(err);
                        res.redirect("/");
                    }
                    else if (result === false) {
                        res.render("login", {
                            errMessage: "Password does not match username."
                        });
                    }
                    else if (result === true) {

                        res.render("secrets");
                        console.log("bcrypt.compare succeeded, passwords match");
                    }
                });

            } else {
                console.log(err);
                res.render("login", {
                    errMessage: "Could not find this username/email address"
                });
            }
        });
    });

// passport.use(new LocalStrategy(
//     function verify(username, password, done) {
//         User.findOne({ username: username }, function (err, user) {

//         })
//     }
// ));
// // User.authenticate()

app.route("/register")
    .get((req, res) => {
        res.render("register");
    })
    .post((req, res) => {
        bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
            if (err) { console.log(err); }
            else {
                const newUser = new User({
                    email: req.body.username,
                    password: hash
                });

                newUser.save(function (err, results) {
                    if (err) {
                        console.log(err);
                        res.redirect("/");
                    }
                    else {
                        // passport.authenticate("local"), function (req, res) {
                        res.render("secrets");
                        console.log(results);
                        // };
                    }
                });
            }
        });
    });

app.get("/submit", (req, res) => {
    res.render("submit");
});

app.listen(port, () => {
    console.log(`Secrets App listening on port ${port}`);
})