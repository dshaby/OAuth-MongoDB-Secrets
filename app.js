require('dotenv').config();
const express = require("express");
const flash = require("express-flash");
const session = require("express-session");
const passport = require("passport");
const app = express();
const GoogleStrategy = require("passport-google-oauth20")
app.use(flash());
app.use(session({
    secret: process.env.SOME_LONG_UNGUESSABLE_STRING,
    resave: false,
    saveUninitialized: false
}));
app.use(passport.authenticate("session"));
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(passport.initialize());
app.use(passport.session());
app.set("view engine", "ejs");
let port = process.env.PORT;
if (port == null || port == "") {
    port = 3000;
}

// Mongoose
const mongoose = require("mongoose");
const passportLocalMongoose = require("passport-local-mongoose");
const mongoosePasscode = process.env.mongoosePasscode;
mongoose.connect("mongodb+srv://danielshaby:" + mongoosePasscode + "@authcluster.yrmin.mongodb.net/AuthDB?retryWrites=true&w=majority");

const secretsSchema = new mongoose.Schema({
    secret: {
        type: String,
        required: [true, "Your secret needs some content"]
    }
});
const Secret = mongoose.model("Secret", secretsSchema);

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, "You need a 'username' as defined in userSchema"]
    },
    userSecrets: secretsSchema
});

userSchema.plugin(passportLocalMongoose);

const User = mongoose.model("User", userSchema);

// passport config
passport.use(User.createStrategy());
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/oauth2/redirect/google",
    passReqToCallback: true
},
    async (request, accessToken, refreshToken, profile, done) => {
        const username = profile.emails[0].value;

        User.findOne({ username: username }, function (err, foundUser) {

            if (foundUser == null) {
                const newUser = new User({
                    username: username
                });
                newUser.save(function (err, result) {
                    if (err) { console.log(err); }
                    else {
                        console.log(result);
                        return done(null, newUser);
                    }
                });
            }
            else {
                console.log("profile.provider: " + profile.provider);
                foundUser.lastVisited = new Date();
                return done(null, foundUser);
            }
        })
    }
));

app.get("/", (req, res) => {
    res.render("home")
});

app.route("/login")
    .get((req, res) => {
        res.render("login", {
            errMessage: "" || req.session.messages
        })
        req.session.messages = "";
    })
    .post(
        passport.authenticate("local", { failureRedirect: "/login", failureMessage: "Invalid username or password" }),
        (req, res) => {
            res.redirect("/secrets")
        }
    );

app.get("/login/federated/google", passport.authenticate("google", {
    scope: ["profile", "email"],
}));

app.get("/oauth2/redirect/google", passport.authenticate("google", {
    failureRedirect: "/login",
    successRedirect: "/secrets",
    failureFlash: true,
    successFlash: "Successfully logged in!",
}));

app.route("/register")
    .get((req, res) => {
        res.render("register");
    })
    .post((req, res) => {
        console.log("Registering new user");
        User.register(new User({ username: req.body.username }), req.body.password, function (err, user) {
            if (err) {
                console.log(err);
                console.log("Error while registering");
                res.redirect("/register");
            }
            else {
                passport.authenticate("local")(req, res, function () {
                    // Below will only be called if successfully authenticated
                    console.log("Successfully authenticated newly registered user");
                    res.redirect("/secrets");
                    console.log("req.isAuthenticated: " + req.isAuthenticated());
                });
            }
        });
    });

app.get("/logout", (req, res) => {
    req.logout();
    console.log("Logging out, req.isAuthenticated: " + req.isAuthenticated());
    res.redirect('/');
});
app.route("/submit")
    .get((req, res) => {
        res.set("Cache-Control", "no-cache, private, no-store, must-revalidate, max-stal e=0, post-check=0, pre-check=0");
        if (req.isAuthenticated()) {
            res.render("submit");
        }
        else {
            res.redirect("/login");
            console.log("req.isAuthenticated: " + req.isAuthenticated());
        }
    })
    .post((req, res) => {
        const submittedSecret = req.body.secret;

        const newSecret = new Secret({
            secret: submittedSecret
        });

        newSecret.save((err, results) => {
            if (err) console.log(err);
            else {
                if (results) {
                    User.findOneAndUpdate({ username: req.user.username }, { $push: { userSecrets: newSecret } }, function (err, foundUser) {
                        if (err) { console.log(err); }
                        else {
                            res.redirect("/secrets")
                        }
                    })
                }
            }
        });
    });

app.get("/secrets", (req, res) => {
    res.set("Cache-Control", "no-cache, private, no-store, must-revalidate, max-stal e=0, post-check=0, pre-check=0");
    if (req.isAuthenticated()) {
        Secret.find({}, "secret", (err, allSecrets) => {
            if (err) { console.log(err); }
            else {
                res.render("secrets", {
                    secrets: allSecrets
                })
            }
        });
    }
    else {
        res.redirect("/login");
        console.log("req.isAuthenticated: " + req.isAuthenticated());
    }
})

app.listen(port, () => {
    console.log(`Secrets App listening on port ${port}`);
});