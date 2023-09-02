const {Router} = require('express');
const router = new Router();
const User = require('../models/User.model');
const mongoose = require('mongoose');

// import middleware functions
const { isLoggedIn, isLoggedOut } = require('../middleware/route-guard.js');

// Authentication set up
const bcryptjs = require("bcryptjs");
const saltRounds = 10;

//////////// S I G N  U P ///////////

// User requests the sign up form
router.get('/signup', isLoggedOut,(req, res) => {
  res.render('auth/signup')
});

// POST route to process the form's data and create the user credentials
router.post('/signup', isLoggedOut,(req, res, next) =>{

  const {username, email, password} = req.body;

  // Check if all fields are filled
  if(!username  || !email || !password){
    res.render('auth/signup', {
      errorMessage: 'All fields need to be filled.'
    });
    return;
  }

  // Check if password's length is ok
  if (password.length < 6){
    res.render('auth/signup', {errorMessage: 'Password needs to be at least 6 characters.'})
  }

  // make sure passwords are strong:
  const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
  if (!regex.test(password)) {
    res
      .status(500)
      .render('auth/signup', { errorMessage: 'Password needs to have at least 6 chars and must contain at least one number, one lowercase and one uppercase letter.' });
    return;
  }

  bcryptjs
    .genSalt(saltRounds)
    .then(salt => bcryptjs.hash(password, salt))
    .then(hashedPassword => {
      return User.create({
        username,
        email,
        passwordHash: hashedPassword
      })
    })
        .then((userFromDB) => {
          console.log(`Newly created user: ${userFromDB}`)
          res.redirect('/myProfile');
        })
    .catch((error) => {
      if (error instanceof mongoose.Error.ValidationError) {
        res.status(500).render("auth/signup", { errorMessage: error.message });
      } else if (error.code === 11000) {
        res.status(500).render("auth/signup", {
          errorMessage: "Hey, you already have an account registered with us!"
        });
          } else {
            next(error)
          }
        });
    });


// Redirect to thank you message once signing up is completed
router.get('/SignedUp', isLoggedOut, (req, res) =>{
  res.render('auth/signed-up')
})

//////////// L O G I N ///////////

// User requests the login form
router.get('/login', isLoggedOut, (req, res) =>{
  res.render('auth/login')
})

// Process info from the login form
router.post('/login', isLoggedOut, (req, res, next) => {
  console.log('SESSION =====> ', req.session);

  const {email, password} = req.body;

  if (email === "" || password === "") {
    res.render("auth/login", {
      errorMessage: "Please enter both, email and password to login."
    });
    return;
  }

  User.findOne({email})
    .then((user) => {
      // check if the user is known
      if (!user) {
        res.render("auth/login", {errorMessage: "User not found and/or incorrect password."});
        return;
      }
      // if there's a user, compare provided password with the hashed password saved in the database
      else if (bcryptjs.compareSync(password, user.passwordHash)) {
          res.render("users/my-profile", {user});
          } else {
          res.render("auth/login", {errorMessage: "User not found and/or incorrect password."})
      }

        /// Save the user's session //
        req.session.currentUser = user;
        res.redirect("/myprofile")

    })

    .catch((error) => console.log(error))
});

// Redirect user to user's profile
router.get('/myprofile', isLoggedIn,(req, res) => {
  res.render('users/my-profile', {userInSession: req.session.currentUser});
});

//////////// L O G  O U T ///////////

router.post("/logout", isLoggedIn,(req, res) => {
  req.session.destroy();
  res.redirect("/");
});

module.exports = router;
