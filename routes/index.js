const router = require("express").Router();
const User = require("../models/User.model");

// we import the bcrypt module
const bcrypt = require("bcryptjs");

// we set the number of salt rounds
// the higher the number, the more secure the password
// but the longer it takes to hash it
const saltRounds = 10;

// ---------- GET ROUTES ---------- \\
router.get("/", (req, res, next) => {
  res.render("index");
});

router.get("/login", (req, res, next) => {
  res.render("login");
});


// ---------- POST ROUTES ---------- \\

router.post("/signup", (req, res, next) => {
  const { username, password } = req.body;

  // we check if the username and password are empty strings
  if (username === "" || password === "") {
    res.status(400).render("index", { errorMessage: "Indicate a username and a password to sign up" });
    return;
  }

  // we check if the username already exists in the database
  User.findOne({ username })
    .then((user) => {
      if (user !== null) {
        // let's render the signup form again (it's in index view) with the error message
        res.status(400).render("index", { errorMessage: "The username already exists" });
        return;
      }
      else {
        bcrypt
          // we generate a salt
          .genSalt(saltRounds)
          // we hash the password with the salt
          .then((salt) => bcrypt.hash(password, salt))
          // we create the user in the database
          .then((hashedPassword) => {
            return User.create({
              // we don't use username: username because the key and the value have the same name
              username,
              // the key in the model is called "password", but the value is the hashed password
              // in this case we can't just write hashedPassword
              password: hashedPassword,
            });
          })
          // we show the success page
          .then((user) => {
            res.render("success");
          })
          .catch((error) => next(error));
      }

    })
    .catch((error) => next(error));

});

module.exports = router;
