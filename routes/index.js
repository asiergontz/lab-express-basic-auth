const router = require("express").Router();
const User = require("../models/User.model");


const bcrypt = require("bcryptjs");


const { isLoggedIn, isLoggedOut } = require('../middlewares/route.guard.js');


const saltRounds = 10;

// ---------- GET ROUTES ---------- \\
router.get("/", (req, res, next) => {
  res.render("index");
});

router.get("/login", (req, res, next) => {
  res.render("login");
});

router.get("/private", isLoggedIn, (req, res, next) => {
    res.render("private", { user: req.session.currentUser });
});

// ---------- POST ROUTES ---------- \\

router.post("/signup", (req, res, next) => {
  const { username, password } = req.body;


  if (username === "" || password === "") {
    res.status(400).render("index", { errorMessage: "Indicate a username and a password to sign up" });
    return;
  }

 
  User.findOne({ username })
    .then((user) => {
      if (user !== null) {
       
        res.status(400).render("index", { errorMessage: "The username already exists" });
        return;
      }
      else {
        bcrypt
         
          .genSalt(saltRounds)
     
          .then((salt) => bcrypt.hash(password, salt))
         
          .then((hashedPassword) => {
            return User.create({
            
              username,
             
              password: hashedPassword,
            });
          })
         
          .then((user) => {
            res.render("success");
          })
          .catch((error) => next(error));
      }

    })
    .catch((error) => next(error));

});

router.post("/login", (req, res, next) => {
  const { username, password } = req.body;
  console.log(username, password);

  if (username === "" || password === "") {
    res.status(400).render("login", { errorMessage: "Indicate a username and a password to log in" });
    return;
  }

  User.findOne({ username })
    .then((user) => {
      console.log('SESSION =====> ', req.session);
  
      if (!user) {
        res.status(400).render("login", { errorMessage: "The username doesn't exist" });
        return;
      }

      bcrypt.compare(password, user.password)
        .then((match) => {
          if (match) {
            req.session.currentUser = user;
            res.redirect("/private");
          }
          else {
            res.status(400).render("login", { errorMessage: "Incorrect password" });
          }
        })
        .catch((error) => next(error));

    })
    .catch((error) => next(error));
});

module.exports = router;
