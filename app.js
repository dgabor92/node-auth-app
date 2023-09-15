const express = require("express");
const mongoose = require("mongoose");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const session = require("express-session");
const flash = require("connect-flash");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("./models/user");
require("dotenv").config();

const app = express();

function generateJwt(user) {
  const payload = {
    id: user.id,
    email: user.email,
  };
  const secret = process.env.SECRET;
  const options = {
    expiresIn: "1h",
  };
  const token = jwt.sign(payload, secret, options);
  return token;
}

mongoose
  .connect("mongodb://root:example@localhost:27017/", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("MongoDB Connected");
  })
  .catch((err) => {
    console.log(err);
  });

app.use(express.urlencoded({ extended: false }));
app.use(
  session({
    secret: "secret",
    resave: true,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());
app.use(express.json());
app.use(flash());

passport.use(
  "local",
  new LocalStrategy({ usernameField: "email" }, (email, password, done) => {
    User.findOne({ email: email })
      .then((user) => {
        if (!user) {
          return done(null, false, { message: "No User Found" });
        }
        bcrypt.compare(password, user.password, (err, isMatch) => {
          if (err) {
            throw err;
          }
          if (isMatch) {
            return done(null, user);
          } else {
            return done(null, false, { message: "Incorrect Password" });
          }
        });
      })
      .catch((err) => {
        console.log(err);
      });
  })
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  User.findById(id)
    .then((user) => {
      if (!user) {
        console.log("User not found");
        return;
      }
      console.log(`Found user: ${user.name}`);
    })
    .catch((error) => {
      console.error(`Error finding user: ${error.message}`);
    });
});

app.post("/api/users", (req, res) => {
  const { username, email, password, password2 } = req.body;

  let errors = [];

  if (!username || !email || !password || !password2) {
    errors.push({ msg: "Please fill in all fields" });
  }

  if (password !== password2) {
    errors.push({ msg: "Passwords do not match" });
  }

  if (password.length < 6) {
    errors.push({ msg: "Password should be at least 6 characters" });
  }

  const specialCharsRegex = /[ !@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/;
  if (!specialCharsRegex.test(password)) {
    errors.push({
      msg: "Password should contain at least one special characters",
    });
  }

  if (errors.length > 0) {
    res.send(errors);
  } else {
    User.findOne({ email: email }).then((user) => {
      if (user) {
        errors.push({ msg: "Email already exists" });
        res.send(errors);
      } else {
        const newUser = new User({
          username: username,
          email,
          password,
        });

        bcrypt.genSalt(10, (err, salt) => {
          if (err) {
            throw err;
          }
          bcrypt.hash(newUser.password, salt, (err, hash) => {
            if (err) {
              throw err;
            }
            newUser.password = hash;
            newUser
              .save()
              .then((user) => {
                res.send(user);
              })
              .catch((err) => {
                console.log(err);
              });
          });
        });
      }
    });
  }
});

app.post("/api/users/login", (req, res, next) => {
  var token;
  passport.authenticate("local", (err, user, info) => {
    if (err) {
      return next(err);
    }
    if (!user) {
      return res.status(401).send("Invalid email or password");
    }
    req.logIn(user, (err) => {
      if (err) {
        return next(err);
      }
      token = generateJwt(user);
      return res.send(token).status(200);
    });
  })(req, res, next);
});

app.get("/api/user", (req, res) => {
  console.log(req.header("Authorization"));
  const token = req.header("Authorization");

  if (!token) {
    return res.status(401).send("Authorization header missing");
  }
  console.log(token, "token");
  jwt.verify(token, process.env.SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).send("Invalid token");
    }
    console.log(decoded);
    const user = decoded;

    res.send(user);
  });
});

app.get("/users", (req, res) => {
  User.find()
    .then((users) => {
      res.send(users);
    })
    .catch((err) => {
      console.log(err);
    });
});

const PORT = process.env.PORT;

app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});
