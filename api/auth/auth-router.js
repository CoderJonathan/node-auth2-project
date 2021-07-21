const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const bcrypt = require('bcryptjs')
const Users = require('../users/users-model');
const { default: jwtDecode } = require("jwt-decode");

router.post("/register", validateRoleName, (req, res, next) => {
  const {username, password, role_name} = req.body
    const hash = bcrypt.hashSync(password, 8)
  
    const trimmedRole = role_name.trim()
    Users.add({username, password: hash, role_name: trimmedRole})
    .then(user => {
      res.status(201).json(user)
    })
    .catch(next)
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
});


router.post("/login", checkUsernameExists, (req, res, next) => { //eslint-disable-line
  let {username, password} = req.body

  Users.findBy({username})
  .then(([user]) => {
    if (user && bcrypt.compareSync(password, user.password)) {
      const token = buildToken(user)
      res.status(200).json({
        message: `${user.username} is back!`,
        token
      })
    } else {
      res.status(401).json({
        message: `Invalid credentials`
      })
    }
  })
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});

function buildToken(u) {
  const payload = {
    subject: u.user_id,
    role_name: u.role_name,
    username: u.username,
  }
  const options = {
    expiresIn: '1d',
  }
  return jwtDecode(payload, JWT_SECRET, options)
} 

module.exports = router;
