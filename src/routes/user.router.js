const { router } = require('../app');
const { getAll, create, getOne, remove, update, verifyUser, login, logged} = require('../controllers/user.controllers');
const express = require('express');
const jwt = require('jsonwebtoken');
const verifyJWT = require('../utils/verifyJWT');

const verifyJwt = (req, res, next) => {
  const authHeader = req.headers.authorization || req.headers.Authorization;
  if (!authHeader?.startsWith('Bearer ')) return res.sendStatus(401);
  const token = authHeader.split(' ')[1];
  jwt.verify(
      token,
      process.env.TOKEN_SECRET,
      (err, decoded) => {
          if (err) return res.sendStatus(403);
          req.user = decoded.user;
          next();
      }
  )
}

module.exports = {verifyJwt};

const routerUser = express.Router();

routerUser.route('/')
  .get(verifyJWT, getAll)
  .post(create);

routerUser.route('/login')
  .post(login)

  routerUser.route('/me')
  .get(verifyJWT, logged)

//dynamic routes
routerUser.route("/verify/:code")
  .get(verifyUser)

  


routerUser.route('/:id')
  .get(verifyJWT, getOne)
  .delete(verifyJWT, remove)
  .put(verifyJWT, update);

module.exports = routerUser;