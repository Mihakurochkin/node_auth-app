const { User } = require('../models/User.js');
const { userService } = require('../services/user.service.js');
const { jwtService } = require('../services/jwt.service.js');
const { ApiError } = require('../exeptions/api.error.js');
const bcrypt = require('bcrypt');
const { tokenService } = require('../services/token.service.js');

const validateEmail = (value) => {
  if (typeof value !== 'string') {
    return 'Email must be a string';
  }

  const trimmedValue = value.trim();

  if (!trimmedValue) {
    return 'Email is required';
  }

  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  if (!emailPattern.test(trimmedValue)) {
    return 'Email is not valid';
  }
};

const validatePassword = (value) => {
  if (typeof value !== 'string') {
    return 'Password must be a string';
  }

  const trimmedValue = value.trim();

  if (!trimmedValue) {
    return 'Password is required';
  }

  if (trimmedValue.length < 6) {
    return 'Password must be at least 6 characters';
  }
};

const generateTokens = async (res, user) => {
  const normalizedUser = userService.normalize(user);
  const accessToken = jwtService.sign(normalizedUser);
  const refreshToken = jwtService.signRefresh(normalizedUser);

  await tokenService.save(normalizedUser, refreshToken);

  res.cookie('refreshToken', refreshToken, {
    maxAge: 30 * 24 * 60 * 60 * 1000,
    HttpOnly: true,
  });

  res.send({
    user: normalizedUser,
    accessToken,
  });
};

const register = async (req, res) => {
  const { email, password } = req.body;
  const errors = {
    email: validateEmail(email),
    password: validatePassword(password),
  };

  if (errors.email || errors.password) {
    throw ApiError.badRequest('Bad request', errors);
  }

  const hashedPass = await bcrypt.hash(password, 10);

  await userService.register(email, hashedPass);
  res.send({ message: 'OK' });
};

const activate = async (req, res) => {
  const { activationToken } = req.params;
  const user = await User.findOne({ where: { activationToken } });

  if (!user) {
    res.sendStatus(404);

    return;
  }

  user.activationToken = null;
  user.save();

  res.send(user);
};

const login = async (req, res) => {
  const { email, password } = req.body;

  const user = await userService.findByEmail(email);

  if (!user) {
    throw ApiError.badRequest('No such user');
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);

  if (!isPasswordValid) {
    throw ApiError.badRequest('Wrong password');
  }

  await generateTokens(res, user);
};

const refresh = async (req, res) => {
  const { refreshToken } = req.cookies;

  const userData = jwtService.verifyRefresh(refreshToken);
  const token = await tokenService.getByToken(refreshToken);

  if (!userData || !token) {
    throw ApiError.unauthorized();
  }

  const user = await userService.findByEmail(userData.email);

  await generateTokens(res, user);
};

const logout = async (req, res) => {
  const { refreshToken } = req.cookies;
  const userData = await jwtService.verifyRefresh(refreshToken);

  if (!userData || !refreshToken) {
    throw ApiError.unauthorized();
  }
  await tokenService.remove(userData.d);

  res.sendStatus(204);
};

module.exports = {
  validateEmail,
  validatePassword,
  authController: {
    register,
    activate,
    login,
    refresh,
    logout,
  },
};
