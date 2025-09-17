const { ApiError } = require('../exeptions/api.error');
const { User } = require('../models/User');
const { emailService } = require('../services/email.service.js');
const { v4: uuidv4 } = require('uuid');

function normalize({ id, email }) {
  return { id, email };
}

function findByEmail(email) {
  return User.findOne({ where: { email } });
}

async function register(email, password) {
  const activationToken = uuidv4();
  const existUser = await findByEmail(email);

  if (existUser) {
    throw ApiError.badRequest('User already exist', {
      email: 'User already exists',
    });
  }

  await User.create({ email, password, activationToken });

  await emailService.sendActivationEmail(email, activationToken);
}

const userService = {
  normalize,
  findByEmail,
  register,
};

module.exports = { userService };
