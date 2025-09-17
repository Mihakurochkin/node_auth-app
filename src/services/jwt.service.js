const jwt = require('jsonwebtoken');

function sign(user) {
  const token = jwt.sign(user, process.env.JWT_KEY, {
    expiresIn: '5s',
  });

  return token;
}

function verify(token) {
  try {
    return jwt.verify(token, process.env.JWT_KEY);
  } catch {
    return null;
  }
}

function signRefresh(user) {
  const token = jwt.sign(user, process.env.JWT_REFRECH_KEY);

  return token;
}

function verifyRefresh(token) {
  try {
    return jwt.verify(token, process.env.JWT_REFRECH_KEY);
  } catch {
    return null;
  }
}

const jwtService = {
  sign,
  verify,
  signRefresh,
  verifyRefresh,
};

module.exports = { jwtService };
