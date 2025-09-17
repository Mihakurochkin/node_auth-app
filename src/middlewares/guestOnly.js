const { jwtService } = require('../services/jwt.service');

function guestOnly(req, res, next) {
  const authorization = req.headers['authorization'] || '';
  const [, token] = authorization.split(' ');
  const refreshToken = req.cookies && req.cookies.refreshToken;

  let userData = null;

  if (token) {
    userData = jwtService.verify(token);
  } else if (refreshToken) {
    userData = jwtService.verifyRefresh(refreshToken);
  }

  if (userData) {
    return res.status(403).json({ message: 'Already authenticated' });
  }

  next();
}

module.exports = { guestOnly };
