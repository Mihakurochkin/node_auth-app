const { jwtService } = require('../services/jwt.service.js');

function authOnly(req, res, next) {
  const authorization = req.headers['authorization'] || '';
  const [, token] = authorization.split(' ');
  const refreshToken = req.cookies && req.cookies.refreshToken;

  let userData = null;

  if (token) {
    userData = jwtService.verify(token);
  } else if (refreshToken) {
    userData = jwtService.verifyRefresh(refreshToken);
  }

  if (!userData) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  next();
}

module.exports = { authOnly };
