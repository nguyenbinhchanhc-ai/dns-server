const { handleProfileRequest } = require('../server.js');

module.exports = (req, res) => {
  return handleProfileRequest(req, res);
};
