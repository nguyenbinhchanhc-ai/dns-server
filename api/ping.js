const { handlePingRequest } = require('../server.js');

module.exports = (req, res) => {
  return handlePingRequest(req, res);
};
