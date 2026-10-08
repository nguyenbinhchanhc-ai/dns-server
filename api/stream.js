const { handleStreamRequest } = require('../server.js');

module.exports = (req, res) => {
  return handleStreamRequest(req, res);
};
