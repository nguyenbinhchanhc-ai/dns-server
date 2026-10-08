const { handleStatsRequest } = require('../server.js');

module.exports = (req, res) => {
  return handleStatsRequest(req, res);
};
