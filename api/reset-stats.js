const { handleResetStatsRequest } = require('../server.js');

module.exports = (req, res) => {
  return handleResetStatsRequest(req, res);
};
