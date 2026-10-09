const { handleStressTestRequest } = require('../server.js');

module.exports = (req, res) => {
  return handleStressTestRequest(req, res);
};
