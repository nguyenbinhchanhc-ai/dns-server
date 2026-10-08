const { handleTestDoHRequest } = require('../server.js');

module.exports = async (req, res) => {
  return handleTestDoHRequest(req, res);
};
