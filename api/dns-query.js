const { handleDoHRequest } = require('../server.js');

module.exports = async (req, res) => {
  return handleDoHRequest(req, res);
};

module.exports.config = {
  api: {
    bodyParser: false,
  },
};
