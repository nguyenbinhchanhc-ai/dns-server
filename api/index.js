const { handler } = require('../server.js');

module.exports = handler;

module.exports.config = {
  api: {
    bodyParser: false,
  },
};
