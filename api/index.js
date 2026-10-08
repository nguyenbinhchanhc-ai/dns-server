const app = require('../server.js');

const handler = typeof app === 'function' 
  ? app 
  : (app.handler || ((req, res) => app.server.emit('request', req, res)));

module.exports = handler;

