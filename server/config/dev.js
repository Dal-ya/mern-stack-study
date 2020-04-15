const k = require('./k');

module.exports = {
  mongoURI: `mongodb+srv://${k.name}:${k.pwd}@bolierplate-nygly.gcp.mongodb.net/test?retryWrites=true&w=majority`
};
