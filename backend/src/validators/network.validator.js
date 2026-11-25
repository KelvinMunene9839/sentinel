const domainValidator = require('./domain.validator');
const ipValidator = require('./ip.validator');
const cveValidator = require('./cve.validator');

module.exports = {
  ...domainValidator,
  ...ipValidator,
  ...cveValidator,
};
