// Golden-path fixture app. lodash 4.17.20 carries CVE-2021-23337 (fixed in 4.17.21).
const _ = require("lodash");

module.exports = { greeting: _.template("hello <%= name %>")({ name: "scrutineering" }) };

if (require.main === module) {
  console.log(module.exports.greeting);
}
