try {
    module.exports = require("bindings")("addon").Multi2;
} catch (err) {
    module.exports = require("./lib/multi2");
}
