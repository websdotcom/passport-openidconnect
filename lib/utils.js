var crypto = require('crypto');


/**
 * Reconstructs the original URL of the request.
 *
 * This function builds a URL that corresponds the original URL requested by the
 * client, including the protocol (http or https) and host.
 *
 * If the request passed through any proxies that terminate SSL, the
 * `X-Forwarded-Proto` header is used to detect if the request was encrypted to
 * the proxy.
 *
 * @return {String}
 * @api private
 */
exports.originalURL = function (req) {
  var headers = req.headers
    , protocol = (req.connection.encrypted || req.headers['x-forwarded-proto'] == 'https')
    ? 'https'
    : 'http'
    , host = headers.host
    , path = req.url || '';
  return protocol + '://' + host + path;
};

/**
 * Merge object b with object a.
 *
 *     var a = { foo: 'bar' }
 *       , b = { bar: 'baz' };
 *
 *     utils.merge(a, b);
 *     // => { foo: 'bar', bar: 'baz' }
 *
 * @param {Object} a
 * @param {Object} b
 * @return {Object}
 * @api private
 */

exports.merge = function (a, b) {
  if (a && b) {
    for (var key in b) {
      a[key] = b[key];
    }
  }
  return a;
};

/**
 * Return a unique identifier with the given `len`.
 *
 *     utils.uid(10);
 *     // => "FDaS435D2z"
 *
 * CREDIT: Connect -- utils.uid
 *         https://github.com/senchalabs/connect/blob/2.7.2/lib/utils.js
 *
 * @param {Number} len
 * @return {String}
 * @api private
 */

exports.uid = function (len) {
  return crypto.randomBytes(Math.ceil(len * 3 / 4))
    .toString('base64')
    .slice(0, len);
};

/**
 * Encrypt a value and return the base64 encoded string representaton
 *
 * @param {String} value
 * @param {String} password
 * @param {String} algorithm (Optional: Defaults to 'aes-256-ctr')
 * @return {String}
 * @api private
 */
exports.encrypt = function (value, password, algorithm) {
  algorithm = algorithm || 'aes-256-ctr';
  var cipher = crypto.createCipher(algorithm, password);
  var crypted = cipher.update(value, 'utf8', 'base64');
  crypted += cipher.final('base64');
  return crypted;
};

/**
 * Decrypt encrypted token and return value
 *
 * @param {String} token
 * @param {String} password
 * @param {String} algorithm (Optional: Defaults to 'aes-256-ctr')
 * @return {String}
 * @api private
 */
exports.decrypt = function (token, password, algorithm) {
  algorithm = algorithm || 'aes-256-ctr';
  var decipher = crypto.createDecipher(algorithm, password);
  var dec = decipher.update(token, 'base64', 'utf8');
  dec += decipher.final('utf8');
  return dec;
}
