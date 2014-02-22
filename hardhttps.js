var tls = require('tls')

// make these defaults a little stricter.
// one renegotiation allowed every 10 hours, instead of 3 every 10 minutes.
tls.CLIENT_RENEG_LIMIT = 1
tls.CLIENT_RENEG_WINDOW = 60 * 60 * 10

var https = require('https')

var hardhttps = module.exports = Object.create(https, {
  createServer: {
    value: createServer,
    configurable: true,
    enumerable: true,
    writable: true
  },
  CLIENT_RENEG_LIMIT: {
    get: function () { return tls.CLIENT_RENEG_LIMIT },
    set: function (s) { tls.CLIENT_RENEG_LIMIT = s },
    enumerable: true,
    configurable: true
  },
  CLIENT_RENEG_WINDOW: {
    get: function () { return tls.CLIENT_RENEG_WINDOW },
    set: function (s) { tls.CLIENT_RENEG_WINDOW = s },
    enumerable: true,
    configurable: true
  },
  ciphers: {
    value: 'ECDHE-RSA-AES256-SHA:AES256-SHA:' +
           'RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
    configurable: true,
    enumerable: true,
    writable: true
  },
  secureProtocol: {
    value: 'SSLv23_server_method',
    configurable: true,
    enumerable: true,
    writable: true
  },
  strictTimeout: {
    value: String(1000 * 60 * 60 * 24 * 365),
    configurable: true,
    enumerable: true,
    writable: true
  }
})

function createServer (options, listener) {
  if (!options || typeof options !== 'object') {
    throw new Error('options object required');
  }

  if (!Array.isArray(options.ca)) {
    throw new Error('options.ca list required.');
  }

  options.ciphers = hardhttps.ciphers
  options.secureProtocol = hardhttps.secureProtocol
  options.honorCipherOrder = true

  var server = https.createServer(options)

  // only https is allowed
  server.on('request', function (q, s) {
    s.setHeader('strict-transport-security',
                'max-age=' + hardhttps.strictTimeout)
    if (typeof listener === 'function')
      listener.call(this, q, s)
  })

  // TODO: This should be fixed for node 0.10 to be less awful.
  server.on('secureConnection', function (socket) {
    socket.on('error', function (er) {
      if (socket._httpMessage) {
        socket._httpMessage.emit('error', er)
      } else {
        socket.destroy()
      }
    })
  })

  return server
}
