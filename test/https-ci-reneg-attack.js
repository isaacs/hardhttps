// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

var PORT = 1337;
var spawn = require('child_process').spawn;
var hardhttps = require('../hardhttps.js');
var fs = require('fs');
var tap = require('tap')

// renegotiation limits to test
var LIMITS = [0, 1, 2, 3, 5, 10, 16];

if (process.platform === 'win32') {
  console.log('Skipping test, you probably don\'t have openssl installed.');
  process.exit();
}

LIMITS.forEach(function (LIMIT) {
  tap.test('test with limit=' + LIMIT, function (t) {
    hardhttps.CLIENT_RENEG_LIMIT = LIMIT;
    var options = {
      cert: fs.readFileSync(__dirname + '/fixtures/test_cert.pem'),
      key: fs.readFileSync(__dirname + '/fixtures/test_key.pem'),
      ca: []
    };

    var seenError = false;

    var server = hardhttps.createServer(options, function(req, res) {
      res.end('ok');
    });

    server.listen(PORT, function() {
      var args = ('s_client -connect 127.0.0.1:' + PORT).split(' ');
      var child = spawn('openssl', args);
      var renegAttempts = 0;

      child.stdout.pipe(process.stdout);
      child.stderr.pipe(process.stderr);

      // count handshakes, start the attack after the initial handshake is done
      var handshakes = 0;
      var renegs = 0;

      child.stderr.on('data', function(data) {
        if (seenError) return;
        handshakes += (('' + data).match(/verify return:1/g) || []).length;
        if (handshakes === 2) spam();
        renegs += (('' + data).match(/RENEGOTIATING/g) || []).length;
      });

      child.on('exit', function() {
        t.equal(renegs, hardhttps.CLIENT_RENEG_LIMIT + 1);
        server.close(t.end.bind(t));
      });

      var closed = false;
      child.stdin.on('error', function(err) {
        t.equal(err.code, 'EPIPE');
        closed = true;
      });
      child.stdin.on('close', function() {
        closed = true;
      });

      // simulate renegotiation attack
      function spam() {
        if (closed) return;
        if (renegAttempts === 100) {
          throw new Error('Reneg attack not defended');
        }
        renegAttempts++;
        child.stdin.write('R\n');
        setTimeout(spam, 50);
      }
    });
  })
})
