# hardhttps

Make an https server that is more resistant to client-initiated
renegotiations, and other common security mistakes.

Not quite an A+ yet, but getting there.

## Usage

```javascript
var https = require('hardhttps')
https.createServer(options, handler)
```

The API is exactly the same as the built-in https module, but
`createServer` is a little bit tweaked:

1. If the secureConnection socket has an error, then it is destroyed.
2. Only the finest TLS ciphers are used.
