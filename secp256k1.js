const secp256k1 = require('secp256k1')
const sodium = require('sodium-native')
const keccak = require('keccak')

function keccak256 (message) {
  return keccak('keccak256').update(message).digest()
}

function randomBytes (len, seed) {
  var rb = Buffer.alloc(len)
  sodium.randombytes_buf(rb)
  return rb
}

// This gives us methods of the same form as nacl
// for use with ssb-keys

exports.curves = ['secp256k1']

exports.generateKeys =
exports.generate = function (seed) {
  let secretKey

  if (seed) {
    secretKey = Buffer.alloc(32)
    // keeping this is under debate
    sodium.randombytes_buf_deterministic(secretKey, seed)

    while (!secp256k1.privateKeyVerify(secretKey)) {
      secretKey = secp256k1.privateKeyTweakAdd(secretKey, seed)
    }
  } else {
    do {
      secretKey = randomBytes(32)
    } while (!secp256k1.privateKeyVerify(secretKey))
  }

  // public key is given in short form
  return {
    curve: 'secp256k1',
    private: secretKey,
    public: secp256k1.publicKeyCreate(secretKey)
  }
}

exports.sign = function (secretKey, message) {
  const hash = keccak256(message)
  // arguments are the other way around
  return secp256k1.sign(hash, secretKey).signature
}

exports.verify = function (publicKey, signature, message) {
  const hash = keccak256(message)
  // arguments are the other way around
  return secp256k1.verify(hash, signature, publicKey)
}
