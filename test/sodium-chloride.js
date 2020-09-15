const Z = (n) => Buffer.alloc(n);

module.exports = function (na) {
  var exports = {};

  // *** Signatures ***

  exports.crypto_sign_seed_keypair = function (seed) {
    var pk = Z(na.crypto_sign_PUBLICKEYBYTES);
    var sk = Z(na.crypto_sign_SECRETKEYBYTES);
    na.crypto_sign_seed_keypair(pk, sk, seed);
    return { publicKey: pk, privateKey: sk };
  };

  exports.crypto_sign_keypair = function () {
    var pk = Z(na.crypto_sign_PUBLICKEYBYTES);
    var sk = Z(na.crypto_sign_SECRETKEYBYTES);
    na.crypto_sign_keypair(pk, sk);
    return { publicKey: pk, privateKey: sk };
  };

  exports.crypto_sign = function (message, sk) {
    var signed = Z(message.length + na.crypto_sign_BYTES);
    na.crypto_sign(signed, Buffer.from(message), sk);
    return signed;
  };

  exports.crypto_sign_open = function (signed, pk) {
    var message = Z(signed.length - na.crypto_sign_BYTES);
    if (na.crypto_sign_open(message, signed, pk)) return message;
  };

  exports.crypto_sign_detached = function (message, sk) {
    var signed = Z(na.crypto_sign_BYTES);
    na.crypto_sign_detached(signed, Buffer.from(message), sk);
    return signed;
  };

  exports.crypto_sign_verify_detached = function (sig, msg, pk) {
    return na.crypto_sign_verify_detached(sig, Buffer.from(msg), pk);
  };
  // *** Box ***

  exports.crypto_box_seed_keypair = function (seed) {
    var pk = Z(na.crypto_box_PUBLICKEYBYTES);
    var sk = Z(na.crypto_box_SECRETKEYBYTES);
    na.crypto_box_seed_keypair(pk, sk, seed);
    return { publicKey: pk, privateKey: sk };
  };

  exports.crypto_box_keypair = function () {
    var pk = Z(na.crypto_box_PUBLICKEYBYTES);
    var sk = Z(na.crypto_box_SECRETKEYBYTES);
    na.crypto_box_keypair(pk, sk);
    return {
      publicKey: pk,
      privateKey: sk,
    };
  };

  exports.crypto_box_easy = function (ptxt, nonce, pk, sk) {
    var ctxt = Z(ptxt.length + na.crypto_box_MACBYTES);
    na.crypto_box_easy(ctxt, Buffer.from(ptxt), nonce, pk, sk);
    return ctxt;
  };

  exports.crypto_box_open_easy = function (ctxt, nonce, pk, sk) {
    var ptxt = Z(ctxt.length - na.crypto_box_MACBYTES);
    if (na.crypto_box_open_easy(ptxt, ctxt, nonce, pk, sk)) return ptxt;
  };

  // *** SecretBox ***

  exports.crypto_secretbox_easy = function (ptxt, nonce, key) {
    var ctxt = Z(ptxt.length + na.crypto_secretbox_MACBYTES);
    na.crypto_secretbox_easy(ctxt, ptxt, nonce, key);
    return ctxt;
  };

  exports.crypto_secretbox_open_easy = function (ctxt, nonce, key) {
    var ptxt = Z(ctxt.length - na.crypto_secretbox_MACBYTES);
    if (na.crypto_secretbox_open_easy(ptxt, ctxt, nonce, key)) return ptxt;
  };

  // *** Auth (hmac) ***

  exports.crypto_auth = function (input, key) {
    var output = Z(na.crypto_auth_BYTES);
    na.crypto_auth(output, input, key);
    return output;
  };

  exports.crypto_auth_verify = function (output, input, key) {
    return na.crypto_auth_verify(output, input, key) ? 0 : 1;
  };
  // *** Hash (sha512)

  exports.crypto_hash = function (ptxt) {
    var hash = Z(na.crypto_hash_BYTES);
    na.crypto_hash_sha512(hash, ptxt);
    return hash;
  };

  exports.crypto_hash_sha256 = function (ptxt) {
    var hash = Z(na.crypto_hash_sha256_BYTES);
    na.crypto_hash_sha256(hash, ptxt);
    return hash;
  };

  // *** scalarmult ***

  exports.crypto_scalarmult = function (sk, pk) {
    var secret = Z(na.crypto_scalarmult_BYTES);
    na.crypto_scalarmult(secret, sk, pk);
    return secret;
  };

  // *** Conversions ***

  exports.crypto_sign_ed25519_pk_to_curve25519 = function (ed_pk) {
    var curve_pk = Z(na.crypto_box_PUBLICKEYBYTES);
    try {
      //in chloridedown, it just returns something no matter what
      //but in sodium-native it throws if you try to convert
      //a random buffer, that isn't a pk.
      na.crypto_sign_ed25519_pk_to_curve25519(curve_pk, ed_pk);
    } catch (err) {
      return null;
    }
    return curve_pk;
  };

  exports.crypto_sign_ed25519_sk_to_curve25519 = function (ed_sk) {
    var curve_sk = Z(na.crypto_box_SECRETKEYBYTES);
    na.crypto_sign_ed25519_sk_to_curve25519(curve_sk, ed_sk);
    return curve_sk;
  };

  // *** Randomness **

  exports.randombytes_buf = function (length) {
    const out = Z(length);
    na.randombytes_buf(out);
    return out;
  };

  exports.crypto_aead_xchacha20poly1305_ietf_encrypt = function (
    m,
    ad,
    literallyNull,
    npub,
    k
  ) {
    const c = Z(m.length + na.crypto_aead_xchacha20poly1305_ietf_ABYTES);
    na.crypto_aead_xchacha20poly1305_ietf_encrypt(
      c,
      m,
      ad,
      literallyNull,
      npub,
      k
    );
    return c;
  };

  exports.crypto_aead_xchacha20poly1305_ietf_decrypt = function (
    literallyNull,
    ciphertext,
    ad,
    npub,
    k
  ) {
    const out = Z(
      ciphertext.byteLength - na.crypto_aead_xchacha20poly1305_ietf_ABYTES
    );
    na.crypto_aead_xchacha20poly1305_ietf_decrypt(
      out,
      literallyNull,
      ciphertext,
      ad,
      npub,
      k
    );
    return out;
  };

  exports.crypto_aead_xchacha20poly1305_ietf_keygen = function () {
    const out = Z(na.crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    na.crypto_aead_xchacha20poly1305_ietf_keygen(out);
    return out;
  };

  exports.crypto_kdf_derive_from_key = function (
    subkeyLength,
    subkeyId,
    ctx,
    key
  ) {
    const subkey = Z(subkeyLength);
    na.crypto_kdf_derive_from_key(subkey, subkeyId, Buffer.from(ctx), key);
    return subkey;
  };

  exports.crypto_auth_keygen = function () {
    const out = Z(na.crypto_auth_KEYBYTES);
    na.crypto_auth_keygen(out);
    return out;
  };

  exports.pad = function (buf, blockSize) {
    const size = Math.ceil((buf.byteLength + 1) / blockSize) * blockSize;
    const out = Buffer.alloc(size);
    out.set(buf);
    const index = na.sodium_pad(out, buf.byteLength, blockSize);
    return out;
  };

  exports.unpad = function (buf, blockSize) {
    const size = na.sodium_unpad(buf, buf.byteLength, blockSize);
    return buf.slice(0, size);
  };

  exports.crypto_shorthash = function (input, k) {
    const out = Z(na.crypto_shorthash_BYTES);
    na.crypto_shorthash(out, Buffer.from(input), k);
    return out;
  };

  exports.crypto_pwhash = function (
    length,
    passwd,
    salt,
    opslimit,
    memlimit,
    alg
  ) {
    const out = Z(length);
    na.crypto_pwhash(out, Buffer.from(passwd), salt, opslimit, memlimit, alg);
    return out;
  };

  exports.crypto_scalarmult_base = function (sk) {
    const out = Z(na.crypto_box_PUBLICKEYBYTES);
    na.crypto_scalarmult_base(out, Buffer.from(sk));
    return out;
  };

  exports.crypto_pwhash_str = function (passwd, opslimit, memlimit) {
    const out = Z(na.crypto_pwhash_STRBYTES);
    na.crypto_pwhash_str(out, Buffer.from(passwd), opslimit, memlimit);
    return out;
  };

  exports.crypto_pwhash_str_verify = function (hash, passwd) {
    return na.crypto_pwhash_str_verify(hash, Buffer.from(passwd));
  };

  exports.crypto_kx_keypair = function () {
    const publicKey = Z(na.crypto_kx_PUBLICKEYBYTES);
    const privateKey = Z(na.crypto_kx_SECRETKEYBYTES);
    na.crypto_kx_keypair(publicKey, privateKey);
    return { publicKey, privateKey };
  };
  exports.crypto_generichash = function (size, input) {
    const out = Z(size);
    na.crypto_generichash(out, Buffer.from(input));
    return out;
  };
  exports.crypto_kx_seed_keypair = function (seed) {
    const publicKey = Z(na.crypto_kx_PUBLICKEYBYTES);
    const privateKey = Z(na.crypto_kx_SECRETKEYBYTES);
    na.crypto_kx_seed_keypair(publicKey, privateKey, seed);
    return { publicKey, privateKey };
  };
  exports.crypto_kx_client_session_keys = function (
    clientPublic,
    clientSecret,
    serverPublic
  ) {
    const sharedRx = Z(na.crypto_kx_SESSIONKEYBYTES);
    const sharedTx = Z(na.crypto_kx_SESSIONKEYBYTES);
    na.crypto_kx_client_session_keys(
      sharedRx,
      sharedTx,
      clientPublic,
      clientSecret,
      serverPublic
    );
    return { sharedRx, sharedTx };
  };

  exports.crypto_kx_server_session_keys = function (
    serverPublic,
    serverSecret,
    clientPublic
  ) {
    const sharedRx = Z(na.crypto_kx_SESSIONKEYBYTES);
    const sharedTx = Z(na.crypto_kx_SESSIONKEYBYTES);
    na.crypto_kx_server_session_keys(
      sharedRx,
      sharedTx,
      serverPublic,
      serverSecret,
      clientPublic
    );
    return { sharedRx, sharedTx };
  };

  exports.crypto_kdf_keygen = function () {
    const out = Z(na.crypto_kdf_KEYBYTES);
    na.crypto_kdf_keygen(out);
    return out;
  };

  exports.add = na.sodium_add;
  exports.compare = na.sodium_compare;
  exports.crypto_pwhash_str_needs_rehash = na.crypto_pwhash_str_needs_rehash;
  exports.increment = na.sodium_increment;
  exports.is_zero = na.sodium_is_zero;
  exports.memcmp = na.sodium_memcmp;
  exports.memzero = na.sodium_memzero;
  exports.randombytes_uniform = na.randombytes_uniform;

  exports.crypto_box_seal = function (m, pk) {
    const buf = Buffer.from(m);
    const out = Z(buf.byteLength + na.crypto_box_SEALBYTES);
    na.crypto_box_seal(out, buf, pk);
    return out;
  };

  exports.crypto_box_seal_open = function (input, pk, sk) {
    const buf = Buffer.from(input);
    const out = Z(buf.byteLength - na.crypto_box_SEALBYTES);
    na.crypto_box_seal_open(out, buf, pk, sk);
    return out;
  };
  exports.crypto_generichash_init = function (key, outlen) {
    const state = Z(na.crypto_generichash_STATEBYTES);
    na.crypto_generichash_init(state, key, outlen);
    return state;
  };
  exports.crypto_generichash_update = function (state, input) {
    na.crypto_generichash_update(state, Buffer.from(input));
    return state;
  };

  exports.crypto_generichash_final = function (state, outlen) {
    const out = Z(outlen);
    na.crypto_generichash_final(state, out);
    return out;
  };

  // TODO: Implement
  exports.crypto_auth_keygen = na.crypto_auth_keygen;
  exports.crypto_secretbox_keygen = na.crypto_secretbox_keygen;
  exports.crypto_generichash_keygen = na.crypto_generichash_keygen;

  return exports;
};
