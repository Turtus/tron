/**
 * @author ksu.zhytomirsky@gmail.com
 */
const createHmac = require('create-hmac')

const createHmacPDFK2Sizes = {
    md5: 16,
    sha1: 20,
    sha224: 28,
    sha256: 32,
    sha384: 48,
    sha512: 64,
    rmd160: 20,
    ripemd160: 20
}

function pbkdf2(password, salt, iterations, keylen, digest) {

    digest = digest || 'sha1'

    const DK = Buffer.allocUnsafe(keylen)
    const block1 = Buffer.allocUnsafe(salt.length + 4)
    salt.copy(block1, 0, 0, salt.length)

    let destPos = 0
    const hLen = createHmacPDFK2Sizes[digest]
    const l = Math.ceil(keylen / hLen)

    for (let i = 1; i <= l; i++) {
        block1.writeUInt32BE(i, salt.length)

        // noinspection JSUnresolvedFunction
        const T = createHmac(digest, password).update(block1).digest()
        let U = T

        for (let j = 1; j < iterations; j++) {
            // noinspection JSUnresolvedFunction
            U = createHmac(digest, password).update(U).digest()
            for (let k = 0; k < hLen; k++) T[k] ^= U[k]
        }

        T.copy(DK, destPos)
        destPos += hLen
    }

    return DK
}

module.exports = {

    bip39MnemonicToSeed(mnemonic, password) {
        if (!mnemonic) {
            throw new Error('bip39MnemonicToSeed is empty')
        }

        function salt(password) {
            return 'mnemonic' + (password || '')
        }

        const mnemonicBuffer = Buffer.from((mnemonic || ''), 'utf8')
        const saltBuffer = Buffer.from(salt(password || ''), 'utf8')
        return pbkdf2(mnemonicBuffer, saltBuffer, 2048, 64, 'sha512')
    }
}