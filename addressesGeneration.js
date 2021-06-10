/**
 * @author ksu.zhytomirsky@gmail.com
 * check if needed https://iancoleman.io/bip39/
 */
const bip32 = require('bip32')

const BipUtils = require('./libs/BipUtils')
const TronUtils = require('./libs/TronUtils')



const MNEMONIC = 'earn bike cream conduct female jelly burger talent warm oppose divert echo achieve syrup struggle'
const HOW_MUCH_ADDRESSES_IS_NEEDED = 3

const seed = BipUtils.bip39MnemonicToSeed(MNEMONIC) // seed could be preset as hex and no need for decoding from mnemonic
const root =  bip32.fromSeed(seed)

for (let index = 0; index < HOW_MUCH_ADDRESSES_IS_NEEDED; index++) {

    const path = `m/44'/195'/0'/0/${index}`

    const child = root.derivePath(path)
    const privateKey = child.privateKey
    const publicKey = child.publicKey

    const pubKey = TronUtils.privHexToPubHex(privateKey)
    const addressHex = TronUtils.pubHexToAddressHex(pubKey)
    const address = TronUtils.addressHexToStr(addressHex)

    console.log(` private : ${privateKey.toString('hex')}  address : ${address}`)
}

