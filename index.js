const {
    sha256
} = require('@noble/hashes/sha256')
const {
    ripemd160
} = require('@noble/hashes/ripemd160')
const {
    base64, utf8, bech32
} = require('@scure/base')
const secp256k1 = require('@noble/secp256k1')

function serializeSignDoc(doc) {
    function sortObjectByKey(obj) {
        if (typeof obj !== 'object' || obj == null) {
            return obj
        }
        if (Array.isArray(obj)) {
            return obj.map(sortObjectByKey)
        }
        const sortedKeys = Object.keys(obj).sort()
        const result = {
        }
        sortedKeys.forEach((key) => {
            result[key] = sortObjectByKey(obj[key])
        })
        return result
    }

    function escapeHtml(str) {
        return str
            .replace(/</g, '\\u003c')
            .replace(/>/g, '\\u003e')
            .replace(/&/g, '\\u0026')
    }

    return utf8.decode(escapeHtml(JSON.stringify(sortObjectByKey(doc))))
}

function verifyECDSA({
    pubKey, data, signature
}) {
    return secp256k1.verify(
        signature,
        sha256(data),
        pubKey
    )
}

function resolveBech32Address(
    publicKey
){
    const address = ripemd160(sha256(publicKey))
    return bech32.encode('terra', bech32.toWords(address))
}

function verifyADR36({
    pubKey, data, signature
}) {

    const msg = serializeSignDoc({
        chain_id: '',
        account_number: '0',
        sequence: '0',
        fee: {
            gas: '0',
            amount: [],
        },
        msgs: [
            {
                type: 'sign/MsgSignData',
                value: {
                    signer: resolveBech32Address(pubKey),
                    data: base64.encode(data)
                },
            },
        ],
        memo: '',
    })
    return verifyECDSA({
        pubKey,
        data: msg,
        signature
    })
}

let result = verifyADR36({
    pubKey:  base64.decode('AoHNk8wJt6mpdSi1XJnUY9OzWkgu3D5QYdhBdyEX6Y+L'),
    data: utf8.decode('Sign this message to login'),
    signature: base64.decode('OPphfghaBJC3tGNEqwuaG6+RM+uCyW8ozFiu1rw6KjQOpJldWwYut7v/5Ji5VjON6kn8aaOjCJcfzWuDFUcD3Q==')
})

console.log(result)
