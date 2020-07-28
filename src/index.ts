import * as assert from 'assert'
import * as brorand from 'brorand'
import * as hashjs from 'hash.js'
import * as elliptic from 'elliptic'

import * as addressCodec from 'brt-address-codec'
import { derivePrivateKey, accountPublicFromPublicGenerator } from './secp256k1'
import * as utils from './utils'

const Secp256k1 = elliptic.ec('secp256k1')

const { hexToBytes } = utils
const { bytesToHex } = utils

function generateSeed(
  options: {
    entropy?: Uint8Array
  } = {},
): string {
  assert(!options.entropy || options.entropy.length >= 16, 'entropy too short')
  const entropy = options.entropy ? options.entropy.slice(0, 16) : brorand(16)
  return addressCodec.encodeSeed(entropy)
}

function hash(message): number[] {
  return hashjs.sha512().update(message).digest().slice(0, 32)
}

const secp256k1 = {
  deriveKeypair(
    entropy: Uint8Array,
    options?: object,
  ): {
    privateKey: string
    publicKey: string
  } {
    const prefix = '00'

    const privateKey =
      prefix + derivePrivateKey(entropy, options).toString(16, 64).toUpperCase()

    const publicKey = bytesToHex(
      Secp256k1.keyFromPrivate(privateKey.slice(2))
        .getPublic()
        .encodeCompressed(),
    )
    return { privateKey, publicKey }
  },

  sign(message, privateKey): string {
    return bytesToHex(
      Secp256k1.sign(hash(message), hexToBytes(privateKey), {
        canonical: true,
      }).toDER(),
    )
  },

  verify(message, signature, publicKey): boolean {
    return Secp256k1.verify(hash(message), signature, hexToBytes(publicKey))
  },
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function select(algorithm): any {
  const methods = { 'ecdsa-secp256k1': secp256k1 }
  return methods[algorithm]
}

function deriveKeypair(
  seed: string,
  options?: object,
): {
  publicKey: string
  privateKey: string
} {
  const decoded = addressCodec.decodeSeed(seed)
  const algorithm = 'ecdsa-secp256k1'
  const method = select(algorithm)
  const keypair = method.deriveKeypair(decoded.bytes, options)
  const messageToVerify = hash('This test message should verify.')
  const signature = method.sign(messageToVerify, keypair.privateKey)
  /* istanbul ignore if */
  if (method.verify(messageToVerify, signature, keypair.publicKey) !== true) {
    throw new Error('derived keypair did not generate verifiable signature')
  }
  return keypair
}

function sign(messageHex, privateKey): string {
  const algorithm = 'ecdsa-secp256k1'
  return select(algorithm).sign(hexToBytes(messageHex), privateKey)
}

function verify(messageHex, signature, publicKey): boolean {
  const algorithm = 'ecdsa-secp256k1'
  return select(algorithm).verify(hexToBytes(messageHex), signature, publicKey)
}

function deriveAddressFromBytes(publicKeyBytes: Buffer): string {
  return addressCodec.encodeAccountID(
    utils.computePublicKeyHash(publicKeyBytes),
  )
}

function deriveAddress(publicKey): string {
  return deriveAddressFromBytes(Buffer.from(hexToBytes(publicKey)))
}

function deriveNodeAddress(publicKey): string {
  const generatorBytes = addressCodec.decodeNodePublic(publicKey)
  const accountPublicBytes = accountPublicFromPublicGenerator(generatorBytes)
  return deriveAddressFromBytes(accountPublicBytes)
}

const { decodeSeed } = addressCodec

export = {
  generateSeed,
  deriveKeypair,
  sign,
  verify,
  deriveAddress,
  deriveNodeAddress,
  decodeSeed,
}
