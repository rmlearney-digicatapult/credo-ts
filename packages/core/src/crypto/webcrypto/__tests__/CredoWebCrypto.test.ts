import { p256, p384, p521 } from '@noble/curves/nist.js'
import { afterEach, vi } from 'vitest'
import { getAgentConfig, getAgentContext } from '../../../../tests'
import { KeyManagementApi, KeyManagementError, PublicJwk } from '../../../modules/kms'
import { Hasher } from '../../hashes'
import { CredoWalletWebCrypto } from '../CredoWalletWebCrypto'
import { CredoWebCrypto } from '../CredoWebCrypto'
import { CredoWebCryptoKey } from '../CredoWebCryptoKey'
import type { KeyGenAlgorithm, KeySignParams, KeyVerifyParams } from '../types'

const algorithmToTestName = (algorithm: Record<string, unknown> | string) =>
  typeof algorithm === 'string' ? algorithm : `${algorithm.name} - ${algorithm.namedCurve} - ${algorithm.hash}`

describe('CredoWebCrypto', () => {
  let webCrypto: CredoWebCrypto
  let walletWebCrypto: CredoWalletWebCrypto
  let agentContext: ReturnType<typeof getAgentContext>

  const supportedAlgorithms: Array<Partial<KeyGenAlgorithm & KeySignParams>> = [
    { hash: 'SHA-256', name: 'ECDSA', namedCurve: 'P-256' },
    { hash: 'SHA-384', name: 'ECDSA', namedCurve: 'P-384' },
    { hash: 'SHA-512', name: 'ECDSA', namedCurve: 'P-521' },
    { hash: 'SHA-256', name: 'ECDSA', namedCurve: 'K-256' },
    { name: 'Ed25519' },
  ]

  beforeAll(async () => {
    agentContext = getAgentContext({
      agentConfig: getAgentConfig('X509Service'),
    })

    webCrypto = new CredoWebCrypto(agentContext)
    walletWebCrypto = new CredoWalletWebCrypto(agentContext)
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('Generate random values', async () => {
    expect(webCrypto.getRandomValues(null)).toBeNull()
    expect(webCrypto.getRandomValues(new Uint8Array(100)).length).not.toStrictEqual(0)
    expect(webCrypto.getRandomValues(new Uint8Array(100)).every((v) => v === 0)).toBeFalsy()
  })

  describe('key creation', () => {
    supportedAlgorithms.forEach((algorithm) => {
      it(`should create key with: ${algorithmToTestName(algorithm)}`, async () => {
        await expect(webCrypto.subtle.generateKey(algorithm, true, ['sign', 'verify'])).resolves.toBeDefined()
      })
    })
  })

  describe('key signing', () => {
    supportedAlgorithms.forEach((algorithm) => {
      it(`should create signature with: ${algorithmToTestName(algorithm)}`, async () => {
        const message = new Uint8Array(10).fill(10)
        const key = await webCrypto.subtle.generateKey(algorithm, true, ['sign', 'verify'])

        const signature = await webCrypto.subtle.sign(algorithm, key.privateKey, message)
        expect(signature).toBeTruthy()
      })
    })

    it('selects the signing backend for the key before signing', async () => {
      const algorithm = { name: 'ECDSA', hash: 'SHA-256' } as const satisfies KeySignParams
      const message = new Uint8Array(10).fill(10)
      const key = await webCrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
      const kms = agentContext.resolve(KeyManagementApi)
      const selectSignatureAlgorithm = vi.spyOn(kms, 'selectSignatureAlgorithm')
      const sign = vi.spyOn(kms, 'sign')

      await expect(walletWebCrypto.sign(key.privateKey, message, algorithm)).resolves.toBeInstanceOf(Uint8Array)

      expect(selectSignatureAlgorithm).toHaveBeenCalledWith({
        key: {
          publicJwk: key.privateKey.publicJwk,
          kmsKeyId: key.privateKey.publicJwk.keyId,
          allowLegacyKeyId: false,
        },
        candidates: ['ES256'],
      })
      const signingSelection = await selectSignatureAlgorithm.mock.results[0].value
      expect(sign).toHaveBeenCalledWith({
        keyId: signingSelection.keyId,
        data: message,
        algorithm: signingSelection.algorithm,
        backend: signingSelection.backend,
      })
    })
  })

  describe('signature verification', () => {
    supportedAlgorithms.forEach((algorithm) => {
      it(`should verify signature with: ${algorithmToTestName(algorithm)}`, async () => {
        const message = new Uint8Array(10).fill(10)
        const key = await webCrypto.subtle.generateKey(algorithm, true, ['sign', 'verify'])
        const signature = await webCrypto.subtle.sign(algorithm, key.privateKey, message)

        const isValid = await webCrypto.subtle.verify(algorithm, key.publicKey, signature, message)

        expect(isValid).toBeTruthy()
      })
    })

    it('uses the backend selected by capability discovery', async () => {
      const algorithm = { name: 'ECDSA', hash: 'SHA-256' } as const satisfies KeyVerifyParams
      const message = new Uint8Array(10).fill(10)
      const key = await webCrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
      const signature = await webCrypto.subtle.sign(algorithm, key.privateKey, message)
      const kms = agentContext.resolve(KeyManagementApi)
      const canPerform = vi.spyOn(kms, 'canPerform')
      const verify = vi.spyOn(kms, 'verify')

      await expect(walletWebCrypto.verify(key.publicKey, algorithm, message, new Uint8Array(signature))).resolves.toBe(
        true
      )

      expect(canPerform).toHaveBeenCalledWith({ operation: 'verify', algorithm: 'ES256' })
      const capability = await canPerform.mock.results[0].value
      expect(verify).toHaveBeenCalledWith(
        expect.objectContaining({
          backend: capability.backend,
          key: { publicJwk: key.publicKey.publicJwk.toJson() },
        })
      )
    })

    it.each([
      ['P-256', 'SHA-384'],
      ['P-256', 'SHA-512'],
      ['P-384', 'SHA-256'],
      ['P-384', 'SHA-512'],
      ['P-521', 'SHA-256'],
      ['P-521', 'SHA-384'],
    ] as const)('uses local Noble verification for non-standard ECDSA %s/%s', async (curve, hash) => {
      const algorithm = { name: 'ECDSA', hash } as const satisfies KeyVerifyParams
      const message = new Uint8Array([1, 2, 3, 4])
      const curveCrypto = curve === 'P-256' ? p256 : curve === 'P-384' ? p384 : p521
      const privateKey = curveCrypto.utils.randomSecretKey()
      const publicKey = curveCrypto.getPublicKey(privateKey)
      const publicJwk = PublicJwk.fromPublicKey({ kty: 'EC', crv: curve, publicKey })
      const key = new CredoWebCryptoKey(publicJwk, { name: 'ECDSA', namedCurve: curve }, true, 'public', ['verify'])
      const signature = curveCrypto.sign(Hasher.hash(message, hash.toLowerCase()), privateKey, {
        prehash: false,
        lowS: false,
      })
      const kms = agentContext.resolve(KeyManagementApi)
      const canPerform = vi.spyOn(kms, 'canPerform')
      const verify = vi.spyOn(kms, 'verify')

      await expect(walletWebCrypto.verify(key, algorithm, message, signature)).resolves.toBe(true)
      expect(canPerform).not.toHaveBeenCalled()
      expect(verify).not.toHaveBeenCalled()

      signature[0] ^= 1
      await expect(walletWebCrypto.verify(key, algorithm, message, signature)).resolves.toBe(false)
    })

    it('does not fall back to local verification when backend verification fails', async () => {
      const algorithm = { name: 'ECDSA', hash: 'SHA-256' } as const satisfies KeyVerifyParams
      const message = new Uint8Array(10).fill(10)
      const key = await webCrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
      const signature = new Uint8Array(await webCrypto.subtle.sign(algorithm, key.privateKey, message))
      const kms = agentContext.resolve(KeyManagementApi)
      vi.spyOn(kms, 'verify').mockRejectedValue(new KeyManagementError('Backend verification failed'))

      await expect(walletWebCrypto.verify(key.publicKey, algorithm, message, signature)).rejects.toThrow(
        'Backend verification failed'
      )
    })
  })
})
