import type { X509Certificate } from '@credo-ts/core'
import { CredoError, X509ModuleConfig, X509Service } from '@credo-ts/core'
import { NativeAskar } from '@openwallet-foundation/askar-nodejs'
import { afterEach, vi } from 'vitest'
import { AskarKeyManagementService, AskarModuleConfig, transformPrivateKeyToPrivateJwk } from '../../../../askar/src'
import { AskarStoreManager } from '../../../../askar/src/AskarStoreManager'
import { NodeFileSystem } from '../../../../node/src/NodeFileSystem'
import { getAgentConfig, getAgentContext, getAskarStoreConfig } from '../../../tests/helpers'
import type { AgentContext } from '../../agent'
import { DidKey } from '../../modules/dids'
import {
  Ed25519PublicJwk,
  KeyManagementAlgorithmNotSupportedError,
  KeyManagementApi,
  KeyManagementError,
  KeyManagementKeyNotFoundError,
  KeyManagementModuleConfig,
  KnownJwaSignatureAlgorithms,
  P256PublicJwk,
  PublicJwk,
} from '../../modules/kms'
import { JsonEncoder, TypedArrayEncoder } from '../../utils'
import { JwsService } from '../JwsService'
import * as didJwsz6Mkf from './__fixtures__/didJwsz6Mkf'
import * as didJwsz6Mkv from './__fixtures__/didJwsz6Mkv'
import * as didJwszDnaey from './__fixtures__/didJwszDnaey'

// NOTE: we use askar for the KMS in this test since the signatures with the
// node KMS are different, but it does correctly verify. It's probably something
// to do with the encoding of the signature?

describe('JwsService', () => {
  let agentContext: AgentContext
  let jwsService: JwsService
  let didJwsz6MkfKey: PublicJwk<Ed25519PublicJwk>
  let didJwsz6MkfCertificate: X509Certificate
  let didJwsz6MkvKey: PublicJwk<Ed25519PublicJwk>
  let didJwsz6MkvCertificate: X509Certificate
  let didJwszDnaeyKey: PublicJwk<P256PublicJwk>

  afterEach(() => {
    vi.restoreAllMocks()
  })

  beforeAll(async () => {
    const askarModuleConfig = new AskarModuleConfig({
      askar: NativeAskar,
      store: getAskarStoreConfig('JwsService'),
    })
    agentContext = getAgentContext({
      registerInstances: [
        [X509ModuleConfig, new X509ModuleConfig()],

        [AskarModuleConfig, askarModuleConfig],
        [AskarStoreManager, new AskarStoreManager(new NodeFileSystem(), askarModuleConfig)],
      ],
      kmsBackends: [new AskarKeyManagementService()],
      agentConfig: getAgentConfig('JwsService'),
    })
    const kms = agentContext.resolve(KeyManagementApi)

    jwsService = new JwsService()

    didJwsz6MkfKey = PublicJwk.fromPublicJwk(
      (
        await kms.importKey({
          privateJwk: transformPrivateKeyToPrivateJwk({
            privateKey: TypedArrayEncoder.fromUtf8String(didJwsz6Mkf.SEED),
            type: {
              kty: 'OKP',
              crv: 'Ed25519',
            },
          }).privateJwk,
        })
      ).publicJwk
    )

    didJwsz6MkfCertificate = await X509Service.createCertificate(agentContext, {
      authorityKey: didJwsz6MkfKey,
      issuer: {
        countryName: 'NL',
      },
    })

    didJwsz6MkvKey = PublicJwk.fromPublicJwk(
      (
        await kms.importKey({
          privateJwk: transformPrivateKeyToPrivateJwk({
            privateKey: TypedArrayEncoder.fromUtf8String(didJwsz6Mkv.SEED),
            type: {
              kty: 'OKP',
              crv: 'Ed25519',
            },
          }).privateJwk,
        })
      ).publicJwk
    )

    didJwsz6MkvCertificate = await X509Service.createCertificate(agentContext, {
      authorityKey: didJwsz6MkvKey,
      issuer: {
        countryName: 'NL',
      },
    })

    didJwszDnaeyKey = PublicJwk.fromPublicJwk(
      (
        await kms.importKey({
          privateJwk: transformPrivateKeyToPrivateJwk({
            privateKey: TypedArrayEncoder.fromUtf8String(didJwszDnaey.SEED),
            type: {
              kty: 'EC',
              crv: 'P-256',
            },
          }).privateJwk,
        })
      ).publicJwk
    )
  })

  it('creates a jws for the payload using Ed25519 key', async () => {
    const payload = JsonEncoder.toUint8Array(didJwsz6Mkf.DATA_JSON)
    const kid = new DidKey(didJwsz6MkfKey).did

    const jws = await jwsService.createJws(agentContext, {
      payload,
      keyId: didJwsz6MkfKey.keyId,
      header: { kid },
      protectedHeaderOptions: {
        alg: KnownJwaSignatureAlgorithms.EdDSA,
        jwk: didJwsz6MkfKey.toJson({ includeKid: false }),
      },
    })

    expect(jws).toEqual(didJwsz6Mkf.JWS_JSON)
  })

  it('creates and verify a jws using ES256 alg and P-256 kty', async () => {
    const payload = JsonEncoder.toUint8Array(didJwszDnaey.DATA_JSON)
    const kid = new DidKey(didJwszDnaeyKey).did

    const jws = await jwsService.createJws(agentContext, {
      payload,
      keyId: didJwszDnaeyKey.keyId,
      header: { kid },
      protectedHeaderOptions: {
        alg: KnownJwaSignatureAlgorithms.ES256,
        jwk: didJwszDnaeyKey.toJson({ includeKid: false }),
      },
    })

    expect(jws).toEqual(didJwszDnaey.JWS_JSON)
  })

  it('resolves the signing key once and executes on the resolved backend', async () => {
    const kms = agentContext.resolve(KeyManagementApi)
    const backend = agentContext.resolve(KeyManagementModuleConfig).backends[0]
    const getPublicKey = vi.spyOn(backend, 'getPublicKey')
    const resolveKey = vi.spyOn(kms, 'resolveKey')
    const canPerform = vi.spyOn(kms, 'canPerform')
    const sign = vi.spyOn(kms, 'sign')

    await jwsService.createJwsCompact(agentContext, {
      payload: JsonEncoder.toUint8Array(didJwszDnaey.DATA_JSON),
      keyId: didJwszDnaeyKey.keyId,
      protectedHeaderOptions: { alg: KnownJwaSignatureAlgorithms.ES256 },
    })

    expect(resolveKey).toHaveBeenCalledTimes(1)
    expect(canPerform).toHaveBeenCalledTimes(1)
    expect(getPublicKey).toHaveBeenCalledTimes(1)
    expect(sign).toHaveBeenCalledWith(
      expect.objectContaining({ keyId: didJwszDnaeyKey.keyId, backend: 'askar', algorithm: 'ES256' })
    )
  })

  it('throws a backend algorithm error when the owning backend cannot sign with the requested algorithm', async () => {
    const kms = agentContext.resolve(KeyManagementApi)
    const sign = vi.spyOn(kms, 'sign')

    await expect(
      jwsService.createJwsCompact(agentContext, {
        payload: JsonEncoder.toUint8Array(didJwszDnaey.DATA_JSON),
        keyId: didJwszDnaeyKey.keyId,
        protectedHeaderOptions: { alg: KnownJwaSignatureAlgorithms.ES512 },
      })
    ).rejects.toThrow(
      new KeyManagementAlgorithmNotSupportedError("signing with JWA signature algorithm 'ES512'", 'askar')
    )
    expect(sign).not.toHaveBeenCalled()
  })

  it('rejects signing when the key usage does not allow signing', async () => {
    const backend = agentContext.resolve(KeyManagementModuleConfig).backends[0]
    const getPublicKey = backend.getPublicKey.bind(backend)
    const getPublicKeySpy = vi.spyOn(backend, 'getPublicKey').mockImplementation(async (context, keyId) => {
      const jwk = await getPublicKey(context, keyId)
      return jwk ? { ...jwk, use: 'enc' } : null
    })
    const kms = agentContext.resolve(KeyManagementApi)
    const sign = vi.spyOn(kms, 'sign')

    await expect(
      jwsService.createJwsCompact(agentContext, {
        payload: JsonEncoder.toUint8Array(didJwszDnaey.DATA_JSON),
        keyId: didJwszDnaeyKey.keyId,
        protectedHeaderOptions: { alg: KnownJwaSignatureAlgorithms.ES256 },
      })
    ).rejects.toThrow(KeyManagementError)
    expect(getPublicKeySpy).toHaveBeenCalledTimes(1)
    expect(sign).not.toHaveBeenCalled()
  })

  it('preserves the key-not-found error for an unknown signing key id', async () => {
    await expect(
      jwsService.createJwsCompact(agentContext, {
        payload: JsonEncoder.toUint8Array(didJwszDnaey.DATA_JSON),
        keyId: 'unknown-signing-key',
        protectedHeaderOptions: { alg: KnownJwaSignatureAlgorithms.ES256 },
      })
    ).rejects.toThrow(KeyManagementKeyNotFoundError)
  })

  it('creates a compact jws', async () => {
    const payload = JsonEncoder.toUint8Array(didJwsz6Mkf.DATA_JSON)

    const jws = await jwsService.createJwsCompact(agentContext, {
      payload,
      keyId: didJwsz6MkfKey.keyId,
      protectedHeaderOptions: {
        alg: KnownJwaSignatureAlgorithms.EdDSA,
        jwk: didJwsz6MkfKey.toJson({ includeKid: false }),
      },
    })

    expect(jws).toEqual(
      `${didJwsz6Mkf.JWS_JSON.protected}.${TypedArrayEncoder.toBase64Url(payload)}.${didJwsz6Mkf.JWS_JSON.signature}`
    )
  })

  it('throws an error when creating a jws with crit or b64', async () => {
    await expect(
      jwsService.createJwsCompact(agentContext, {
        payload: JsonEncoder.toUint8Array(didJwsz6Mkf.DATA_JSON),
        keyId: didJwsz6MkfKey.keyId,
        protectedHeaderOptions: { alg: KnownJwaSignatureAlgorithms.EdDSA, b64: false, crit: ['b64'] },
      })
    ).rejects.toThrow("JWS protected header parameters 'crit' and 'b64' are not supported.")
  })

  it('allows both x5c/jwk and kid (no did) to be present', async () => {
    const payload = JsonEncoder.toUint8Array(didJwsz6Mkf.DATA_JSON)

    const signed1 = await jwsService.createJwsCompact(agentContext, {
      payload,
      keyId: didJwsz6MkfKey.keyId,
      protectedHeaderOptions: {
        alg: KnownJwaSignatureAlgorithms.EdDSA,
        jwk: didJwsz6MkfKey,
        kid: 'something',
      },
    })
    const { isValid: isValid1 } = await jwsService.verifyJws(agentContext, {
      jws: signed1,
    })
    expect(isValid1).toEqual(true)

    const signed2 = await jwsService.createJwsCompact(agentContext, {
      payload,
      keyId: didJwsz6MkfKey.keyId,
      protectedHeaderOptions: {
        alg: KnownJwaSignatureAlgorithms.EdDSA,
        x5c: [didJwsz6MkfCertificate.toString('base64url')],
        kid: 'something',
      },
    })

    const { isValid: isValid2 } = await jwsService.verifyJws(agentContext, {
      jws: signed2,
      trustedCertificates: [didJwsz6MkfCertificate.toString('base64url')],
    })
    expect(isValid2).toEqual(true)
  })

  describe('verifyJws', () => {
    it('returns true if the jws signature matches the payload', async () => {
      const { isValid, jwsSigners } = await jwsService.verifyJws(agentContext, {
        jws: didJwsz6Mkf.JWS_JSON,
        allowedJwsSignerMethods: ['did'],
        jwsSigner: {
          didUrl: `did:key:${didJwsz6MkfKey.fingerprint}#${didJwsz6MkfKey.fingerprint}`,
          jwk: didJwsz6MkfKey,
          method: 'did',
        },
      })

      expect(isValid).toBe(true)
      expect(jwsSigners).toEqual([
        {
          method: 'did',
          didUrl: `did:key:${didJwsz6MkfKey.fingerprint}#${didJwsz6MkfKey.fingerprint}`,
          jwk: didJwsz6MkfKey,
        },
      ])
    })

    it('verifies a compact JWS', async () => {
      const { isValid, jwsSigners } = await jwsService.verifyJws(agentContext, {
        jws: `${didJwsz6Mkf.JWS_JSON.protected}.${didJwsz6Mkf.JWS_JSON.payload}.${didJwsz6Mkf.JWS_JSON.signature}`,
        jwsSigner: {
          didUrl: `did:key:${didJwsz6MkfKey.fingerprint}#${didJwsz6MkfKey.fingerprint}`,
          jwk: didJwsz6MkfKey,
          method: 'did',
        },
      })

      expect(isValid).toBe(true)
      expect(jwsSigners).toEqual([
        {
          method: 'did',
          didUrl: `did:key:${didJwsz6MkfKey.fingerprint}#${didJwsz6MkfKey.fingerprint}`,
          jwk: didJwsz6MkfKey,
        },
      ])
    })

    it('returns all keys that signed the jws', async () => {
      const { isValid, jwsSigners } = await jwsService.verifyJws(agentContext, {
        jws: { signatures: [didJwsz6Mkf.JWS_JSON, didJwsz6Mkv.JWS_JSON], payload: didJwsz6Mkf.JWS_JSON.payload },
        allowedJwsSignerMethods: ['did'],
        resolveJwsSigner: ({ jws }) => {
          if (jws.header.kid === `did:key:${didJwsz6MkfKey.fingerprint}`) {
            return {
              method: 'did',
              jwk: didJwsz6MkfKey,
              didUrl: `did:key:${didJwsz6MkfKey.fingerprint}#${didJwsz6MkfKey.fingerprint}`,
            }
          }

          if (jws.header.kid === `did:key:${didJwsz6MkvKey.fingerprint}`) {
            return {
              method: 'did',
              jwk: didJwsz6MkvKey,
              didUrl: `did:key:${didJwsz6MkvKey.fingerprint}#${didJwsz6MkvKey.fingerprint}`,
            }
          }

          throw new CredoError('unexpected request')
        },
      })

      expect(isValid).toBe(true)
      expect(jwsSigners).toEqual([
        {
          method: 'did',
          didUrl: `did:key:${didJwsz6MkfKey.fingerprint}#${didJwsz6MkfKey.fingerprint}`,
          jwk: didJwsz6MkfKey,
        },
        {
          method: 'did',
          didUrl: `did:key:${didJwsz6MkvKey.fingerprint}#${didJwsz6MkvKey.fingerprint}`,
          jwk: didJwsz6MkvKey,
        },
      ])
    })

    it('returns false if the jws signature does not match the payload', async () => {
      const { isValid, jwsSigners } = await jwsService.verifyJws(agentContext, {
        jws: {
          ...didJwsz6Mkf.JWS_JSON,
          payload: JsonEncoder.toBase64Url({ ...didJwsz6Mkf, did: 'another_did' }),
        },
      })

      expect(isValid).toBe(false)
      expect(jwsSigners).toMatchObject([])
    })

    it.each([{ crit: ['exp'] }, { b64: false, crit: ['b64'] }, { b64: true }])(
      'throws an error if the protected header contains %o',
      async (header) => {
        const protectedHeader = JsonEncoder.toBase64Url({
          ...JsonEncoder.fromBase64Url(didJwsz6Mkf.JWS_JSON.protected),
          ...header,
        })

        await expect(
          jwsService.verifyJws(agentContext, { jws: { ...didJwsz6Mkf.JWS_JSON, protected: protectedHeader } })
        ).rejects.toThrow("JWS protected header parameters 'crit' and 'b64' are not supported.")
      }
    )

    it('throws an error if the jws signatures array does not contain a JWS', async () => {
      await expect(
        jwsService.verifyJws(agentContext, {
          jws: { signatures: [], payload: '' },
        })
      ).rejects.toThrow('Unable to verify JWS, no signatures present in JWS.')
    })

    it('throws an error if provided jws signer is of different method than allowed jws signer', async () => {
      await expect(
        jwsService.verifyJws(agentContext, {
          allowedJwsSignerMethods: ['x5c'],
          jws: { signatures: [], payload: '' },
          jwsSigner: {
            method: 'jwk',
            jwk: didJwsz6MkfKey,
          },
        })
      ).rejects.toThrow("jwsSigner provided with method 'jwk', but allowed jws signer methods are x5c.")
    })

    it('throws an error if provided jws signer does not match the signer of the jws', async () => {
      const { isValid, jwsSigners } = await jwsService.verifyJws(agentContext, {
        jws: didJwsz6Mkf.JWS_JSON,
        jwsSigner: {
          method: 'jwk',
          jwk: didJwsz6MkvKey,
        },
      })

      expect(isValid).toBe(false)
      expect(jwsSigners).toEqual([])
    })

    it('verifies x5c chain for provided jws signer', async () => {
      const payload = JsonEncoder.toUint8Array(didJwsz6Mkf.DATA_JSON)

      const signed = await jwsService.createJwsCompact(agentContext, {
        payload,
        keyId: didJwsz6MkfKey.keyId,
        protectedHeaderOptions: {
          alg: KnownJwaSignatureAlgorithms.EdDSA,
          x5c: [didJwsz6MkfCertificate.toString('base64url')],
        },
      })

      const { isValid } = await jwsService.verifyJws(agentContext, {
        jws: signed,
        allowedJwsSignerMethods: ['x5c'],
        trustedCertificates: [didJwsz6MkfCertificate.toString('base64url')],
      })
      expect(isValid).toEqual(true)

      // Invalid cert
      await expect(
        jwsService.verifyJws(agentContext, {
          jws: signed,
          allowedJwsSignerMethods: ['x5c'],
          jwsSigner: {
            method: 'x5c',
            x5c: ['invalid'],
            jwk: didJwsz6MkfKey,
          },
          trustedCertificates: [didJwsz6MkfCertificate.toString('base64url')],
        })
      ).rejects.toThrow('Error during parsing of x509 certificate')

      // No trusted cert
      await expect(
        jwsService.verifyJws(agentContext, {
          jws: signed,
          allowedJwsSignerMethods: ['x5c'],
          jwsSigner: {
            method: 'x5c',
            x5c: [didJwsz6MkfCertificate.toString('base64url')],
            jwk: didJwsz6MkfKey,
          },
          trustedCertificates: [didJwsz6MkvCertificate.toString('base64url')],
        })
      ).rejects.toThrow('No trusted certificate was found while validating the X.509 chain')
    })
  })
})
