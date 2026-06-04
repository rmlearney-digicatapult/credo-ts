import { CredoError } from '../../../error'
import { W3cV2JwtVerifiablePresentation } from '../jwt-vc'
import { CredoEs256DidJwkJwtVc, CredoEs256DidKeyJwtVp } from '../jwt-vc/__tests__/fixtures/credo-jwt-vc-v2'
import { W3cV2JwtVerifiableCredential } from '../jwt-vc/W3cV2JwtVerifiableCredential'
import { ClaimFormat } from '../models'
import { W3cV2Presentation } from '../models/presentation/W3cV2Presentation'
import { W3cV2SdJwtVerifiableCredential } from '../sd-jwt-vc'
import {
  CredoEs256DidJwkJwtVc as CredoEs256DidJwkSdJwtVc,
  CredoEs256DidKeyJwtVp as CredoEs256DidKeySdJwtVp,
} from '../sd-jwt-vc/__tests__/fixtures/credo-sd-jwt-vc'
import { W3cV2SdJwtVerifiablePresentation } from '../sd-jwt-vc/W3cV2SdJwtVerifiablePresentation'
import { W3cV2CredentialService } from '../W3cV2CredentialService'
import { mixedJwtVp, mixedSdJwtVp, mixedVpBaseResolvedPresentation } from './mixedVpFixture'

describe('W3cV2CredentialService Data Integrity stubs', () => {
  const repository = {
    save: vi.fn(),
    deleteById: vi.fn(),
    getAll: vi.fn(),
    getById: vi.fn(),
    findByQuery: vi.fn(),
    findSingleByQuery: vi.fn(),
  }

  const sdJwtService = {
    signCredential: vi.fn(),
    verifyCredential: vi.fn(),
    signPresentation: vi.fn(),
    verifyPresentation: vi.fn(),
  }

  const jwtService = {
    signCredential: vi.fn(),
    verifyCredential: vi.fn(),
    signPresentation: vi.fn(),
    verifyPresentation: vi.fn(),
  }

  const agentContext = {} as never

  const service = new W3cV2CredentialService(repository as never, sdJwtService as never, jwtService as never)

  beforeEach(() => {
    vi.clearAllMocks()
  })

  test('signCredential rejects di_vc via stub hook', async () => {
    await expect(
      service.signCredential(agentContext, {
        format: ClaimFormat.DiVc,
        credential: {} as never,
        verificationMethod: 'did:example:issuer#key-1',
      })
    ).rejects.toThrow(CredoError)

    await expect(
      service.signCredential(agentContext, {
        format: ClaimFormat.DiVc,
        credential: {} as never,
        verificationMethod: 'did:example:issuer#key-1',
      })
    ).rejects.toThrow("Data Integrity format 'di_vc' is not supported")
  })

  test('verifyCredential rejects di_vc via stub hook', async () => {
    await expect(
      service.verifyCredential(agentContext, {
        credential: { claimFormat: ClaimFormat.DiVc },
      } as never)
    ).rejects.toThrow("Data Integrity format 'di_vc' is not supported")
  })

  test('verifyCredential normalizes compact JWT VC strings before routing', async () => {
    jwtService.verifyCredential.mockResolvedValue({ isValid: true, validations: {}, error: undefined })

    await service.verifyCredential(agentContext, {
      credential: CredoEs256DidJwkJwtVc,
    } as never)

    expect(jwtService.verifyCredential).toHaveBeenCalledTimes(1)
    expect(sdJwtService.verifyCredential).not.toHaveBeenCalled()
    expect(jwtService.verifyCredential.mock.calls[0]?.[1].credential).toBeInstanceOf(W3cV2JwtVerifiableCredential)
  })

  test('verifyCredential normalizes compact SD-JWT VC strings before routing', async () => {
    sdJwtService.verifyCredential.mockResolvedValue({ isValid: true, validations: {}, error: undefined })

    await service.verifyCredential(agentContext, {
      credential: CredoEs256DidJwkSdJwtVc,
    } as never)

    expect(sdJwtService.verifyCredential).toHaveBeenCalledTimes(1)
    expect(jwtService.verifyCredential).not.toHaveBeenCalled()
    expect(sdJwtService.verifyCredential.mock.calls[0]?.[1].credential).toBeInstanceOf(W3cV2SdJwtVerifiableCredential)
  })

  test('signPresentation rejects di_vp via stub hook', async () => {
    await expect(
      service.signPresentation(agentContext, {
        format: ClaimFormat.DiVp,
        presentation: {} as never,
        challenge: 'challenge-123',
      })
    ).rejects.toThrow("Data Integrity format 'di_vp' is not supported")
  })

  test('verifyPresentation rejects di_vp via stub hook', async () => {
    await expect(
      service.verifyPresentation(agentContext, {
        presentation: { claimFormat: ClaimFormat.DiVp },
        challenge: 'challenge-123',
      } as never)
    ).rejects.toThrow("Data Integrity format 'di_vp' is not supported")
  })

  test('non-DI signCredential routes to jwt service unchanged', async () => {
    jwtService.signCredential.mockResolvedValue({ claimFormat: ClaimFormat.JwtW3cVc })

    const result = await service.signCredential(agentContext, {
      format: ClaimFormat.JwtW3cVc,
      credential: {} as never,
      verificationMethod: 'did:example:issuer#key-1',
      alg: 'EdDSA',
    } as never)

    expect(jwtService.signCredential).toHaveBeenCalledTimes(1)
    expect(sdJwtService.signCredential).not.toHaveBeenCalled()
    expect(result).toEqual({ claimFormat: ClaimFormat.JwtW3cVc })
  })

  test('verifyPresentation enforces JWT VP profile for JWT enclosed credentials', async () => {
    jwtService.verifyPresentation.mockResolvedValue({
      isValid: true,
      presentation: { isValid: true, validations: {} },
      credentialEntries: [],
    })
    jwtService.verifyCredential.mockResolvedValue({ isValid: true, validations: {}, error: undefined })
    sdJwtService.verifyCredential.mockResolvedValue({ isValid: true, validations: {}, error: undefined })

    const result = await service.verifyPresentation(agentContext, {
      presentation: mixedJwtVp,
      challenge: 'challenge-123',
    } as never)

    expect(jwtService.verifyPresentation).toHaveBeenCalledTimes(1)
    expect(sdJwtService.verifyPresentation).not.toHaveBeenCalled()
    expect(jwtService.verifyCredential).toHaveBeenCalledTimes(1)
    expect(sdJwtService.verifyCredential).not.toHaveBeenCalled()
    expect(result.presentation.isValid).toBe(true)
    expect(result.credentialEntries).toHaveLength(3)
    expect(result.credentialEntries[0]?.isValid).toBe(true)
    expect(result.credentialEntries[1]?.isValid).toBe(false)
    expect(result.credentialEntries[1]?.error?.message).toContain(
      "Credential entry uses 'vc+sd-jwt' inside a non-'vp+sd-jwt' presentation"
    )
    expect(result.credentialEntries[2]?.isValid).toBe(false)
    expect(result.credentialEntries[2]?.error?.message).toContain(
      "Data Integrity format 'di_vc' is not yet implemented"
    )
    expect(result.isValid).toBe(false)
  })

  test('verifyPresentation enforces SD-JWT VP profile for SD-JWT enclosed credentials', async () => {
    sdJwtService.verifyPresentation.mockResolvedValue({
      isValid: true,
      presentation: { isValid: true, validations: {} },
      credentialEntries: [],
    })
    jwtService.verifyCredential.mockResolvedValue({ isValid: true, validations: {}, error: undefined })
    sdJwtService.verifyCredential.mockResolvedValue({ isValid: true, validations: {}, error: undefined })

    const result = await service.verifyPresentation(agentContext, {
      presentation: mixedSdJwtVp,
      challenge: 'challenge-123',
    } as never)

    expect(sdJwtService.verifyPresentation).toHaveBeenCalledTimes(1)
    expect(jwtService.verifyPresentation).not.toHaveBeenCalled()
    expect(sdJwtService.verifyCredential).toHaveBeenCalledTimes(1)
    expect(jwtService.verifyCredential).not.toHaveBeenCalled()
    expect(result.presentation.isValid).toBe(true)
    expect(result.credentialEntries).toHaveLength(3)
    expect(result.credentialEntries[0]?.isValid).toBe(false)
    expect(result.credentialEntries[0]?.error?.message).toContain(
      "Credential entry uses 'vc+jwt' inside a non-'vp+jwt' presentation"
    )
    expect(result.credentialEntries[1]?.isValid).toBe(true)
    expect(result.credentialEntries[2]?.isValid).toBe(false)
    expect(result.credentialEntries[2]?.error?.message).toContain(
      "Data Integrity format 'di_vc' is not yet implemented"
    )
    expect(result.isValid).toBe(false)
  })

  test('verifyPresentation normalizes compact JWT VP strings before routing', async () => {
    jwtService.verifyPresentation.mockResolvedValue({
      isValid: true,
      presentation: { isValid: true, validations: {} },
      credentialEntries: [],
    })
    jwtService.verifyCredential.mockResolvedValue({ isValid: true, validations: {}, error: undefined })

    await service.verifyPresentation(agentContext, {
      presentation: CredoEs256DidKeyJwtVp,
      challenge: 'daf942ad-816f-45ee-a9fc-facd08e5abca',
      domain: 'example.com',
    } as never)

    expect(jwtService.verifyPresentation).toHaveBeenCalledTimes(1)
    expect(jwtService.verifyPresentation.mock.calls[0]?.[1].presentation).toBeInstanceOf(W3cV2JwtVerifiablePresentation)
  })

  test('verifyPresentation normalizes compact SD-JWT VP strings before routing', async () => {
    sdJwtService.verifyPresentation.mockResolvedValue({
      isValid: true,
      presentation: { isValid: true, validations: {} },
      credentialEntries: [],
    })
    sdJwtService.verifyCredential.mockResolvedValue({ isValid: true, validations: {}, error: undefined })

    await service.verifyPresentation(agentContext, {
      presentation: CredoEs256DidKeySdJwtVp,
      challenge: 'daf942ad-816f-45ee-a9fc-facd08e5abca',
      domain: 'example.com',
    } as never)

    expect(sdJwtService.verifyPresentation).toHaveBeenCalledTimes(1)
    expect(sdJwtService.verifyPresentation.mock.calls[0]?.[1].presentation).toBeInstanceOf(
      W3cV2SdJwtVerifiablePresentation
    )
  })

  test('verifyPresentation short-circuits when outer presentation verification fails', async () => {
    jwtService.verifyPresentation.mockResolvedValue({
      isValid: false,
      presentation: { isValid: false, validations: {} },
      credentialEntries: [],
    })

    const result = await service.verifyPresentation(agentContext, {
      presentation: mixedJwtVp,
      challenge: 'challenge-123',
    } as never)

    expect(jwtService.verifyPresentation).toHaveBeenCalledTimes(1)
    expect(jwtService.verifyCredential).not.toHaveBeenCalled()
    expect(sdJwtService.verifyCredential).not.toHaveBeenCalled()
    expect(result.isValid).toBe(false)
    expect(result.presentation.isValid).toBe(false)
    expect(result.credentialEntries).toEqual([])
  })

  test('verifyPresentation marks credential invalid when presenter does not authenticate credential subject', async () => {
    const jwtOnlyVp = {
      __proto__: W3cV2JwtVerifiablePresentation.prototype,
      resolvedPresentation: {
        __proto__: W3cV2Presentation.prototype,
        ...mixedVpBaseResolvedPresentation,
        holder: 'did:example:presenter',
        verifiableCredential: [mixedVpBaseResolvedPresentation.verifiableCredential[0]],
      },
    }

    jwtService.verifyPresentation.mockResolvedValue({
      isValid: true,
      presentation: { isValid: true, validations: {} },
      credentialEntries: [],
    })
    jwtService.verifyCredential.mockResolvedValue({ isValid: true, validations: {}, error: undefined })

    const result = await service.verifyPresentation(agentContext, {
      presentation: jwtOnlyVp,
      challenge: 'challenge-123',
    } as never)

    expect(result.credentialEntries).toHaveLength(1)
    expect(result.credentialEntries[0]?.isValid).toBe(false)
    expect(result.credentialEntries[0]?.validations.credentialSubjectAuthentication?.isValid).toBe(false)
    expect(result.credentialEntries[0]?.validations.credentialSubjectAuthentication?.error?.message).toContain(
      'presentation does not authenticate credential subject'
    )
    expect(result.isValid).toBe(false)
  })

  test('verifyPresentation returns valid when outer presentation and enclosed credentials are valid', async () => {
    const jwtOnlyVp = {
      __proto__: W3cV2JwtVerifiablePresentation.prototype,
      resolvedPresentation: {
        __proto__: W3cV2Presentation.prototype,
        ...mixedVpBaseResolvedPresentation,
        verifiableCredential: [mixedVpBaseResolvedPresentation.verifiableCredential[0]],
      },
    }

    jwtService.verifyPresentation.mockResolvedValue({
      isValid: true,
      presentation: { isValid: true, validations: {} },
      credentialEntries: [],
    })
    jwtService.verifyCredential.mockResolvedValue({ isValid: true, validations: {}, error: undefined })

    const result = await service.verifyPresentation(agentContext, {
      presentation: jwtOnlyVp,
      challenge: 'challenge-123',
    } as never)

    expect(result.presentation.isValid).toBe(true)
    expect(result.credentialEntries).toHaveLength(1)
    expect(result.credentialEntries[0]?.isValid).toBe(true)
    expect(result.credentialEntries[0]?.validations.credentialSubjectAuthentication?.isValid).toBe(true)
    expect(result.isValid).toBe(true)
  })
})
