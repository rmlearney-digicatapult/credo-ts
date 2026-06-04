import { CredoError } from '../../../error'
import { ClaimFormat } from '../models'
import { W3cV2CredentialService } from '../W3cV2CredentialService'
import { mixedJwtVp, mixedSdJwtVp } from './mixedVpFixture'

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
})
