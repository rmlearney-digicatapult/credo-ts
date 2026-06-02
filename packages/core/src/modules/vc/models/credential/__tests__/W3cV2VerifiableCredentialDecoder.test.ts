import { CredoError } from '../../../../../error'
import { W3cV2DataIntegrityVerifiableCredential } from '../../../data-integrity-v1'
import { W3cV2JwtVerifiableCredential } from '../../../jwt-vc'
import { W3cV2SdJwtVerifiableCredential } from '../../../sd-jwt-vc'
import { decodeW3cV2VerifiableCredential } from '../W3cV2VerifiableCredential'

describe('decodeW3cV2VerifiableCredential', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  test('routes JSON object payload to DI credential decoder', () => {
    const diSpy = vi
      .spyOn(W3cV2DataIntegrityVerifiableCredential, 'fromObject')
      .mockReturnValue({ claimFormat: 'di_vc' } as never)

    const result = decodeW3cV2VerifiableCredential('   {"proof":{"type":"DataIntegrityProof"}}')

    expect(diSpy).toHaveBeenCalledTimes(1)
    expect(result).toEqual({ claimFormat: 'di_vc' })
  })

  test('routes compact with vc+sd-jwt typ to SD-JWT VC decoder', () => {
    const sdSpy = vi.spyOn(W3cV2SdJwtVerifiableCredential, 'fromCompact').mockReturnValue({} as never)
    const jwtSpy = vi.spyOn(W3cV2JwtVerifiableCredential, 'fromCompact').mockReturnValue({} as never)

    const compact = `${toCompactHeader({ alg: 'ES256', typ: 'vc+sd-jwt' })}~disclosure`

    decodeW3cV2VerifiableCredential(compact)

    expect(sdSpy).toHaveBeenCalledTimes(1)
    expect(jwtSpy).not.toHaveBeenCalled()
  })

  test('does not treat arbitrary tilde strings as SD-JWT VC', () => {
    const sdSpy = vi.spyOn(W3cV2SdJwtVerifiableCredential, 'fromCompact').mockReturnValue({} as never)

    expect(() => decodeW3cV2VerifiableCredential('not-a-jwt~still-not-a-jwt')).toThrow(CredoError)
    expect(sdSpy).not.toHaveBeenCalled()
  })

  test('rejects vp+sd-jwt compact token in VC decode path', () => {
    const sdSpy = vi.spyOn(W3cV2SdJwtVerifiableCredential, 'fromCompact').mockReturnValue({} as never)

    const compact = `${toCompactHeader({ alg: 'ES256', typ: 'vp+sd-jwt' })}~disclosure`

    expect(() => decodeW3cV2VerifiableCredential(compact)).toThrow(
      'Value is a W3C SD-JWT VP, but a W3C SD-JWT VC was expected'
    )
    expect(sdSpy).not.toHaveBeenCalled()
  })
})

function toCompactHeader(header: Record<string, unknown>) {
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url')
  const encodedPayload = Buffer.from(JSON.stringify({ iss: 'did:example:issuer' })).toString('base64url')
  const encodedSignature = Buffer.from('signature').toString('base64url')

  return `${encodedHeader}.${encodedPayload}.${encodedSignature}`
}
