import { CredoError } from '../../../../../error'
import { W3cV2DataIntegrityVerifiablePresentation } from '../../../data-integrity-v1'
import { W3cV2JwtVerifiablePresentation } from '../../../jwt-vc'
import { CredoEs256DidKeyJwtVp } from '../../../jwt-vc/__tests__/fixtures/credo-jwt-vc-v2'
import { W3cV2SdJwtVerifiablePresentation } from '../../../sd-jwt-vc'
import { CredoEs256DidKeyJwtVp as CredoEs256DidKeySdJwtVp } from '../../../sd-jwt-vc/__tests__/fixtures/credo-sd-jwt-vc'
import { ClaimFormat } from '../../ClaimFormat'
import { decodeW3cV2VerifiablePresentation } from '../W3cV2VerifiablePresentation'

describe('decodeW3cV2VerifiablePresentation', () => {
  test('routes JSON object payload to DI presentation decoder', () => {
    const result = decodeW3cV2VerifiablePresentation(
      '  {"@context":["https://www.w3.org/ns/credentials/v2","https://w3id.org/security/data-integrity/v2"],"type":["VerifiablePresentation"],"holder":"did:key:z6Mkholder","proof":{"type":"DataIntegrityProof"}}'
    )

    expect(result).toBeInstanceOf(W3cV2DataIntegrityVerifiablePresentation)
    expect(result.claimFormat).toBe(ClaimFormat.DiVp)
  })

  test('accepts envelope-first vp+jwt data URI encoding', () => {
    const result = decodeW3cV2VerifiablePresentation(`data:application/vp+jwt,${CredoEs256DidKeyJwtVp}`)

    expect(result).toBeInstanceOf(W3cV2JwtVerifiablePresentation)
  })

  test('accepts envelope-first vp+sd-jwt data URI encoding', () => {
    const result = decodeW3cV2VerifiablePresentation(`data:application/vp+sd-jwt,${CredoEs256DidKeySdJwtVp}`)

    expect(result).toBeInstanceOf(W3cV2SdJwtVerifiablePresentation)
  })

  test('rejects unsupported data URI encoding for presentation', () => {
    expect(() => decodeW3cV2VerifiablePresentation('data:application/vp+cose,ZmFrZQ')).toThrow(CredoError)
  })
})
