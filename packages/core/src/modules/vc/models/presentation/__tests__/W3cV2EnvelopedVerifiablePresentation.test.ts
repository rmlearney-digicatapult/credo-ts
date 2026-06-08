import { JsonTransformer } from '../../../../../utils'
import { ENVELOPED_VERIFIABLE_PRESENTATION_TYPE } from '../../../constants'
import { W3cV2JwtVerifiablePresentation } from '../../../jwt-vc'
import { CredoEs256DidKeyJwtVp } from '../../../jwt-vc/__tests__/fixtures/credo-jwt-vc-v2'
import { ClaimFormat } from '../../ClaimFormat'
import { W3cV2EnvelopedVerifiablePresentation } from '../W3cV2EnvelopedVerifiablePresentation'

describe('W3cV2EnvelopedVerifiablePresentation', () => {
  const jwtVpDataUri = `data:application/vp+jwt,${CredoEs256DidKeyJwtVp}`

  test('defaults type to EnvelopedVerifiablePresentation', () => {
    const enveloped = new W3cV2EnvelopedVerifiablePresentation({ id: jwtVpDataUri })

    expect(enveloped.type).toBe(ENVELOPED_VERIFIABLE_PRESENTATION_TYPE)
  })

  test('rejects non-presentation envelope type', () => {
    expect(() =>
      JsonTransformer.fromJSON(
        {
          '@context': 'https://www.w3.org/ns/credentials/v2',
          id: jwtVpDataUri,
          type: 'EnvelopedVerifiableCredential',
        },
        W3cV2EnvelopedVerifiablePresentation
      )
    ).toThrow(ENVELOPED_VERIFIABLE_PRESENTATION_TYPE)
  })

  test('exposes decoded presentation and claim format accessors', () => {
    const enveloped = new W3cV2EnvelopedVerifiablePresentation({ id: jwtVpDataUri })

    expect(enveloped.envelopedPresentation).toBeInstanceOf(W3cV2JwtVerifiablePresentation)
    expect(enveloped.resolvedPresentation).toEqual(enveloped.envelopedPresentation.resolvedPresentation)
    expect(enveloped.claimFormat).toBe(ClaimFormat.JwtW3cVp)
  })

  test('creates an enveloped wrapper from a verifiable presentation instance', () => {
    const vp = W3cV2JwtVerifiablePresentation.fromCompact(CredoEs256DidKeyJwtVp)
    const enveloped = W3cV2EnvelopedVerifiablePresentation.fromVerifiablePresentation(vp)

    expect(enveloped.id).toBe(`data:application/vp+jwt,${CredoEs256DidKeyJwtVp}`)
    expect(enveloped.type).toBe(ENVELOPED_VERIFIABLE_PRESENTATION_TYPE)
  })

  test('throws deterministic error for malformed data URI', () => {
    expect(() => new W3cV2EnvelopedVerifiablePresentation({ id: 'data:application/vp+jwt' })).toThrow(
      'data URI is missing comma separator'
    )
  })
})
