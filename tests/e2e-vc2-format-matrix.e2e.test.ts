import {
  Agent,
  ClaimFormat,
  Kms,
  W3cV2Credential,
  W3cV2CredentialRecord,
  W3cV2CredentialSubject,
  W3cV2DataIntegrityVerifiableCredential,
  W3cV2EnvelopedVerifiableCredential,
  W3cV2Issuer,
  W3cV2JwtVerifiableCredential,
  W3cV2Presentation,
  W3cV2SdJwtVerifiableCredential,
} from '@credo-ts/core'

import { createDidKidVerificationMethod, getAgentOptions } from '../packages/core/tests/helpers'

type IssuanceCase = {
  name: string
  credentialFormat: ClaimFormat.JwtW3cVc | ClaimFormat.SdJwtW3cVc | ClaimFormat.DiVc
  presentationFormat: ClaimFormat.JwtW3cVp | ClaimFormat.SdJwtW3cVp | ClaimFormat.DiVp
}

type DidRef = Awaited<ReturnType<typeof createDidKidVerificationMethod>>

const issuanceCases: IssuanceCase[] = [
  {
    name: 'jwt-vc / jwt-vp',
    credentialFormat: ClaimFormat.JwtW3cVc,
    presentationFormat: ClaimFormat.JwtW3cVp,
  },
  {
    name: 'sd-jwt-vc / sd-jwt-vp',
    credentialFormat: ClaimFormat.SdJwtW3cVc,
    presentationFormat: ClaimFormat.SdJwtW3cVp,
  },
  {
    name: 'di-vc / di-vp',
    credentialFormat: ClaimFormat.DiVc,
    presentationFormat: ClaimFormat.DiVp,
  },
]

function buildCredentialToSign(issuerDid: string, holderDid: string) {
  return new W3cV2Credential({
    type: ['VerifiableCredential', 'ExampleCredential'],
    issuer: new W3cV2Issuer({ id: issuerDid }),
    credentialSubject: new W3cV2CredentialSubject({
      id: holderDid,
      name: 'Jane Doe',
      employeeId: 'E-1001',
    }),
    validFrom: new Date().toISOString(),
  })
}

function buildSignCredentialOptions(params: {
  credentialFormat: IssuanceCase['credentialFormat']
  issuerDidRef: DidRef
  holderDidRef: DidRef
}) {
  const { credentialFormat, issuerDidRef, holderDidRef } = params
  const credential = buildCredentialToSign(issuerDidRef.did, holderDidRef.did)

  // Intentionally untyped skeleton: this file is a template for true format e2e tests.
  if (credentialFormat === ClaimFormat.JwtW3cVc) {
    return {
      format: ClaimFormat.JwtW3cVc,
      credential,
      alg: Kms.KnownJwaSignatureAlgorithms.EdDSA,
      verificationMethod: issuerDidRef.kid,
    }
  }

  if (credentialFormat === ClaimFormat.SdJwtW3cVc) {
    return {
      format: ClaimFormat.SdJwtW3cVc,
      credential,
      alg: Kms.KnownJwaSignatureAlgorithms.EdDSA,
      verificationMethod: issuerDidRef.kid,
      disclosureFrame: {
        credentialSubject: {
          _sd: ['name'],
        },
      },
      holder: {
        method: 'did',
        didUrl: holderDidRef.kid,
      },
    }
  }

  return {
    format: ClaimFormat.DiVc,
    credential: {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: `urn:vc2:e2e:di:${Date.now()}`,
      type: ['VerifiableCredential', 'ExampleCredential'],
      issuer: issuerDidRef.did,
      validFrom: new Date().toISOString(),
      credentialSubject: {
        id: holderDidRef.did,
        name: 'Jane Doe',
      },
    },
    cryptosuite: 'eddsa-jcs-2022',
    verificationMethod: issuerDidRef.kid,
  }
}

function buildSignPresentationOptions(params: {
  presentationFormat: IssuanceCase['presentationFormat']
  holderDidRef: DidRef
  signedCredential: unknown
  challenge: string
  domain: string
}) {
  const { presentationFormat, holderDidRef, signedCredential, challenge, domain } = params

  // TODO: replace this payload with exact API-native W3C V2 presentation objects for each format.
  // The structure below is a practical starting scaffold for wiring the matrix.
  if (presentationFormat === ClaimFormat.JwtW3cVp) {
    const jwtCredential = signedCredential as W3cV2JwtVerifiableCredential
    return {
      format: ClaimFormat.JwtW3cVp,
      challenge,
      domain,
      verificationMethod: holderDidRef.kid,
      alg: Kms.KnownJwaSignatureAlgorithms.EdDSA,
      presentation: new W3cV2Presentation({
        holder: holderDidRef.did,
        verifiableCredential: [W3cV2EnvelopedVerifiableCredential.fromVerifiableCredential(jwtCredential)],
      }),
    }
  }

  if (presentationFormat === ClaimFormat.SdJwtW3cVp) {
    const sdJwtCredential = signedCredential as W3cV2SdJwtVerifiableCredential
    return {
      format: ClaimFormat.SdJwtW3cVp,
      challenge,
      domain,
      verificationMethod: holderDidRef.kid,
      alg: Kms.KnownJwaSignatureAlgorithms.EdDSA,
      presentation: new W3cV2Presentation({
        holder: holderDidRef.did,
        verifiableCredential: [W3cV2EnvelopedVerifiableCredential.fromVerifiableCredential(sdJwtCredential)],
      }),
    }
  }

  return {
    format: ClaimFormat.DiVp,
    challenge,
    domain,
    verificationMethod: holderDidRef.kid,
    cryptosuite: 'eddsa-jcs-2022',
    presentation: new W3cV2Presentation({
      id: `urn:vp2:e2e:di:${Date.now()}`,
      holder: holderDidRef.did,
      verifiableCredential: [signedCredential as W3cV2DataIntegrityVerifiableCredential],
    }),
  }
}

describe('W3C VC 2.0 format e2e matrix (transport-agnostic)', () => {
  let issuerAgent: Agent
  let holderAgent: Agent
  let issuerDidRef: DidRef
  let holderDidRef: DidRef

  beforeEach(async () => {
    issuerAgent = new Agent(getAgentOptions('VC2 E2E Issuer'))
    holderAgent = new Agent(getAgentOptions('VC2 E2E Holder'))

    await issuerAgent.initialize()
    await holderAgent.initialize()

    issuerDidRef = await createDidKidVerificationMethod(issuerAgent.context)
    holderDidRef = await createDidKidVerificationMethod(holderAgent.context)
  })

  afterEach(async () => {
    await issuerAgent.shutdown()
    await holderAgent.shutdown()
  })

  test.each(issuanceCases)('issues, stores, presents, and verifies %s', async ({
    name,
    credentialFormat,
    presentationFormat,
  }) => {
    const challenge = `challenge-${name.replace(/\s+/g, '-')}`
    const domain = 'example.org'

    const signCredentialOptions = buildSignCredentialOptions({
      credentialFormat,
      issuerDidRef,
      holderDidRef,
    })

    const signedCredential = await issuerAgent.w3cV2Credentials.signCredential(signCredentialOptions as never)

    const verifyCredentialResult = await holderAgent.w3cV2Credentials.verifyCredential({
      credential: signedCredential,
    } as never)

    expect(verifyCredentialResult.isValid).toBe(true)

    await holderAgent.w3cV2Credentials.store({
      record: W3cV2CredentialRecord.fromCredential(signedCredential as never),
    })

    const signPresentationOptions = buildSignPresentationOptions({
      presentationFormat,
      holderDidRef,
      signedCredential,
      challenge,
      domain,
    })

    const signedPresentation = await holderAgent.w3cV2Credentials.signPresentation(signPresentationOptions as never)

    const verifyPresentationResult = await issuerAgent.w3cV2Credentials.verifyPresentation({
      presentation: signedPresentation,
      challenge,
      domain,
    } as never)

    expect(verifyPresentationResult.presentation.isValid).toBe(true)
    expect(verifyPresentationResult.isValid).toBe(true)
  })

  test.todo('negative: tampered credential should fail verification for each format')
  test.todo('negative: wrong challenge/domain should fail VP verification for each format')
  test.todo('negative: presenter must authenticate credentialSubject where applicable')
})
