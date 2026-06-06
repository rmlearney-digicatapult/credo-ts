export const CredoDidKeyDiVc = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential'],
  issuer: {
    id: 'did:example:issuer-di',
  },
  credentialSubject: {
    id: 'did:key:z6MkqgkLrRyLg6bqk27djwbbaQWgaSYgFVCKq9YKxZbNkpVv',
  },
  proof: {
    type: 'DataIntegrityProof',
  },
} as const

export const CredoDidKeyDiVp = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiablePresentation'],
  id: 'urn:fixture:nested-di-vp-leaf',
  holder: 'did:key:z6MkqgkLrRyLg6bqk27djwbbaQWgaSYgFVCKq9YKxZbNkpVv',
  verifiableCredential: [CredoDidKeyDiVc],
  proof: {
    type: 'DataIntegrityProof',
  },
} as const

export const CredoDidKeyDiVpDataUri =
  'data:application/vp+di,eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiXSwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sImlkIjoidXJuOmZpeHR1cmU6bmVzdGVkLWRpLXZwLWxlYWYiLCJob2xkZXIiOiJkaWQ6a2V5Ono2TWtxZ2tMclJ5TGc2YnFrMjdkandiYmFRV2dhU1lnRlZDS3E5WUt4WmJOa3BWdiIsInZlcmlmaWFibGVDcmVkZW50aWFsIjpbeyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOnsiaWQiOiJkaWQ6ZXhhbXBsZTppc3N1ZXItZGkifSwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6a2V5Ono2TWtxZ2tMclJ5TGc2YnFrMjdkandiYmFRV2dhU1lnRlZDS3E5WUt4WmJOa3BWdiJ9LCJwcm9vZiI6eyJ0eXBlIjoiRGF0YUludGVncml0eVByb29mIn19XSwicHJvb2YiOnsidHlwZSI6IkRhdGFJbnRlZ3JpdHlQcm9vZiJ9fQ'

export const CredoDidKeyDiExampleCredentialToSign = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential', 'ExampleCredential'],
  issuer: 'https://example.org/issuer',
  credentialSubject: {
    id: 'did:example:subject',
    name: 'Jane Doe',
  },
} as const
