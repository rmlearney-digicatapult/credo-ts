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

export const CredoDidKeyDiExampleCredentialToSign = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential', 'ExampleCredential'],
  issuer: 'https://example.org/issuer',
  credentialSubject: {
    id: 'did:example:subject',
    name: 'Jane Doe',
  },
} as const
