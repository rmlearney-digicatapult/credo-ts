import { isWebVhAttestedResource, zWebVhAttestedResource } from '../attestedResource'

const validResource = {
  '@context': ['https://identity.foundation/did-attested-resources/context/v0.1'],
  id: 'did:webvh:example.com:tenant:01/resources/zQmHash',
  type: ['AttestedResource'],
  content: { name: 'resource' },
  proof: {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    proofPurpose: 'assertionMethod',
    proofValue: 'zProof',
    verificationMethod: 'did:webvh:example.com:tenant:01#key-1',
  },
  metadata: {
    resourceType: 'anonCredsSchema',
  },
}

describe('attestedResource', () => {
  it('detects valid attested resource payloads', () => {
    expect(isWebVhAttestedResource(validResource)).toBe(true)
  })

  it('rejects missing attested resource type', () => {
    const invalid = {
      ...validResource,
      type: ['OtherType'],
    }

    expect(isWebVhAttestedResource(invalid)).toBe(false)
  })

  it('accepts a string type, as the schema does', () => {
    expect(isWebVhAttestedResource({ ...validResource, type: 'AttestedResource' })).toBe(true)
  })

  it('normalizes type strings and preserves unknown resource fields', () => {
    const parsed = zWebVhAttestedResource.parse({
      ...validResource,
      type: 'AttestedResource',
      extension: { retained: true },
      content: { name: 'resource', contentExtension: true },
      proof: { ...validResource.proof, proofExtension: true },
      links: [
        {
          id: 'did:webvh:example.com:tenant:01/resources/previous',
          type: 'PreviousVersion',
          timestamp: 123,
          linkExtension: true,
        },
      ],
    })

    expect(parsed.type).toEqual(['AttestedResource'])
    expect(parsed).toHaveProperty('extension', { retained: true })
    expect(parsed.content).toHaveProperty('contentExtension', true)
    expect(parsed.proof).toHaveProperty('proofExtension', true)
    expect(parsed.links?.[0]).toHaveProperty('linkExtension', true)
  })

  it('rejects malformed nested proof and link properties', () => {
    expect(() =>
      zWebVhAttestedResource.parse({
        ...validResource,
        proof: { ...validResource.proof, verificationMethod: 1 },
      })
    ).toThrow()

    expect(() =>
      zWebVhAttestedResource.parse({
        ...validResource,
        links: [{ id: 'previous', type: 'PreviousVersion', timestamp: '123' }],
      })
    ).toThrow()
  })
})
