import { JsonTransformer } from '@credo-ts/core'

import { WebVhAttestedResource } from '../../../resources'
import { parseWebVhAnonCredsContent } from '../../utils/transform'

import { mockCredDefResource, mockSchemaResource } from './mock-resources'

function parseResource(json: unknown) {
  const resource = JsonTransformer.fromJSON(json, WebVhAttestedResource)
  return Object.assign(resource, { content: parseWebVhAnonCredsContent(resource.content) })
}

describe('WebVhTransform', () => {
  it('should correctly transform a schema resource', () => {
    const resource = parseResource(mockSchemaResource)

    expect(resource).toBeInstanceOf(WebVhAttestedResource)
    expect(resource['@context']).toContain('https://opsecid.github.io/attested-resource/v1')
    expect(resource.type).toEqual(['AttestedResource'])

    // Type guard to check if content is a schema
    if ('attrNames' in resource.content) {
      expect(resource.content.name).toBe(mockSchemaResource.content.name)
      expect(resource.content.version).toBe(mockSchemaResource.content.version)
      expect(Array.isArray(resource.content.attrNames)).toBe(true)
      expect(resource.content.attrNames).toContain(mockSchemaResource.content.attrNames[0])
    } else {
      throw new Error('Content should be a schema')
    }
  })

  it('should correctly transform a credential definition resource', () => {
    const resource = parseResource(mockCredDefResource)

    expect(resource).toBeInstanceOf(WebVhAttestedResource)
    expect(resource['@context']).toContain('https://identity.foundation/did-attested-resources/context/v0.1')
    expect(resource.type).toEqual(['AttestedResource'])

    // Type guard to check if content is a credential definition
    if ('schemaId' in resource.content) {
      expect(resource.content.type).toBe(mockCredDefResource.content.type)
      expect(resource.content.tag).toBe(mockCredDefResource.content.tag)
      expect(resource.content.schemaId).toBe(mockSchemaResource.id)
    } else {
      throw new Error('Content should be a credential definition')
    }
  })

  it('preserves extra properties in transformed content', () => {
    const resource = parseResource({
      ...mockSchemaResource,
      content: { ...mockSchemaResource.content, extension: { retained: true } },
    })

    expect(resource.content).toHaveProperty('extension', { retained: true })
  })

  it('rejects non-string schema attribute names instead of coercing them', () => {
    const invalidResource = {
      ...mockSchemaResource,
      content: { ...mockSchemaResource.content, attrNames: [1] },
    }

    expect(() => parseResource(invalidResource)).toThrow()
  })

  it('transforms revocation registry definition content', () => {
    const content = {
      issuerId: mockSchemaResource.content.issuerId,
      revocDefType: 'CL_ACCUM',
      credDefId: 'cred-def-id',
      tag: 'default',
      value: {},
    }
    const resource = parseResource({ ...mockSchemaResource, content })

    expect(resource.content).toMatchObject(content)
  })

  it('leaves revocation status-list content as plain JSON', () => {
    const content = {
      issuerId: mockSchemaResource.content.issuerId,
      revRegDefId: 'rev-reg-def-id',
      revocationList: [0, 1],
      currentAccumulator: 'accumulator',
    }
    const resource = parseResource({ ...mockSchemaResource, content })

    expect(resource.content).toEqual(content)
  })
})
