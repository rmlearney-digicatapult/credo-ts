import type { ZodType } from 'zod'
import { zWebVhAttestedResource } from '../../../resources'
import {
  zWebVhCredDefContent,
  zWebVhRevRegDefContent,
  zWebVhSchemaContent,
  zWebVhStatusListContent,
} from '../../utils/transform'

import {
  mockCredDefResource,
  mockRegRevEntryResource,
  mockRevRegDefResource,
  mockSchemaResource,
} from './mock-resources'

function parseResource<Content>(json: unknown, contentSchema: ZodType<Content>) {
  const resource = zWebVhAttestedResource.parse(json)
  return { ...resource, content: contentSchema.parse(resource.content) }
}

describe('WebVhTransform', () => {
  it('should correctly transform a schema resource', () => {
    const resource = parseResource(mockSchemaResource, zWebVhSchemaContent)

    expect(resource['@context']).toContain('https://opsecid.github.io/attested-resource/v1')
    expect(resource.type).toEqual(['AttestedResource'])
    expect(resource.content.name).toBe(mockSchemaResource.content.name)
    expect(resource.content.version).toBe(mockSchemaResource.content.version)
    expect(resource.content.attrNames).toContain(mockSchemaResource.content.attrNames[0])
  })

  it('should correctly transform a credential definition resource', () => {
    const resource = parseResource(mockCredDefResource, zWebVhCredDefContent)

    expect(resource['@context']).toContain('https://identity.foundation/did-attested-resources/context/v0.1')
    expect(resource.type).toEqual(['AttestedResource'])
    expect(resource.content.type).toBe(mockCredDefResource.content.type)
    expect(resource.content.tag).toBe(mockCredDefResource.content.tag)
    expect(resource.content.schemaId).toBe(mockSchemaResource.id)
  })

  it('preserves extra properties in transformed content', () => {
    const resource = parseResource(
      { ...mockSchemaResource, content: { ...mockSchemaResource.content, extension: { retained: true } } },
      zWebVhSchemaContent
    )

    expect(resource.content).toHaveProperty('extension', { retained: true })
  })

  it('rejects non-string schema attribute names instead of coercing them', () => {
    const invalidResource = {
      ...mockSchemaResource,
      content: { ...mockSchemaResource.content, attrNames: [1] },
    }

    expect(() => parseResource(invalidResource, zWebVhSchemaContent)).toThrow()
  })

  it('rejects schema content without an issuerId', () => {
    const { issuerId: _, ...content } = mockSchemaResource.content

    expect(() => parseResource({ ...mockSchemaResource, content }, zWebVhSchemaContent)).toThrow()
  })

  it('transforms revocation registry definition content', () => {
    const resource = parseResource(mockRevRegDefResource, zWebVhRevRegDefContent)

    expect(resource.content).toMatchObject(mockRevRegDefResource.content)
  })

  it('transforms revocation status list content', () => {
    const resource = parseResource(mockRegRevEntryResource, zWebVhStatusListContent)

    expect(resource.content).toMatchObject(mockRegRevEntryResource.content)
  })
})
