import { z } from 'zod'

const zWebVhSchemaContent = z.looseObject({
  attrNames: z.array(z.string()).min(1),
  name: z.string(),
  version: z.string(),
  issuerId: z.string(),
})
type WebVhSchemaContent = z.output<typeof zWebVhSchemaContent>

const zWebVhCredDefContent = z.looseObject({
  issuerId: z.string(),
  schemaId: z.string(),
  type: z.string(),
  tag: z.string(),
  value: z.record(z.string(), z.unknown()),
})
type WebVhCredDefContent = z.output<typeof zWebVhCredDefContent>

const zWebVhRevRegDefContent = z.looseObject({
  issuerId: z.string(),
  revocDefType: z.string(),
  credDefId: z.string(),
  tag: z.string(),
  value: z.record(z.string(), z.unknown()),
})
type WebVhRevRegDefContent = z.output<typeof zWebVhRevRegDefContent>
const zWebVhUnknownContent = z.record(z.string(), z.unknown())

export type WebVhAnonCredsContent =
  | WebVhSchemaContent
  | WebVhCredDefContent
  | WebVhRevRegDefContent
  | Record<string, unknown>

export function parseWebVhAnonCredsContent(value: unknown): WebVhAnonCredsContent {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return zWebVhUnknownContent.parse(value)
  if ('attrNames' in value) return zWebVhSchemaContent.parse(value)
  if ('schemaId' in value) return zWebVhCredDefContent.parse(value)
  if ('revocDefType' in value) return zWebVhRevRegDefContent.parse(value)

  return zWebVhUnknownContent.parse(value)
}
