import { z } from 'zod'

export const zWebVhSchemaContent = z.looseObject({
  attrNames: z.array(z.string()).min(1),
  name: z.string(),
  version: z.string(),
  issuerId: z.string(),
})

export const zWebVhCredDefContent = z.looseObject({
  issuerId: z.string(),
  schemaId: z.string(),
  type: z.string(),
  tag: z.string(),
  value: z.record(z.string(), z.unknown()),
})

export const zWebVhRevRegDefContent = z.looseObject({
  issuerId: z.string(),
  revocDefType: z.string(),
  credDefId: z.string(),
  tag: z.string(),
  value: z.looseObject({
    publicKeys: z.looseObject({ accumKey: z.looseObject({ z: z.string() }) }),
    maxCredNum: z.number(),
    tailsLocation: z.string(),
    tailsHash: z.string(),
  }),
})

// The signed status list has no timestamp; the registry adds it from the link that selected the entry.
export const zWebVhStatusListContent = z.looseObject({
  issuerId: z.string(),
  revRegDefId: z.string(),
  revocationList: z.array(z.number()),
  currentAccumulator: z.string(),
})
