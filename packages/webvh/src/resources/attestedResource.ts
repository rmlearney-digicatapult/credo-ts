import { z } from 'zod'

export const zWebVhAttestedResourceProof = z.looseObject({
  type: z.string(),
  cryptosuite: z.string(),
  proofPurpose: z.string(),
  proofValue: z.string(),
  verificationMethod: z.string(),
})
export type WebVhAttestedResourceProof = z.output<typeof zWebVhAttestedResourceProof>

export const zWebVhAttestedResourceLink = z.looseObject({
  id: z.string(),
  type: z.string(),
  timestamp: z.number().nullish(),
  digestMultibase: z.string().nullish(),
})
export type WebVhAttestedResourceLink = z.output<typeof zWebVhAttestedResourceLink>

export const zWebVhAttestedResource = z
  .looseObject({
    '@context': z.array(z.string()),
    type: z.union([z.string(), z.array(z.string())]),
    id: z.string(),
    content: z.record(z.string(), z.unknown()),
    proof: zWebVhAttestedResourceProof,
    metadata: z.record(z.string(), z.unknown()).nullish(),
    links: z.array(zWebVhAttestedResourceLink).nullish(),
  })
  .transform(({ type, ...resource }) => ({
    ...resource,
    type: Array.isArray(type) ? type : [type],
  }))
export type WebVhAttestedResource = z.output<typeof zWebVhAttestedResource>
export type WebVhAttestedResourceInput = z.input<typeof zWebVhAttestedResource>

export function isWebVhAttestedResource(value: unknown): value is WebVhAttestedResourceInput {
  const result = zWebVhAttestedResource.safeParse(value)
  return result.success && result.data.type.includes('AttestedResource')
}
