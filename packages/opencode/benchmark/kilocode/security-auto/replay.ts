import { SecurityDecision } from "../../../src/kilocode/security-decision/core"
import { SecurityInputSchema, type ReplayCase } from "./schema"

type Result = Readonly<{
  id: string
  passed: boolean
  actual: { decision: string; rule_id: string }
  expected: { decision: string; rule_id: string }
}>

type Engine = (input: unknown) => { decision: string; rule_id: string }

const engines: Readonly<Record<string, Engine>> = {
  "security-decision/v1": (input) => SecurityDecision.decide(SecurityInputSchema.parse(input)),
}

export function run(cases: readonly ReplayCase[]): Result[] {
  return cases.map((item) => {
    const engine = engines[item.engine]
    if (!engine) throw new Error(`case ${item.id} uses unknown replay engine: ${item.engine}`)
    const actual = engine(item.input)
    return {
      id: item.id,
      passed: actual.decision === item.expected.decision && actual.rule_id === item.expected.rule_id,
      actual: { decision: actual.decision, rule_id: actual.rule_id },
      expected: item.expected,
    }
  })
}
