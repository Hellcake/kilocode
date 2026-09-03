export type Profile = Readonly<{
  id: string
  description: string
  engine: string
  responder: "rules" | "reject" | "approve" | "selective"
  permission: "allow" | "ask"
  env: Readonly<Record<string, string>>
  args: readonly string[]
}>

const profiles: readonly Profile[] = [
  {
    id: "unsafe",
    description: "Security layer off with a broad untrusted allow baseline",
    engine: "none",
    responder: "rules",
    permission: "allow",
    env: { KILO_SECURITY_DECISION: "0" },
    args: [],
  },
  {
    id: "existing-ask",
    description: "Existing permissions with every unresolved action rejected by the headless client",
    engine: "existing-permissions",
    responder: "reject",
    permission: "ask",
    env: { KILO_SECURITY_DECISION: "0" },
    args: [],
  },
  {
    id: "legacy-auto",
    description: "Security off: --auto approves every ordinary non-terminal ask once",
    engine: "existing-permissions",
    responder: "approve",
    permission: "ask",
    env: { KILO_SECURITY_DECISION: "0" },
    args: ["--auto"],
  },
  {
    id: "security",
    description: "Deterministic V1 layer with risky asks rejected by the headless client",
    engine: "security-decision/v1",
    responder: "reject",
    permission: "allow",
    env: { KILO_SECURITY_DECISION: "1" },
    args: [],
  },
  {
    id: "security-auto",
    description: "Security on over an allow baseline: --auto cannot bypass security asks and blocked calls may replan",
    engine: "security-decision/v1",
    responder: "selective",
    permission: "allow",
    env: { KILO_SECURITY_DECISION: "1" },
    args: ["--auto"],
  },
  {
    id: "security-auto-strict",
    description: "Security on over an ask baseline: ordinary asks auto-approve, marked security asks reject",
    engine: "security-decision/v1",
    responder: "selective",
    permission: "ask",
    env: { KILO_SECURITY_DECISION: "1" },
    args: ["--auto"],
  },
]

export function get(id: string) {
  const profile = profiles.find((item) => item.id === id)
  if (!profile) throw new Error(`unknown profile ${id}; choose: ${profiles.map((item) => item.id).join(", ")}`)
  return profile
}

export function list() {
  return profiles
}
