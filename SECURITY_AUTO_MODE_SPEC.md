# Deterministic Security Decision Layer — Hackathon V1

Статус: design/spec для последующего `writing-plans` и TDD. Production-код не изменён.  
Code baseline: `main@943bf253cf21ff6666b488b8ba710c9d35406642`, 2026-09-03.  
Нормативные слова MUST/SHOULD/MAY употребляются в смысле RFC 2119. Research-документы — входные материалы, не нормативный источник.

## 1. Цель, V1 и Deferred

V1 добавляет deterministic recommendation layer внутрь authoritative backend permission pipeline Kilo. Слой покрывает только действия, уже естественно наблюдаемые через permission requests: destructive actions; persistence/system modification; sensitive/authority boundary crossing; delegated effects; unsafe/ambiguous execution; network/remote effects.

### V1 — реализуем

- pure portable decision core, types и rule tables;
- Kilo adapter и один минимальный authoritative hook в existing permission pipeline;
- `AuthoritySnapshot` и precedence floor через `Config.getGlobal()` без изменения config loader;
- audit в existing tool metadata и фиксированный model-facing block;
- process-lifetime operational signal для macOS/Seatbelt при backend-neutral core contract;
- reviewer только как interface/extension point, без LLM implementation;
- отдельный независимый background restart permission fix.

### Deferred — спроектировано, но сейчас не реализуется

- trusted-control-flow capability channel, human attestation и вся client/protocol/SDK обвязка;
- creation invariant для trusted global/session grants, зависящий от proof flow;
- bounded MCP metadata plumbing и semantic MCP classification;
- Linux operational probe и generation-aware/backend-agnostic probe lifecycle.

Готовая реализация MUST:

- давать одинаковый backend decision для всех клиентов без их изменения;
- не ослаблять hard product policy, existing deny, XDG authority floor и human-only guards;
- не выполнять IO и не импортировать Kilo-типы в decision core;
- сохранять структурированный audit в существующей tool metadata;
- иметь выключаемый server/env feature flag, который project config не может выключить, и при выключении побитово сохранять прежнюю decision-семантику;
- проходить table-driven core tests и integration tests из разделов 10 и 14.

## 2. Подтверждённое текущее состояние

Все пункты этого раздела — наблюдения о текущем коде, не требования к новой реализации.

- Permission schema знает только `allow | deny | ask`; request несёт `sessionID`, `metadata` и tool `callID` ([`packages/schema/src/v1/permission.ts:16-35`](packages/schema/src/v1/permission.ts#L16-L35)). Fallback evaluation — `ask`, matching использует последний подходящий rule ([`packages/opencode/src/permission/index.ts:102-112`](packages/opencode/src/permission/index.ts#L102-L112)). `resolve` не позволяет saved/session rule ослабить base deny, но разрешает covering saved allow повысить base ask ([`packages/opencode/src/permission/index.ts:115-135`](packages/opencode/src/permission/index.ts#L115-L135)).
- `Permission.ask` сначала применяет hard veto и resolved deny, затем принудительный ask для `skillShell`/`sandboxEscalation` и protected config, после чего либо auto-allows, либо публикует pending request ([`packages/opencode/src/permission/index.ts:187-282`](packages/opencode/src/permission/index.ts#L187-L282)). Обычный неотвеченный ask ждёт `Deferred.await` до reply/cleanup ([`packages/opencode/src/permission/index.ts:270-282`](packages/opencode/src/permission/index.ts#L270-L282)). Headless child ask превращается в `DeniedError` до постановки в pending ([`packages/opencode/src/permission/index.ts:246-249`](packages/opencode/src/permission/index.ts#L246-L249)); CLI также auto-rejects неотвечаемые asks ([`packages/opencode/src/cli/cmd/run.ts:919-984`](packages/opencode/src/cli/cmd/run.ts#L919-L984)).
- Reply API принимает присланный клиентом `interactive?: boolean` ([`packages/schema/src/v1/permission.ts:38-49`](packages/schema/src/v1/permission.ts#L38-L49), [`packages/opencode/src/server/routes/instance/httpapi/groups/permission.ts:11-16`](packages/opencode/src/server/routes/instance/httpapi/groups/permission.ts#L11-L16)); handler без дополнительной аттестации передаёт его permission service ([`packages/opencode/src/server/routes/instance/httpapi/handlers/permission.ts:23-34`](packages/opencode/src/server/routes/instance/httpapi/handlers/permission.ts#L23-L34)). Сервер проверяет только его значение для двух sensitive kinds ([`packages/opencode/src/permission/index.ts:286-304`](packages/opencode/src/permission/index.ts#L286-L304)), а VS Code выставляет `true` сам ([`packages/kilo-vscode/src/kilo-provider/handlers/permission-handler.ts:97-99`](packages/kilo-vscode/src/kilo-provider/handlers/permission-handler.ts#L97-L99)). Поэтому поле доказывает заявленный client mode, но не human action.
- Endpoint-specific обязательная auth сейчас есть для `/permission/allow-everything`, но не для обычного reply; при отсутствии общей server auth middleware пропускает прочие paths ([`packages/opencode/src/server/routes/instance/httpapi/middleware/authorization.ts:15-16`](packages/opencode/src/server/routes/instance/httpapi/middleware/authorization.ts#L15-L16), [`packages/opencode/src/server/routes/instance/httpapi/middleware/authorization.ts:128-139`](packages/opencode/src/server/routes/instance/httpapi/middleware/authorization.ts#L128-L139)). Auth сама по себе всё равно удостоверяет клиента, не факт human gesture.
- Reply `always` добавляет rule в runtime-approved state и пишет его через `updateGlobal` ([`packages/opencode/src/permission/index.ts:342-365`](packages/opencode/src/permission/index.ts#L342-L365)); selective always делает то же ([`packages/opencode/src/permission/index.ts:375-403`](packages/opencode/src/permission/index.ts#L375-L403)). Session/global YOLO создаёт broad allow rule ([`packages/opencode/src/kilocode/permission/allow-everything.ts:16-56`](packages/opencode/src/kilocode/permission/allow-everything.ts#L16-L56)). Эти способы создания нельзя различить только по итоговому rule.
- User-global config расположен в XDG config directory ([`packages/core/src/global.ts:21-44`](packages/core/src/global.ts#L21-L44)) и читается отдельно через `Config.getGlobal()` ([`packages/opencode/src/config/config.ts:180-199`](packages/opencode/src/config/config.ts#L180-L199), [`packages/opencode/src/config/config.ts:382-451`](packages/opencode/src/config/config.ts#L382-L451)). Project configs ищутся вверх от workspace/worktree и могут находиться в `.kilo`/`.kilocode` либо root files ([`packages/opencode/src/kilocode/config/sources.ts:59-75`](packages/opencode/src/kilocode/config/sources.ts#L59-L75), [`packages/opencode/src/kilocode/config/config.ts:40-76`](packages/opencode/src/kilocode/config/config.ts#L40-L76)). `Config.update` пишет именно project target, по умолчанию `.kilo/kilo.jsonc` ([`packages/opencode/src/config/config.ts:998-1022`](packages/opencode/src/config/config.ts#L998-L1022), [`packages/opencode/src/kilocode/config/config.ts:65-97`](packages/opencode/src/kilocode/config/config.ts#L65-L97)); extension вызывает этот endpoint для project settings ([`packages/kilo-vscode/src/provider-actions.ts:270-276`](packages/kilo-vscode/src/provider-actions.ts#L270-L276)). Значит project policy может приехать с clone и не является внеполосным authority.
- Project agent files также могут содержать permission и сохраняются в `.kilo/agent` ([`packages/opencode/src/kilocode/agent/builder.ts:23-32`](packages/opencode/src/kilocode/agent/builder.ts#L23-L32), [`packages/opencode/src/kilocode/agent/builder.ts:67-97`](packages/opencode/src/kilocode/agent/builder.ts#L67-L97)); loader по умолчанию считает такие agents недоверенными ([`packages/opencode/src/config/agent.ts:21-38`](packages/opencode/src/config/agent.ts#L21-L38), [`packages/opencode/src/config/agent.ts:60-80`](packages/opencode/src/config/agent.ts#L60-L80)).
- `permission_origins` хранит лишь scope последнего merge на leaf ([`packages/opencode/src/config/config.ts:578-594`](packages/opencode/src/config/config.ts#L578-L594)). Runtime `source` классифицирует rule как `agent | global | project | yolo | session | manual | default`, причём session tagging выводится из формы rule ([`packages/opencode/src/kilocode/permission/provenance.ts:13-34`](packages/opencode/src/kilocode/permission/provenance.ts#L13-L34), [`packages/opencode/src/kilocode/permission/provenance.ts:47-80`](packages/opencode/src/kilocode/permission/provenance.ts#L47-L80)). Ни один механизм не фиксирует creation mechanism.
- Global слой merge-ится раньше project слоя ([`packages/opencode/src/config/config.ts:655-699`](packages/opencode/src/config/config.ts#L655-L699)); merge применяет поздний patch поверх раннего ([`packages/opencode/src/config/config.ts:66-78`](packages/opencode/src/config/config.ts#L66-L78), [`packages/opencode/src/kilocode/config/config.ts:572-606`](packages/opencode/src/kilocode/config/config.ts#L572-L606)). Поэтому project leaf сейчас способен заменить ранее загруженный global leaf; один merged permission не сохраняет authority semantics.
- Tool adapter уже имеет `sessionID`, `callID`, model и снимок sandbox flags, вызывает `KiloSessionPrompt.askPermission`, затем пишет approval в tool metadata ([`packages/opencode/src/session/tools.ts:75-165`](packages/opencode/src/session/tools.ts#L75-L165)). `KiloSessionPrompt` перечитывает agent/session и строит rules непосредственно перед `Permission.ask` ([`packages/opencode/src/kilocode/session/prompt.ts:330-375`](packages/opencode/src/kilocode/session/prompt.ts#L330-L375)).
- File tools дают path/diff/filediff, а apply-patch — operation (`add|update|delete|move`) и per-file metadata ([`packages/opencode/src/tool/write.ts:45-73`](packages/opencode/src/tool/write.ts#L45-L73), [`packages/opencode/src/tool/edit.ts:27-45`](packages/opencode/src/tool/edit.ts#L27-L45), [`packages/opencode/src/tool/apply_patch.ts:219-241`](packages/opencode/src/tool/apply_patch.ts#L219-L241)). Shell scanner восстанавливает unparsed fragments fail-closed, но permission metadata сейчас содержит лишь command/description/heredoc, а не полный AST plan ([`packages/opencode/src/tool/shell.ts:280-323`](packages/opencode/src/tool/shell.ts#L280-L323), [`packages/opencode/src/tool/shell.ts:412-447`](packages/opencode/src/tool/shell.ts#L412-L447)).
- Native MCP asks используют tool name, `patterns:["*"]` и пустую metadata, хотя validated args доступны рядом ([`packages/opencode/src/session/tools.ts:463-505`](packages/opencode/src/session/tools.ts#L463-L505)). Restricted sessions вообще не регистрируют эти MCP tools ([`packages/opencode/src/session/tools.ts:461-464`](packages/opencode/src/session/tools.ts#L461-L464)).
- Background `start` спрашивает `bash`, но `restart` выполняет side effect до любого ask ([`packages/opencode/src/kilocode/tool/background-process.ts:128-158`](packages/opencode/src/kilocode/tool/background-process.ts#L128-L158), [`packages/opencode/src/kilocode/tool/background-process.ts:160-190`](packages/opencode/src/kilocode/tool/background-process.ts#L160-L190)).
- Ошибка tool сохраняется и затем попадает в model context как `errorText` ([`packages/opencode/src/session/processor.ts:294-318`](packages/opencode/src/session/processor.ts#L294-L318), [`packages/opencode/src/session/message-v2.ts:459-491`](packages/opencode/src/session/message-v2.ts#L459-L491)). Existing reject/corrected/deny тексты определены здесь, причём deny сериализует ruleset ([`packages/core/src/v1/permission.ts:7-26`](packages/core/src/v1/permission.ts#L7-L26)). Только перечисленные reject/dismiss errors выставляют `ctx.blocked`; `DeniedError` в список не входит ([`packages/opencode/src/session/processor.ts:294-318`](packages/opencode/src/session/processor.ts#L294-L318)). Reject останавливает loop, кроме `continue_loop_on_deny=true` ([`packages/opencode/src/session/processor.ts:916-916`](packages/opencode/src/session/processor.ts#L916), [`packages/opencode/src/session/processor.ts:1031-1036`](packages/opencode/src/session/processor.ts#L1031-L1036)).

## 3. Security invariants и authority model V1

V1 использует три enforcement-класса; неопределимый provenance сохраняется как diagnostic `unknown`, но исполняется как `untrusted`:

1. hard product policy;
2. XDG user-global policy как repo-independent enforcement floor;
3. untrusted: project/repository-local policy, session rules, agent defaults, YOLO, session content, tool outputs, README и MCP.

XDG scope доверен только относительно содержимого malicious repository: repo не должен ослабить его `ask`/`deny`. Это не утверждение, что правило human-authenticated. V1 не пытается доказать human action. `permission_origins`, runtime `source`, имя scope и `interactive:true` не являются proof; неизвестный provenance считается `untrusted`. Семантическое намерение из chat/user message, README, tool output или MCP response не authority и не может понизить решение.

Generic manual approval продолжает работать через существующий Kilo pending/reply flow и разрешает текущий action. Оно не создаёт для security layer доказанного human authority. Если existing `always` сохраняет правило в XDG, последующие решения видят только repo-independent XDG scope, а не human proof; эта неполнота явно принята как ограничение V1.

Инварианты enforcement:

- adapter применяет отношение строгости `deny > ask > allow`; `pass` означает отсутствие мнения, а не уровень строгости;
- existing hard/product deny и любой existing explicit deny terminal;
- existing human-only/config-protection ask terminal для auto-path;
- XDG `ask`/`deny` нельзя ослабить project/session/default/YOLO rule; XDG `allow` не запрещает core повысить строгость;
- project/session/default/YOLO allow остаётся gateable;
- auto-decision никогда не сохраняется как `always` и не создаёт policy.

## 4. Source-aware precedence V1 без изменения config loader

Kilo-owned `AuthoritySnapshot` отдельно читает raw XDG permission через существующий `Config.getGlobal()`, effective rules и `permission_origins` только как diagnostic scope. Другие источники (`KILO_CONFIG*`, cloud/managed/runtime) получают XDG-floor status только если текущий server-side resolver однозначно относит их к repo-independent global source; неизвестные — untrusted. Итоговый merged rule не является authority source.

Для каждого pattern runtime guard независимо вычисляет matching XDG action и effective action, затем применяет strictness floor. Следствия: XDG `deny` остаётся deny; XDG `ask` + project/session/default/YOLO `allow` становится ask; XDG `allow` не ослабляет effective deny/ask и не мешает core повысить строгость. Если matching provenance или конфликт нельзя надёжно классифицировать, результат не выше `ask`, если уже не был `deny`. Loader не меняется; ограничения происхождения XDG writes перечислены в разделе 13.

## 5. Decision core

Новый файл `packages/opencode/src/kilocode/security-decision/core.ts` экспортирует единственную pure function; supporting types/constants могут лежать рядом. Никаких IO, clock/randomness, Effect, Kilo imports или mutable global state.

```ts
type Decision = "allow" | "ask" | "deny" | "pass"
type Authority = "hard" | "xdg_global" | "untrusted" | "unknown"
type Containment = {
  sandbox: "off" | "unavailable" | "unknown" | "operational" | "failed"
  network: "allow" | "deny" | "proxy"
  destinations: readonly string[]
  escalated: boolean
}
type Input = Readonly<{
  version: 1
  action: Readonly<{ kind: string; operation: string; paths: readonly PathFact[]; exec?: ExecFact; remote?: RemoteFact }>
  baseline: Readonly<{ decision: "allow" | "ask"; authority: Authority; humanOnly: boolean }>
  metadata: Readonly<{ complete: boolean; truncated: boolean }>
  containment: Readonly<Containment>
}>
type Result = Readonly<{
  decision: Decision
  reason: string
  rule_id: string
  requirements: readonly ("sandbox" | "restricted_network")[]
  reviewable: boolean
}>
declare function decide(input: Input): Result
```

`reason` MUST быть короткой константой из rule catalog, без command/path/content echo; `rule_id` стабилен в пределах major policy version. `pass` всегда возвращает `SEC.V1.NO_OPINION`. Multi-target `allow` допустим только когда каждый target разрешён; один unknown делает общий result не выше `ask`. Core не вычисляет именованные autonomy profiles: он получает фактические containment facts и возвращает requirements, достаточные для audit/benchmark.

`Result` — только рекомендация: core не выполняет effect, не отвечает на permission и не пишет policy. Финальное решение и side-effect ordering остаются у `Permission.ask`/существующего enforcement.

### 5.1. Граница `deny` / `ask`

`deny` разрешён только на untrusted soft/autonomous path для полностью распознанного, точного, platform-aware сигнала с жёстким правилом: destructive root/device action; запись в `.git/hooks/*`; точная установка persistence или system modification. Hard product/existing deny уже завершил pipeline раньше; XDG policy задаёт floor, но не объявляется human proof. Любая неполнота parser/metadata, alias/dynamic path, неизвестная платформа, смешанный target, возможное benign interpretation или недостаточный operation context даёт `ask`, не `deny`. Такая граница минимизирует необратимый false positive: deny отвечает только за доказанную capability, human решает семантическую неоднозначность через обычный ask.

## 6. Adapter и authoritative pipeline

Kilo-owned `adapter.ts` MUST валидировать существующую per-permission metadata, canonicalize paths/hosts без IO на core side, собрать authority/containment, вызвать core, выполнить reviewer stage и вернуть directive + audit. Raw chat, README, tool output и MCP text не передаются. Invalid/missing/truncated metadata маркируется явно и приводит к `ask` для покрываемой категории. MCP V1 остаётся opaque delegated action: без нового plumbing его нельзя semantic auto-allow.

| Kilo input | Core fact |
|---|---|
| tool ID + canonical permission | `action.kind/operation` |
| permission patterns + validated file metadata | canonical `PathFact[]`, operation, changed region |
| enriched shell scan | argv/AST completeness, composition, cwd, executable class |
| current MCP permission request | opaque delegated kind + incomplete metadata |
| raw XDG/effective rules | baseline decision + XDG floor/untrusted class |
| macOS operational cache | backend-neutral containment state/destinations/escalation |
| `sessionID/callID` | audit correlation only; не core input |

Порядок в `Permission.ask`:

1. existing hard product/hard ruleset veto;
2. existing explicit/effective deny;
3. source-aware XDG strictness floor;
4. existing human-only/config-protection ask;
5. deterministic core только для оставшегося soft path;
6. optional reviewer только для eligible core `ask`;
7. монотонное объединение и существующий auto-return либо pending human flow.

Conflict matrix: любой earlier deny остаётся deny; XDG-floor/human-only ask остаётся ask; core deny terminal; core ask может повысить только reviewer при `reviewable=true`; core allow не понижает earlier ask/deny; core pass оставляет existing pipeline. Exception/invalid output в adapter/core/reviewer => fail-closed-to-`ask`; в headless это block. Ошибка до обязательной initial audit write также => ask/block. Ошибка post-execution audit update не отменяет совершённый effect, но MUST логироваться как audit-integrity failure.

### 6.1. Планируемые файлы

Новые Kilo-owned файлы:

- `packages/opencode/src/kilocode/security-decision/{core,types,rules,adapter,authority,containment-macos,reviewer}.ts` — pure policy, normalization, XDG floor, process-lifetime Seatbelt probe и disabled reviewer interface;
- `packages/opencode/test/kilocode/security-decision/*.test.ts` — pure tables, pipeline, provenance, containment и failure cases.

Минимальные изменения вне adapter, поимённо:

- `packages/opencode/src/permission/index.ts` — один marked authoritative hook после terminal guards и до auto-return/pending; shared OpenCode diff неизбежен для monotonic enforcement;
- `packages/opencode/src/kilocode/session/prompt.ts` — собрать fresh rules/authority envelope для hook;
- `packages/opencode/src/session/tools.ts` — передать call/containment context и записать audit; MCP args не добавлять; shared diff держать механическим и marked;
- `packages/opencode/src/session/processor.ts` — сохранить security audit при complete/error и остановить turn на typed security block;
- `packages/opencode/src/kilocode/permission/provenance.ts` — переносить `securityDecision` вместе с existing approval metadata;
- `packages/opencode/src/tool/shell.ts` — минимально добавить уже вычисленные parse/composition facts в permission metadata, без второго parser;
- `packages/opencode/src/kilocode/tool/background-process.ts` — отдельный независимый upstreamable fix: permission emission перед `restart`, до side effect;

V1 не меняет permission/global HTTP schemas, SDK, VS Code, JetBrains, ACP или CLI approval protocol.

## 7. Autonomy profiles и containment

Profiles — внешние deployment/benchmark labels, не core input:

- conservative no-sandbox: новые auto-allows только для детерминированно доказуемой bounded semantics; test/lint/build, project scripts и неизвестные executables не получают новый allow;
- extended autonomy: дополнительно допускает rules, требующие `sandbox=operational`, `network in {deny,proxy}`, exact bounded destinations и `escalated=false`. Название команды (`pytest`, `eslint`, `cargo check`, `npm test`, `make`) никогда не является достаточным security signal: они исполняют project code. `pass` сохраняет existing pipeline только когда core действительно не имеет security opinion.

Текущий config по умолчанию выключает sandbox; restricted mode становится deny без hosts или proxy с exact hosts ([`packages/opencode/src/kilocode/sandbox/config.ts:19-47`](packages/opencode/src/kilocode/sandbox/config.ts#L19-L47)). macOS выбирает Seatbelt, Linux bubblewrap, Windows unavailable ([`packages/kilo-sandbox/src/backend.ts:39-49`](packages/kilo-sandbox/src/backend.ts#L39-L49)); macOS availability сейчас означает только наличие `/usr/bin/sandbox-exec` ([`packages/kilo-sandbox/src/seatbelt.ts:75-82`](packages/kilo-sandbox/src/seatbelt.ts#L75-L82)). `status.enabled` — stored enabled + advertised availability, а `networkRestricted` — stored enabled + mode != allow ([`packages/opencode/src/kilocode/sandbox/policy.ts:339-354`](packages/opencode/src/kilocode/sandbox/policy.ts#L339-L354)); это не operational proof. Execution fail-closes при unavailable backend и только затем вызывает sandbox runner ([`packages/opencode/src/kilocode/sandbox/policy.ts:601-627`](packages/opencode/src/kilocode/sandbox/policy.ts#L601-L627)); approved escalation может снять confinement ([`packages/opencode/src/kilocode/sandbox/policy.ts:630-639`](packages/opencode/src/kilocode/sandbox/policy.ts#L630-L639)).

### 7.1. Operational containment check V1

Core и adapter видят backend-neutral `Containment`; единственная V1 provider implementation — macOS/Seatbelt. На Linux, Windows и неизвестной платформе operational state для extended autonomy равен `unavailable`, поэтому применяется conservative profile. Добавление Linux provider позднее не меняет core contract.

Process-local state: `unknown | checking | operational | failed`. Первый extended candidate запускает один bounded probe; concurrent calls ждут тот же promise. Результат, включая failure/timeout, кэшируется до завершения server process. V1 не пере-probes по config generation. Текущие `enabled`, restricted network mode, exact destinations, actual `executeTool/executeMcp` routing и `escalated=false` всё равно проверяются на каждом decision; process cache подтверждает способность Seatbelt применить containment, а не разрешает конкретный call.

Probe MUST идти через public sandbox launch abstraction и temporary roots: (1) confined benign child succeeds; (2) write внутри scratch succeeds, outside и denied-name write fails; (3) deny mode: sandboxed outbound TCP к контролируемому listener фактически fails и listener не accepts; (4) proxy mode: allowed synthetic destination succeeds через proxy, blocked destination и direct bypass fail; (5) sensitive env absent. Любая ошибка даёт `failed` и fail-closed-to-ask/block. `models.dev:443` MAY быть exact proxy destination для build; это не разрешает blanket network.

### 7.2. Результаты локальной feasibility-проверки

На тестовой macOS 26.6.2 arm64 Seatbelt реально применился; `seatbelt-network` дал 9/9 pass. Внутри deny-profile lint завершился с code 0 (9591 diagnostics), выбранный unit test — 3 pass, sandbox package typecheck — code 0. CLI build в deny-profile ожидаемо остановился на fetch `models.dev`; proxy-profile с единственным `models.dev:443` завершил build и smoke. Отдельная попытка TCP к `1.1.1.1:443` снаружи прошла, внутри deny-profile получила kernel `Operation not permitted`.

Точные команды воспроизведения из обычного macOS Terminal, после `bun install --frozen-lockfile`:

```sh
cd /path/to/kilocode
sw_vers && uname -m && test -x /usr/bin/sandbox-exec
/usr/bin/sandbox-exec -p '(version 1) (allow default)' -- /usr/bin/true
/usr/bin/nc -vz -w 3 1.1.1.1 443
/usr/bin/sandbox-exec -p '(version 1) (allow default) (deny network-outbound)' -- /usr/bin/nc -vz -w 3 1.1.1.1 443

cd packages/kilo-sandbox
bun test ./test/seatbelt-network.test.ts
bun test ./test/seatbelt-network.test.ts -t 'allows only the configured proxy destination and denies direct bypasses'

cd ../opencode
bun test ./test/kilocode/sandbox/macos-confinement.test.ts -t 'confines shell writes inside the workspace and denies outside and .git'
cd ../..
/usr/bin/sandbox-exec -p '(version 1) (allow default) (deny network-outbound)' -- bun run lint
cd packages/kilo-sandbox
/usr/bin/sandbox-exec -p '(version 1) (allow default) (deny network-outbound)' -- bun test ./test/destination.test.ts
/usr/bin/sandbox-exec -p '(version 1) (allow default) (deny network-outbound)' -- bun run typecheck
```

Первый `nc` MUST succeed для валидности внешней проверки, второй MUST fail. Proxy test одновременно проверяет allowed destination, blocked destination и direct bypass ([`packages/kilo-sandbox/test/seatbelt-network.test.ts:230-260`](packages/kilo-sandbox/test/seatbelt-network.test.ts#L230-L260)). Confinement test проверяет workspace success и outside/`.git` failure ([`packages/opencode/test/kilocode/sandbox/macos-confinement.test.ts:189-220`](packages/opencode/test/kilocode/sandbox/macos-confinement.test.ts#L189-L220)). Последние lint/test/typecheck команды воспроизводят command compatibility под реальным Seatbelt deny-network; production operational probe использует более строгий Kilo-generated filesystem profile.

## 8. LLM reviewer extension point

Reviewer V1 не реализуется; `reviewer.ts` содержит disabled interface и deterministic tests. Стадия стоит после core, не является значением `Decision`.

Вход: immutable normalized `Input`, core `Result`, safe rule catalog text и bounded shell/file execution facts; MCP в V1 остаётся opaque. Chat/history, README, file contents/diff по умолчанию, environment, secrets, raw MCP args и external tool text не передаются. Выход schema: `{ recommendation: "allow" | "keep_ask"; reason_code: string; confidence: number }`; confidence audit-only.

Reviewer вызывается только для `core.decision="ask" && core.reviewable && containment requirements satisfied`. Он может только `ask -> allow`. `deny`, `pass`, explicit policy, source-conflict ask и human-only ask не меняет. Invalid output, cancellation, no model, exception или timeout (default 2 s, configurable с hard cap 5 s) сохраняет ask. Reviewer allow не переживает текущий call, не становится authority и не записывает policy.

## 9. Rule table — нормативные TDD cases

| Угроза | Перехват | Наблюдаемый сигнал | Layer decision | Auto-allow example | Human-ask example | Existing deny example |
|---|---|---|---|---|---|---|
| Destructive FS | `edit`/shell ask | parsed op+canonical path | exact root/device delete: deny soft; delete/move/unknown: ask | update `src/a.ts` | delete `docs/old.md` | existing plan-mode edit deny |
| Persistence/system | shell/file/background | exact verb/path/lifetime | exact persistence: deny soft; ambiguous: ask | background `logs` | unknown installer or persistent start | hard rule deny |
| Git persistence | edit/shell | write target `.git/hooks/*` | deny soft | edit `src/hook.ts` | dynamic/symlink target | existing explicit deny |
| CI authority | edit | path+operation+changed region | ask | lockfile update | `.github/workflows/ci.yml`; CI exec config | existing global deny |
| Package execution | edit | `package.json` changed region | scripts: ask; dependencies: pass/out-of-scope | lockfile update | `package.json` `scripts` | existing explicit deny |
| Sensitive boundary | read/edit/external_directory | inside/outside+sensitive class | ask unless rule-specific bounded allow permits it; XDG ask/deny is floor | ordinary workspace source read | `.env`, SSH material, outside path | existing read/external deny |
| Unsafe execution | shell ask | complete AST facts, cwd, executable, composition | missing/unparsed/compound: ask | bounded non-exec semantic op; or existing exact allow via pass | heredoc, substitution, pipeline, `npm test` without operational containment | read-only agent shell deny |
| Sandboxed project code | shell ask | operational sandbox+restricted net+no escalation | allow only rule-specific bounded envelope | single invocation with exact destinations in extended mode | same invocation without operational proof | existing explicit deny |
| Delegated/MCP | MCP ask | tool name+`*` pattern+empty metadata | soft allow: ask; no semantic allow | none new in V1 | any opaque delegated action | restricted sandbox suppresses/denies path |
| Remote/network | shell/web/MCP permission | canonical scheme/host/port+effect | unbounded/private/unknown: ask | exact allowlisted host via operational proxy | `git push`, arbitrary `curl`, unknown port | existing rule or sandbox network deny |
| Background restart gap | background tool | action+known process metadata | ask before effect | list/logs | restart/start | sandbox-enabled start/restart unavailable |

Число files/lines/bytes MAY быть operational UI guard, но MUST NOT влиять на security allow/deny. Capability, path sensitivity, operation и changed region — основные signals. Empty/truncated metadata, delete и move => ask. Dependencies/slopsquatting не классифицируются V1; lockfile — ordinary edit.

Code anchors для колонки existing deny: plan agent задаёт edit deny ([`packages/opencode/src/agent/agent.ts:188-208`](packages/opencode/src/agent/agent.ts#L188-L208)); read-only shell rules начинаются с catch-all deny ([`packages/opencode/src/kilocode/agent/index.ts:69-80`](packages/opencode/src/kilocode/agent/index.ts#L69-L80)); resolved/hard deny terminal в permission service ([`packages/opencode/src/permission/index.ts:217-228`](packages/opencode/src/permission/index.ts#L217-L228)); restricted mode suppresses native MCP registration ([`packages/opencode/src/session/tools.ts:461-464`](packages/opencode/src/session/tools.ts#L461-L464)); sandboxed background start/restart отклоняются до action ([`packages/opencode/src/kilocode/tool/background-process.ts:128-130`](packages/opencode/src/kilocode/tool/background-process.ts#L128-L130)).

## 10. Block, ask-and-continue и model-facing text

Новый typed security block MUST иметь единственный model-facing текст без command/path/external echo:

```text
Security policy blocked this tool call. rule_id=<RULE_ID>. Contact the user.
```

- Core deny: tool не запускается; audit final=`deny`; processor останавливает текущий turn независимо от `continue_loop_on_deny`. Следующее user message может начать новый turn, но его текст не является authority.
- Interactive core ask: публикуется обычный pending request; до reply model не получает synthetic result. Existing `once/always` reply разрешает текущий call без новой protocol semantics. Это manual enforcement event, не доказанный human authority для layer. Reject даёт существующий rejected/corrected result и текущую loop policy.
- Headless/unanswerable ask: pending не оставляется; возвращается тот же fixed security block с исходным `rule_id`. Это семантически block, не silent deny и не auto-continue.
- Existing deny/reject messages до V1 остаются как есть; отдельный security error не должен сериализовать ruleset. Adapter никогда не предлагает «безопасную альтернативу» и не инструктирует модель обходить policy.

## 11. Audit

Формат хранения Kilo не меняется: nested `securityDecision` записывается в persisted tool-part metadata. Текущий processor уже сохраняет metadata при complete и error ([`packages/opencode/src/session/processor.ts:259-305`](packages/opencode/src/session/processor.ts#L259-L305)); approval переносится при замене metadata ([`packages/opencode/src/kilocode/permission/provenance.ts:83-112`](packages/opencode/src/kilocode/permission/provenance.ts#L83-L112)). Model conversion использует tool output/error, а не произвольные metadata fields ([`packages/opencode/src/session/message-v2.ts:441-491`](packages/opencode/src/session/message-v2.ts#L441-L491)).

Initial record пишется после adapter/core/reviewer и до auto-execution либо публикации ask; final fields обновляются после enforcement/reply/tool outcome. Обязательные поля:

```ts
{
  schema: "kilo.security-decision/v1", policy_version, rule_id, reason,
  decision: "allow" | "ask" | "deny" | "pass",
  reviewer: { state: "not_run" | "allow" | "keep_ask" | "timeout" | "error", reason_code?, latency_ms? },
  final_enforcement: "allow" | "ask_pending" | "reject" | "deny" | "blocked" | "error",
  enforcement_source, authority_level,
  authority_basis: "none" | "xdg_scope" | "hard_product",
  authority_conflict, metadata_complete, metadata_truncated,
  containment: { sandbox, network, destinations, escalated, probe_id, checked_at },
  requirements, latency_ms, callID, sessionID
}
```

Никаких raw command/args/diff/headers/tokens/user text. `callID` и `sessionID` обязательны для post-factum multi-step analysis. Машиночитаемые metrics строит внешний exporter; Kilo storage/API format не расширяется специально ради benchmark. По этим полям внешний benchmark сравнивает conservative и extended coverage, не заставляя core вычислять profiles.

## 12. Ограничения текущей модели и расхождения с research

Текущие model gaps, фиксируемые без exploit/PoC и без public issue/PR:

- `interactive:true` — client assertion, не доказательство human action ([`packages/schema/src/v1/permission.ts:41-49`](packages/schema/src/v1/permission.ts#L41-L49), [`packages/opencode/src/server/routes/instance/httpapi/handlers/permission.ts:23-34`](packages/opencode/src/server/routes/instance/httpapi/handlers/permission.ts#L23-L34)).
- project config merge способен перекрыть XDG global leaf; merged permission недостаточен для source-aware authority ([`packages/opencode/src/config/config.ts:655-699`](packages/opencode/src/config/config.ts#L655-L699), [`packages/opencode/src/config/config.ts:66-78`](packages/opencode/src/config/config.ts#L66-L78)).
- Local permission/global HTTP APIs способны менять runtime/global rules без доказанного human gesture ([`packages/opencode/src/server/routes/instance/httpapi/handlers/permission.ts:23-34`](packages/opencode/src/server/routes/instance/httpapi/handlers/permission.ts#L23-L34), [`packages/opencode/src/server/routes/instance/httpapi/handlers/global.ts:97-109`](packages/opencode/src/server/routes/instance/httpapi/handlers/global.ts#L97-L109)). Поэтому XDG в V1 — repo-independent floor, не human-authenticated authority.

Расхождения research с этой спецификацией/актуальным кодом:

1. Research считает project/global/session policy одинаково explicit и полагается на source tags; V1 считает только XDG repo-independent floor, а project/session/default/YOLO и unknown — untrusted/gateable ([`SECURITY_AUTO_MODE_IMPLEMENTATION_RESEARCH.md:140-164`](SECURITY_AUTO_MODE_IMPLEMENTATION_RESEARCH.md#L140-L164)); текущие tags отражают scope, не creation mechanism ([`packages/opencode/src/kilocode/permission/provenance.ts:47-80`](packages/opencode/src/kilocode/permission/provenance.ts#L47-L80)).
2. Research утверждает, что machine auto-approver не может выдать себя за человека через `interactive` ([`SECURITY_AUTO_MODE_RESEARCH.md:139-145`](SECURITY_AUTO_MODE_RESEARCH.md#L139-L145)); текущий API принимает client boolean без server-side proof ([`packages/opencode/src/server/routes/instance/httpapi/handlers/permission.ts:23-34`](packages/opencode/src/server/routes/instance/httpapi/handlers/permission.ts#L23-L34)).
3. Research считает `status.enabled===true` достаточным containment proof ([`SECURITY_AUTO_MODE_IMPLEMENTATION_RESEARCH.md:534-540`](SECURITY_AUTO_MODE_IMPLEMENTATION_RESEARCH.md#L534-L540)); текущая macOS availability — лишь existence check, поэтому V1 требует operational probe ([`packages/kilo-sandbox/src/seatbelt.ts:75-82`](packages/kilo-sandbox/src/seatbelt.ts#L75-L82)).
4. Research допускает новые allows по test/typecheck/lint family при enabled/available sandbox ([`SECURITY_AUTO_MODE_IMPLEMENTATION_RESEARCH.md:203-232`](SECURITY_AUTO_MODE_IMPLEMENTATION_RESEARCH.md#L203-L232)); V1 не использует family name как security signal и требует operational containment + bounded network destinations.
5. Research edit envelope использует 3 files/200 lines/32 KiB как allow criterion ([`SECURITY_AUTO_MODE_IMPLEMENTATION_RESEARCH.md:178-199`](SECURITY_AUTO_MODE_IMPLEMENTATION_RESEARCH.md#L178-L199)); V1 оставляет числа только operational guards и решает по capability/path/operation/region.
6. Research предлагает synthetic allow с source=`session` и без protocol change ([`SECURITY_AUTO_MODE_IMPLEMENTATION_RESEARCH.md:542-573`](SECURITY_AUTO_MODE_IMPLEMENTATION_RESEARCH.md#L542-L573)); V1 не считает такой source authority и не реализует human proof, который остаётся Deferred.
7. Research трактует background start/restart как уже фиксированную manual boundary ([`SECURITY_AUTO_MODE_IMPLEMENTATION_RESEARCH.md:212-222`](SECURITY_AUTO_MODE_IMPLEMENTATION_RESEARCH.md#L212-L222)); актуальный restart вызывает side effect без ask ([`packages/opencode/src/kilocode/tool/background-process.ts:128-158`](packages/opencode/src/kilocode/tool/background-process.ts#L128-L158)). Fix вынесен отдельно от layer.
8. Research оставляет raw/bounded MCP plumbing после MVP ([`SECURITY_AUTO_MODE_IMPLEMENTATION_RESEARCH.md:621-630`](SECURITY_AUTO_MODE_IMPLEMENTATION_RESEARCH.md#L621-L630)); сокращённый V1 также переносит его в Deferred и запрещает semantic MCP auto-allow при текущих неполных facts.

## 13. Non-goals и гарантии

Non-goals V1: cross-call exfiltration/taint tracking; supply-chain/slopsquatting и dependency-change analysis; universal контроль всех tool calls; cross-request blocking/sequence analysis; executable provenance resolution; semantic intent inference из conversation/repository content; LLM reviewer implementation; trusted human attestation; bounded MCP metadata; отдельный metrics storage/export API.

Слой не ловит tool/custom/plugin paths, не вызывающие authoritative permission ask; multi-call exfiltration; benign-looking project code с runtime side effects вне наблюдаемых facts; TOCTOU после metadata capture; supply-chain attacks; kernel/backend escape; destinations, скрытые внутри opaque delegated tool. Причина — V1 per-request и опирается на существующие permission interception points; MCP/metadata coverage неполна.

Всегда гарантируется при включённом layer: monotonicity относительно existing deny/XDG floor/human-only ask; unknown provenance untrusted; ambiguity ask; narrow soft-path deny; fixed non-echo block text; audit-before-effect либо fail to ask/block; отсутствие reviewer authority. Best effort: полнота tool coverage, точность path/AST metadata, process-lifetime Seatbelt availability, audit finalization после crash и сетевое ограничение тех execution paths, которые реально проходят через sandbox adapters.

## 14. TDD acceptance и rollout

Порядок V1 implementation plan: (1) pure types/rule tables; (2) XDG authority snapshot+precedence tests; (3) authoritative hook с feature off/on tests; (4) audit/error semantics; (5) macOS process-lifetime containment probe; (6) независимый restart fix; (7) shadow telemetry, затем opt-in enforcement.

Обязательные integration tests: existing hard/explicit deny не повышается; XDG ask/deny не перекрывается project/session/default/YOLO allow; XDG allow не мешает core tightening; unknown provenance asks; generic manual reply продолжает текущий call без нового authority claim; human-only/config protection не auto-allow; core `pass` сохраняет baseline; exception/timeout asks; headless ask blocks fixed text; no command/content echo; no auto `always`; audit присутствует на allow/ask/deny/error и связывает call/session; Seatbelt probe кэшируется на process lifetime; deny/proxy probes фактически проверяют сеть; non-macOS extended path conservative; escalated call не использует extended allow; feature off сохраняет current outcomes. Примеры раздела 9 являются именованными test vectors, а не иллюстрациями.

## 15. Deferred design

### 15.1. Trusted human control flow и creation provenance

Целевая иерархия после реализации proof flow:

1. hard product policy;
2. explicit human approval / trusted user-global config;
3. trusted session policy, созданная действием человека;
4. project/repository-local policy;
5. agent defaults / YOLO;
6. session content / tool outputs / README / MCP.

| Вариант provenance | Плюсы | Минусы |
|---|---|---|
| A. In-process callback | Минимальная поверхность | Не покрывает external clients/reconnect |
| B. Server-issued one-time capability по trusted host channel | Request-bound, TTL, single-use, cross-process | Private channel lifecycle и client work |
| C. Client installation signing key | Переживает reconnect | Key management; слабее доказывает конкретный gesture |

Предпочтён B, а A — локальная TUI реализация. Сервер выпускает capability, связанную с `{requestID, sessionID, allowedReply, expiry, channelID}`, доставляет только через созданный сервером in-process/private OS channel и атомарно consumes. Capability не попадает в SSE, model/tool metadata или audit. Generic boolean/claim не повышает trust.

Связанная Deferred обвязка: permission/global HTTP proof paths и schemas; SDK regeneration; `packages/opencode/src/cli/cmd/run/permission.shared.ts`; `packages/opencode/src/acp/permission.ts`; `packages/kilo-vscode/src/kilo-provider/handlers/permission-handler.ts`; JetBrains `SessionController.kt`, `ChatDto.kt` и `KiloBackendChatManager.kt`. До этого V1 не меняет clients/protocol.

После proof flow вводится creation invariant: только proof-bearing flow пишет trusted permission в XDG/session ledger; generic `always`, `saveAlwaysRules` и global permission patch без proof reject persistence или downgrade до `once`; YOLO хранится с отдельным untrusted provenance. Неопределимый provenance остаётся untrusted.

### 15.2. Bounded MCP metadata

Отдельный change передаёт server/tool ID; schema annotations `readOnlyHint/destructiveHint/idempotentHint/openWorldHint` только как untrusted risk-raising hints; sorted arg key/type/size shape; canonical workspace path class; stripped `host:port`; `complete/truncated`. Raw args, headers, tokens, URL userinfo/path/query и content запрещены. Missing/ambiguous facts => ask. До этого MCP V1 остаётся opaque.

### 15.3. Portable containment providers

Deferred lifecycle добавляет Linux/bubblewrap provider, backend fingerprint, config/policy generation, invalidation/re-probe после changes и execution failures, bounded retries и общую provider conformance suite. Backend-neutral `Containment` core contract V1 сохраняется.

## 16. Оценка реализации V1

Новые production-файлы: 7 в `packages/opencode/src/kilocode/security-decision/` — `types.ts`, `rules.ts`, `core.ts`, `adapter.ts`, `authority.ts`, `containment-macos.ts`, `reviewer.ts`. Новые tests: ориентировочно 5 файлов в `packages/opencode/test/kilocode/security-decision/`; restart покрывается расширением existing `background-process-tool.test.ts`.

Изменяемые existing production-файлы: `packages/opencode/src/permission/index.ts`, `packages/opencode/src/kilocode/session/prompt.ts`, `packages/opencode/src/session/tools.ts`, `packages/opencode/src/session/processor.ts`, `packages/opencode/src/kilocode/permission/provenance.ts`, `packages/opencode/src/tool/shell.ts`, `packages/opencode/src/kilocode/tool/background-process.ts`. Из shared OpenCode paths меняются только четыре файла: `permission/index.ts`, `session/tools.ts`, `session/processor.ts` и `tool/shell.ts`; logic остаётся в `src/kilocode/`, shared blocks минимальны и marked.

Оценка: 1,100–1,350 production LOC и 800–1,000 test LOC; всего 1,900–2,350 LOC. Основные независимые slices:

1. pure core/types/rule tables;
2. XDG snapshot + precedence floor + authoritative hook;
3. shell facts + adapter + audit/block semantics;
4. macOS Seatbelt process-lifetime operational probe;
5. reviewer interface stub;
6. отдельный background restart permission fix.

V1 не требует существенных client/protocol changes и укладывается в ориентир 2–2.5k LOC. Если detailed plan превысит 2.5k, первыми кандидатами в Deferred будут changed-region parsing для `package.json`/CI (оставить path-level ask) и новые remote/web auto-allows (оставить ask/pass); security invariants, XDG floor, audit, Seatbelt signal и restart fix сохраняются.
