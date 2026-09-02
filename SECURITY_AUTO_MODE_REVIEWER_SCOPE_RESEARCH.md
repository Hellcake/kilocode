# Scope LLM reviewer-а в security auto mode Kilo Code

## Статус и границы исследования

- Снимок репозитория: ветка `main`, commit `785b0bcdf7ac765dd29016cc7e8f25f66dc473c1` от 2026-09-02.
- Документ продолжает [`SECURITY_AUTO_MODE_LLM_REVIEW_RESEARCH.md`](SECURITY_AUTO_MODE_LLM_REVIEW_RESEARCH.md) и проверяет альтернативную гипотезу: не слишком ли узок предложенный там eligibility filter.
- Метод: статический разбор текущего shell AST/scanner, permission precedence, sandbox envelope и тестов compound-команд.
- Это не измерение реальной частоты prompts: в репозитории нет telemetry/corpus, достаточных для количественной оценки coverage.
- Production-код не изменялся.

## Краткий вывод

Предыдущий single-command filter действительно можно ослабить без перехода к `review every ask`. Наиболее разумный баланс для hackathon MVP — **bounded compound reviewer**:

- только soft `bash: ask` после existing deny/hard/human boundaries;
- один полностью распарсенный плоский shell-план;
- до 4 command nodes и небольшой общий byte limit;
- разрешённые формы композиции: обычный invocation, `&&`, `||`, `;` и простой pipeline;
- без heredoc, background, output redirection, command/process substitution, nested shell/interpreter, loops, script blocks и parser recovery;
- один LLM call на весь plan, но assessment отдельно для каждого node;
- итоговое решение принимает deterministic mapper по объединению effects всех nodes и реальному sandbox state.

Это переносит часть строгости с входа на выход: само наличие нескольких команд или pipe больше не означает немедленный human prompt. Но authority boundaries, неполный parse, secrets и семантически непрозрачное nested execution должны отсекаться **до** модели. Если отправить reviewer-у все soft asks, большинство high-risk calls всё равно превратятся в `ask`, только на несколько секунд позже.

Главное ограничение coverage: значимый auto-allow неизвестных test/build/lint команд остаётся sandbox-dependent. Без работающего sandbox модель знает предполагаемую семантику имени бинарника, но Kilo не подтверждает его provenance или фактические side effects. На Windows, где backend отсутствует, broad review в основном добавит latency; там следует сохранять узкий режим.

## 1. Что именно было слишком консервативно

Предыдущий документ отправлял reviewer-у только один invocation и исключал любой pipeline, `&&`, `;` или иной compound syntax. Это сильная граница, но она смешивает три разные причины отказа:

1. **Authority boundary** — действие требует согласия пользователя независимо от качества анализа.
2. **Parser/information boundary** — Kilo не может построить полный план выполнения.
3. **Composition** — Kilo видит несколько обычных commands и оператор между ними.

Первые две причины должны оставаться terminal `ask`. Третья сама по себе не делает действие опасным. Для `lint && test` host effects равны объединению effects `lint` и `test`; для `cmd1 || cmd2` необходимо оценить обе ветви; для простого pipe — producer, consumer и возможный data-to-execution sink.

Следовательно, blanket rule `commandCount !== 1 -> ask` чрезмерно строг. Но обратное правило `parsed -> reviewable` тоже недостаточно: AST может быть корректным для `curl ... | sh`, nested substitution или PowerShell script block, оставаясь слишком непрозрачным для безопасного MVP.

## 2. Что Kilo уже знает о compound shell

### 2.1. Scanner уже декомпозирует команды

`ShellPermission` использует tree-sitter для Bash/PowerShell и получает все descendants типа `command`. Внутренние helpers уже извлекают command parts, source text и ordered nodes ([`tool/shell.ts:106-147`](packages/opencode/src/tool/shell.ts#L106)).

`collect()`:

- получает список command nodes;
- выделяет tokens каждого node;
- формирует отдельный permission pattern на node;
- ищет известные file/path arguments и внешние directories;
- отмечает aggregate access как `unknown` при redirection или неизвестном command effect;
- добавляет потерянные fragments обратно в patterns ([`tool/shell.ts:368-420`](packages/opencode/src/tool/shell.ts#L368)).

`unparsed()` явно использует `root.hasError`, ERROR nodes и raw fallback. Это уже хороший fail-closed signal, который можно передать как `parsedComplete`, не создавая второй parser ([`kilocode/tool/shell-unparsed.ts:1-21`](packages/opencode/src/kilocode/tool/shell-unparsed.ts#L1)).

Тесты подтверждают текущую декомпозицию:

- `echo foo && echo bar` даёт два patterns;
- PowerShell conditional выделяет оба `Write-Host` commands;
- parse errors и partially parsed pipeline получают raw fallback ([`tool/shell.test.ts:244-288`](packages/opencode/test/tool/shell.test.ts#L244), [`shell-unparsed.test.ts:94-166`](packages/opencode/test/kilocode/tool/shell-unparsed.test.ts#L94)).

### 2.2. Permission engine уже принимает решение по всем nodes

`Permission.ask` проходит по каждому `request.patterns`, немедленно останавливается на hard veto/deny и auto-approves только когда каждый pattern разрешён ([`permission/index.ts:187-244`](packages/opencode/src/permission/index.ts#L187)). Это подтверждено отдельными tests для multi-pattern allow/deny ([`permission/next.test.ts:1088-1148`](packages/opencode/test/permission/next.test.ts#L1088)).

Поэтому compound-команда, состоящая только из current allow patterns, уже может не создавать prompt. В default Code/Build rules `bash: * = ask`, но readable commands, `touch`, `mkdir`, `cp`, `mv`, `tsc`, `tsgo` и архиваторы разрешены отдельно ([`kilocode/agent/index.ts:23-67`](packages/opencode/src/kilocode/agent/index.ts#L23)).

Reviewer снижает fatigue только если:

- хотя бы один node сейчас пришёл к soft `ask`;
- ни один node не пришёл к `deny`/locked human boundary;
- final mapper действительно способен выдать `allow` в текущем environment.

Отправлять already-all-allowed compound в LLM бессмысленно.

### 2.3. Сейчас теряется topology

Permission payload содержит raw command в metadata, но `patterns` — это `Set` из source отдельных command nodes ([`tool/shell.ts:286-323`](packages/opencode/src/tool/shell.ts#L286), [`tool/shell.ts:375-409`](packages/opencode/src/tool/shell.ts#L375)). При этом:

- order и duplicate nodes не являются отдельным contract;
- оператор между nodes не передаётся;
- nesting/control-flow не передаются;
- redirection виден scanner-у только как aggregate `access = unknown`;
- path targets redirection не извлекаются;
- valid compound обычно не сохраняет весь raw expression как permission pattern.

Это важно и для current rules. `readOnlyBash` содержит raw wildcard-denies для pipe, `;`, `&`, substitution и redirection ([`kilocode/agent/index.ts:69-125`](packages/opencode/src/kilocode/agent/index.ts#L69)), но fully parsed compound может быть представлен permission engine отдельными patterns без оператора. Поэтому эти lexical guards не являются надёжной заменой structured topology.

Broad reviewer не должен повторно парсить `metadata.command`. Правильный путь — экспортировать небольшой summary из того же AST до того, как topology потеряна.

### 2.4. Не вся видимая compound coverage одинаково ценна

Shell prompt уже рекомендует:

- запускать независимые commands отдельными параллельными tool calls;
- использовать `workdir` вместо `cd ... && ...`;
- не применять shell text tools там, где есть dedicated tools ([`tool/shell/prompt.ts:106-129`](packages/opencode/src/tool/shell/prompt.ts#L106)).

Поэтому `cd subdir && command` и простые read pipelines встречаться могут, но Kilo уже подталкивает модель не генерировать их. Более ценный дополнительный класс — зависимые developer workflows вроде `lint && test`, `generate && typecheck` и mixed known-allow + unknown command.

Package scripts показывают ещё одно ограничение: репозиторий содержит scripts с внутренними `&&`, но permission layer видит только внешний `bun run <script>`, а не expansion manifest-а. Расширение compound eligibility само по себе не раскрывает скрытую цепочку ([`packages/kilo-vscode/package.json:1235-1248`](packages/kilo-vscode/package.json#L1235), [`packages/opencode/package.json:11`](packages/opencode/package.json#L11)).

## 3. Сравнение вариантов

### Вариант A. Узкий single-command reviewer

Eligibility:

- один command node;
- нет composition/redirection/substitution;
- остальные boundaries из предыдущего исследования.

Плюсы:

- минимальный prompt и output;
- простая validation schema;
- низкий риск пропущенного interaction effect;
- быстрый MVP.

Минусы:

- исключает понятные `lint && test` и `tool | formatter`;
- не использует уже существующую AST decomposition;
- создаёт prompt из-за syntax shape, даже когда все effects bounded.

### Вариант B. Bounded compound plan

Eligibility:

- 1–4 ordered nodes;
- полный parse без recovered fragments;
- только flat `&&`, `||`, `;` и simple pipe;
- без nested execution и сложного control flow;
- один review request на целый plan.

Плюсы:

- заметно шире A именно для developer workflows;
- safety определяется union effects, а не количеством nodes;
- не требует нового shell parser;
- остаётся небольшим и тестируемым contract.

Минусы:

- нужен AST topology summary;
- structured output больше;
- необходимо валидировать exact node coverage;
- реальный прирост сильно зависит от sandbox и command distribution.

### Вариант C. Review почти всех soft `bash: ask`

Eligibility исключает только explicit hard/human boundaries; heredoc, redirection, nested interpreters и большие shell programs всё равно отправляются модели.

Плюсы:

- максимальная теоретическая coverage;
- минимальная deterministic command taxonomy на входе;
- эффектная demo-формулировка «модель рассматривает всё».

Минусы:

- `curl | sh`, deploy/admin/publish, installers и opaque scripts почти всегда должны вернуться к human;
- model call становится задержкой перед большинством risky prompts;
- prompt-injection и secret-exposure surface больше;
- mapping вынужден интерпретировать слишком богатую shell language;
- трудно проверить полноту model assessment для loops, nested substitutions и conditional blocks.

### Сводка

| Критерий | A: single | B: bounded compound | C: almost all soft ask |
|---|---|---|---|
| Дополнительная coverage | Низкая/средняя | Средняя, высокая при sandbox | Формально высокая, practically noisy |
| Бесполезные LLM calls | Мало | Умеренно мало при pre-routing | Много |
| Parser enrichment | Минимальный | Умеренный | Большой |
| Mapping complexity | Низкая | Средняя | Высокая |
| Failure blast radius | Узкий | Ограниченный | Почти весь shell ask path |
| Hackathon fit | Надёжный, но менее заметный | Лучший баланс | Слишком рискованно |

Рекомендуется B, но не как arbitrary shell reviewer: это reviewer ограниченного execution plan.

## 4. Что должно остаться до LLM

Перенос строгости на final mapping не означает, что вход должен быть почти пустым. Pre-filter отвечает не за оценку side effects, а за authority, integrity, privacy и отсутствие заведомо бесполезного model call.

### 4.1. Terminal policy и human boundaries

Reviewer не вызывается при:

- hard veto или resolved `deny` любого pattern;
- explicit project/global/session `ask`;
- `skillShell` или `sandboxEscalation`;
- detected `external_directory`;
- background start/restart;
- credential-like arguments, `.env`/secret targets;
- known publish/deploy/admin/system/persistence families;
- saved user policy, которая намеренно требует prompt.

Это не semantic uncertainty, которую LLM может устранить. Здесь отсутствует user authority.

### 4.2. Integrity boundaries

Reviewer не вызывается при:

- `root.hasError` или непустом `unparsed` recovery;
- неизвестном shell dialect;
- превышении byte/node limits;
- heredoc;
- command/process substitution;
- shell/interpreter `-c`/`-Command`, `eval`, `source`, `Invoke-Expression`;
- background operator;
- loops, functions, script blocks, subshell grouping или nesting выше простой flat composition;
- dynamic executable name;
- output redirection до появления typed redirection targets.

Некоторые формы теоретически можно описать через richer AST graph, но для короткого MVP они дают мало fatigue reduction относительно complexity.

### 4.3. Privacy boundaries

LLM не получает:

- tool description как trusted evidence;
- chat history;
- environment values;
- command с credential-like literals;
- contents файлов или package manifest;
- raw loose metadata.

Command/node text остаётся hostile data. Если credential detector срабатывает, fallback должен произойти **до** provider call, а не после assessment.

## 5. Что можно перенести в final mapping

Следующие признаки больше не должны автоматически исключать request из review:

- `commandCount > 1`, пока count bounded;
- flat `&&`, `||` и `;`;
- simple pipe без nested execution;
- неизвестный developer CLI;
- project-code execution;
- workspace/sandbox-confined write effect;
- сочетание current `allow` и soft `ask` nodes.

Reviewer оценивает эти effects, а mapper применяет environment-specific ceiling. Например, `vitest && eslint` может быть reviewable всегда, но стать `allow` только при enforcement envelope, достаточном для project code.

## 6. Structured shell context

### 6.1. Данные, которые уже существуют

Без новой инфраструктуры можно переиспользовать:

- raw normalized command и heredoc marker из current bash metadata;
- ordered `command` nodes и их `source`/`parts` из AST;
- `root.hasError` и recovered fragments;
- aggregate external directories и access;
- current `cwd`, shell path и dialect из `PermissionInput`;
- per-pattern resolved action внутри `Permission.ask`;
- sandbox status и network restriction.

`SessionTools.resolve` уже вычисляет и `restricted`, и `sandboxed` перед созданием `Tool.Context`; сейчас в `extra` записан только `sandboxed` ([`session/tools.ts:50-103`](packages/opencode/src/session/tools.ts#L50)). Reviewer adapter может получить оба значения без нового sandbox probe.

### 6.2. Небольшое AST enrichment

Нужно сохранить до permission call:

- stable node IDs, order и duplicates;
- normalized argv/parts каждого node;
- connector edges: `and`, `or`, `sequence`, `pipe`;
- nesting depth и parent construct;
- flags `hasRedirect`, `hasSubstitution`, `hasBackground`, `hasControlFlow`;
- `parsedComplete` и raw recovered fragments count;
- cwd transitions и их `workspace | external | dynamic` scope;
- per-node known path facts, когда их уже умеет извлекать scanner.

Это extraction из уже построенного tree-sitter tree, а не второй parser и не новый allowlist.

### 6.3. Возможный internal contract

```ts
type ShellPlan = {
  version: 1
  dialect: "bash" | "powershell" | "cmd"
  raw: string
  parsedComplete: boolean
  cwd: { scope: "workspace" | "external"; path?: string }
  nodes: Array<{
    id: number
    source: string
    argv: string[]
    prefix: string
    baseline: "allow" | "ask"
    depth: number
  }>
  edges: Array<{
    from: number
    to: number
    kind: "and" | "or" | "sequence" | "pipe"
  }>
  syntax: {
    heredoc: boolean
    redirection: boolean
    substitution: boolean
    background: boolean
    controlFlow: boolean
  }
  external: { detected: boolean; access: "read" | "unknown" }
  sandbox: { enabled: boolean; networkRestricted: boolean }
}
```

Это internal Kilo action shape. Добавлять его в public permission schema не требуется: current `metadata` допускает JSON object ([`packages/schema/src/v1/permission.ts:27-35`](packages/schema/src/v1/permission.ts#L27)).

### 6.4. Ограничения context

Даже richer shell plan не знает:

- что реально находится по имени executable в `PATH`;
- expansion `npm run`/`bun run`/`make`;
- поведение local script или compiler plugin;
- runtime-generated paths;
- содержимое accessible workspace files.

Поэтому structured parsing улучшает completeness и composition reasoning, но не превращает LLM в enforcement layer.

## 7. Reviewer assessment для compound plan

Reviewer получает один plan и обязан вернуть assessment каждого node по exact ID:

```ts
type NodeAssessment = {
  id: number
  filesystem: "none" | "read_only" | "sandbox_confined_write" | "outside_or_system" | "unknown"
  network: "none" | "present" | "unknown"
  execution: "tool_only" | "project_code_or_plugins" | "arbitrary_or_nested" | "unknown"
  persistence: "none" | "present" | "unknown"
  destructive: "no" | "yes" | "unknown"
  secrets: "not_indicated" | "possible" | "unknown"
  confidence: "high" | "medium" | "low"
}
```

Validator до mapping проверяет:

1. Result содержит ровно IDs из plan, без пропусков и extras.
2. Каждый enum валиден.
3. Нет `unknown` или confidence ниже требуемого ceiling.
4. Model не изменила topology и не добавила «безопасные» nodes.
5. Aggregate effects вычисляются кодом, а не берутся из model summary.

Reviewer не возвращает `allow`, `deny` или общий risk label. Он только заполняет effect dimensions.

Для pipe полезно дополнительно спросить, является ли consumer execution sink, но mapper всё равно обязан иметь deterministic hard guard для `xargs`, shell interpreters и аналогичных known sinks. Нельзя позволять одному неверному field превратить `curl | sh` в allow.

## 8. Final deterministic mapping

### 8.1. Effect fold

Mapper объединяет effects всех nodes независимо от control-flow:

- для `&&` оцениваются и success continuation, и первый command;
- для `||` оцениваются обе ветви, включая fallback;
- для `;` оцениваются все nodes;
- для pipe оцениваются producer, consumer и sink restrictions.

Невыполненная runtime branch всё равно считается возможной. `unknown` доминирует над safe value; model confidence не отменяет parser/sandbox facts.

### 8.2. Без работающего sandbox

Рекомендуемый ceiling:

- все nodes должны быть `tool_only`;
- filesystem — `none` или `read_only`;
- network/persistence/destructive — отсутствуют;
- secrets — `not_indicated`;
- только flat bounded topology;
- executable должен быть уже trusted existing policy или иным детерминированно подтверждённым binary class.

Последнее условие существенно режет новый coverage: Kilo сейчас не резолвит executable provenance для reviewer. Разрешать неизвестный binary только потому, что LLM узнала его имя, означает доверять предположению без containment. Для safety-oriented MVP это плохой trade-off.

Итог: без sandbox broad review полезен главным образом для composition уже trusted nodes, но такие plans часто и сейчас auto-approved по отдельным patterns. Поэтому no-sandbox/Windows profile должен оставаться близок к прежнему single-command scope.

### 8.3. С работающим sandbox

При `SandboxPolicy.status(...).enabled === true` и network restriction mapper может разрешить:

- `project_code_or_plugins`;
- writes внутри реально применённого sandbox envelope;
- flat chained build/test/lint/generate workflows;
- простые pipelines, если нет external/system/persistence/destructive effects.

Однако корректный термин — не «workspace-only sandbox». Текущий profile разрешает writes не только в project/worktree, но и в несколько Kilo data/cache/state/tmp paths и user-configured `writable_paths`, одновременно отдельно запрещая `.git` и critical config writes ([`sandbox/policy.ts:228-270`](packages/opencode/src/kilocode/sandbox/policy.ts#L228)). Mapping должен опираться на факт **sandbox-confined**, а не обещать более узкую boundary, чем реально обеспечивает runtime.

Git mutation уже имеет отдельный `sandbox_escalation` ask перед unrestricted execution ([`tool/shell.ts:423-447`](packages/opencode/src/tool/shell.ts#L423)). Reviewer не должен обходить этот path.

### 8.4. Residual read risk

Sandbox ограничивает writes/network/environment, но не делает workspace contents confidential. Документация Kilo прямо отмечает, что sandbox не мешает читать accessible files и включать их содержимое в model context ([`sandboxing.md:65`](packages/kilo-docs/pages/getting-started/settings/sandboxing.md#L65)).

Поэтому auto-approval project code под sandbox остаётся осознанным MVP assumption:

- explicit `.env`/credential arguments остаются human;
- Kilo secret environment variables вырезаются profile-ом;
- скрытое чтение secrets внутри project script полностью не исключается.

Если такой residual риск неприемлем, package scripts и project executables нужно оставить `ask` до manifest/script resolution или read confinement. Тогда broad reviewer даст заметно меньший эффект.

### 8.5. Network modes

`SandboxPolicy.status()` сообщает availability/enabled, а `networkRestricted()` — отдельный state ([`sandbox/policy.ts:339-354`](packages/opencode/src/kilocode/sandbox/policy.ts#L339)). Для MVP:

- `enabled && networkRestricted` — допускает sandbox-dependent mapping;
- sandbox с unrestricted network — network-capable/unknown assessment даёт `ask`;
- reviewer-reported `network: none` может пройти, но фактическая попытка network не должна расширять policy;
- configured allowed hosts не следует автоматически считать разрешением на semantic remote action вроде publish/deploy.

## 9. Где coverage реально растёт

| Пример | Current/narrow result | Bounded reviewer | Реальный выигрыш |
|---|---|---|---|
| `git status && git diff --stat` | Оба nodes уже allow | Reviewer не вызывается | Нет: prompt уже не нужен |
| `tsc --noEmit && vitest run` | `tsc` allow, `vitest` soft ask | Allow при sandbox + safe assessment | Высокий для mixed dev chain |
| `eslint . && vitest run` | Оба soft ask | Allow при sandbox | Высокий для common verification |
| `generate-client && tsc --noEmit` | Первый unknown/project effect | Allow только при sandbox | Средний/высокий |
| `cd packages/opencode && bun test ...` | `cd` не даёт bash pattern, test asks | Может allow при sandbox | Есть, но shell prompt уже советует `workdir` |
| `git diff | sed -n '1,80p'` | `sed` может дать ask | Model понимает read pipeline | Небольшой; prompt советует dedicated tools |
| `npm run check` | Один opaque wrapper | Compound scope ничего не добавляет | Зависит от sandbox, не от topology |
| `lint || lint --fix` | Fallback branch может write | Allow как sandbox-confined edit | Полезно, если workspace edits допустимы |
| `echo x | tee file` | `tee` unknown/write | Только sandbox-confined allow | Умеренный, но не core workflow |
| `curl URL | sh` | Soft ask/unsafe | Pre-filter human | Никакого полезного review |
| `rg ... | xargs rm` | Dynamic execution/destructive | Pre-filter human | Никакого полезного review |
| `cmd > file` | Redirection insufficiently typed | Pre-filter human | Не включать в MVP |

Наиболее сильный coverage slice — 2–4 chained developer commands, где хотя бы один node unknown текущей allowlist и sandbox реально включён. Read-only compound обычно либо уже разрешён, либо нечасто нужен из-за dedicated tools.

## 10. Где wider review только добавляет latency

LLM call почти наверняка бесполезен для:

- known deploy/publish/cloud/admin commands;
- package install/update с network и dependency execution;
- external/system paths;
- git mutations, требующих sandbox escalation;
- credential-bearing commands;
- interpreters с inline code;
- parse recovery;
- long shell programs;
- sandbox-dependent project execution при unavailable sandbox;
- plans, где все patterns уже allow или один pattern deny.

Эти cases должен отсеивать `canProduceAllow(plan, environment)` до reviewer. Это не full semantic classifier, а дешёвая проверка существования хотя бы одного допустимого route в mapping matrix.

## 11. Latency и complexity

### 11.1. Latency

Bounded compound требует один model call на plan, не call на node. По сравнению с single-command reviewer:

- input растёт примерно линейно до 4 nodes;
- output должен содержать per-node assessments;
- timeout остаётся bounded, например около 3 секунд;
- model/schema error возвращает existing human prompt;
- reviewer failure cooldown остаётся полезен.

Чтобы wider review уменьшал fatigue, а не только замедлял prompts:

1. Call выполняется только при хотя бы одном soft-ask node.
2. Terminal boundaries отсекаются заранее.
3. Environment допускает хотя бы один `allow` outcome.
4. All-known-allow plans не review-ятся.
5. Один invalid node переводит весь plan в immediate `ask` после call.

### 11.2. Implementation complexity

Относительно предыдущего MVP добавляются:

- topology extraction;
- typed nodes/edges metadata;
- exact-ID output validation;
- effect fold по plan;
- несколько дополнительных scanner/mapping fixtures.

Не добавляются:

- новый shell parser;
- chat/file/manifest context;
- per-node model calls;
- public API/schema migration;
- client-side middleware;
- learned classifier.

Это умеренное увеличение сложности, оправданное только если demo проходит на macOS/Linux с working sandbox.

## 12. Code-level shape

Рекомендуемая граница остаётся прежней:

```text
packages/opencode/src/kilocode/permission/decision/
  shell-plan.ts       # validated AST summary -> portable Action
  shell-routing.ts    # terminal / review / pass
  reviewer.ts         # one bounded structured call
  assessment.ts       # exact node schema + validation
  mapping.ts          # pure effect fold -> allow | ask
```

Минимальные shared changes:

1. `shell.ts` сохраняет plan summary из уже построенного AST в internal metadata.
2. Existing lazy hook в `Permission.ask` получает resolved action для каждого pattern и вызывает Kilo adapter только после deny/hard/force-ask checks.
3. `SessionTools` передаёт уже вычисленный `restricted` рядом с `sandboxed` в reviewer environment.

Shared `shell.ts` потребует узкого `kilocode_change` block; основная policy/reviewer logic может остаться в Kilo-owned paths.

## 13. Scope hackathon MVP

### Включить

- soft default `bash: ask` в Code/Build-like agent;
- 1–4 fully parsed ordered nodes;
- flat `&&`, `||`, `;`, simple pipe;
- same-provider small reviewer;
- one assessment per exact node ID;
- pure sandbox-aware mapping;
- no-review fast paths для all-allow, deny и terminal boundaries;
- timeout/error -> existing prompt;
- audit reason `shell.reviewer_compound_allow`/`shell.reviewer_fallback`.

### Не включать

- heredoc/substitution/redirection;
- nested shell/interpreter and inline code;
- loops/functions/PowerShell script blocks;
- more than 4 nodes;
- package manifest expansion;
- executable provenance resolution;
- Windows sandbox substitute;
- reviewer всех soft asks;
- automatic persistence/cache of model decisions.

### Проверки, достаточные для confidence

1. Scanner summary сохраняет order, duplicates и connectors.
2. Parse error/raw recovery никогда не проходит eligibility.
3. Existing deny/hard/explicit ask не вызывает reviewer.
4. All-allow compound не вызывает reviewer.
5. Mixed allow+ask plan вызывает reviewer один раз.
6. Missing/extra assessment ID даёт `ask`.
7. Any `unknown`, network, persistence, external/system или destructive effect даёт `ask`.
8. Sandboxed chained lint/test может дать `allow`.
9. Тот же plan без sandbox даёт `ask`, если содержит untrusted/project execution.
10. Reviewer timeout/error даёт prompt без сохранения hidden approval.

## 14. Итоговая рекомендация

Предыдущий filter стоит расширить, но только по одной оси: **от single invocation к bounded flat execution plan**.

Оптимальный баланс:

1. Existing Kilo permissions и hard boundaries остаются первыми.
2. Parser integrity, secrets, external authority и opaque nested execution остаются pre-LLM gates.
3. Command count и простая composition больше не являются автоматическим `ask`.
4. Reviewer оценивает каждый AST node, не принимает permission decision.
5. Mapper объединяет worst-case effects всех возможных branches.
6. Project-code/workspace effects auto-approve только внутри реально работающего sandbox envelope с restricted network.
7. Без sandbox используется прежний узкий ceiling; LLM confidence не заменяет executable provenance и containment.

Такой вариант увеличивает coverage на наиболее демонстрируемом классе `lint/test/build/generate` chains, но не тратит model latency на действия, которые policy всё равно не может безопасно разрешить. Для hackathon это сильнее single-command reviewer и существенно надёжнее схемы «все soft bash asks отправляем модели».
