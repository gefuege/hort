import { expect, test } from 'claude-code/testing'

const VALUE = 'synthetic-value-7f3a'
const TOOL = 'mcp__hort-secrets__request_secrets'
const API_KEY = { name: 'api-key', description: 'API-Key für Foo', env: 'prod', context: 'heine' }
const API_KEY_FIELD = `value:${JSON.stringify(['api-key', 'prod', 'heine'])}`
const API_KEY_CANCEL = `cancel:${JSON.stringify(['api-key', 'prod', 'heine'])}`
const TOKEN = { name: 'token', description: 'Token für Bar' }
const TOKEN_FIELD = `value:${JSON.stringify(['token', null, null])}`

const BAND = {
  plugin: 'hort-secrets',
  component: 'AbovePrompt',
  requestId: 'band',
  props: {
    hasSurvey: false,
    isWorking: false,
    maxRows: 20,
    bodyColumns: 80,
    scroll: { offset: 0, bodyRows: 20 },
    view: {},
  },
} as const

type Exit = { exitCode: number; stderr?: string }
type Run = { argv: readonly string[]; init?: { stdin?: string } }

// Stands for the engine: answers hort with `exit`, records what reaches it, and
// keeps every event the plugin raises so a test can look for the value.
const setUp = (
  $: any,
  on: any,
  exit: Exit | Error = { exitCode: 0 },
  surfaces: readonly string[] = ['desktop'],
) => {
  const runs: Run[] = []
  const messages: string[] = []
  const events: { name: string; text: string }[] = []

  on('*', (_: unknown, e: unknown, next: any) => {
    events.push({ name: next.event, text: JSON.stringify(e) ?? '' })
    return next(e)
  })
  on('tool.register', () => ({ value: { tool: TOOL } }))
  on('session.surfaces', () => ({ value: surfaces }))
  on('session.start', (_: unknown, e: { cwd: string }) => ({ cwd: e.cwd }))
  on('process.run', (_: unknown, e: Run) => {
    runs.push(e)
    if (exit instanceof Error) {
      return { deny: exit.message }
    }
    return {
      value: {
        exitCode: exit.exitCode,
        stdout: '',
        stderr: exit.stderr ?? '',
        isStdoutTruncated: false,
        isStderrTruncated: false,
      },
    }
  })
  on('prompt.submit', (_: unknown, e: { text: string }) => {
    messages.push(e.text)
    return { text: e.text }
  })
  on('ui.render', ($: any, e: unknown) => {
    const { Text } = $.ui.resolve(e)

    return <Text>engine</Text>
  })

  return { runs, messages, events }
}

const ask = async ($: any, secrets: unknown) => {
  await $.session.start({ cwd: '/', surface: 'desktop', isInteractive: true })
  return $.tool.call({ tool: TOOL, secrets })
}

const expectNoBand = async ($: any) => {
  const ui = await $.ui.mount({ ...BAND, surface: 'desktop' })

  expect(await ui.find({ type: 'Text', text: /Secret eintragen/ })).toBeUndefined()
  await ui.unmount()
}

test('the band offers one field per secret on terminal and desktop', async ($, on) => {
  setUp($, on)
  await ask($, [API_KEY, TOKEN])

  for (const surface of ['terminal', 'desktop'] as const) {
    const ui = await $.ui.mount({ ...BAND, surface })

    expect(await ui.find({ key: API_KEY_FIELD })).toBeDefined()
    expect(await ui.find({ key: TOKEN_FIELD })).toBeDefined()
    expect((await ui.find({ type: 'Text', text: /API-Key/ }))?.text).toBe(
      'API-Key für Foo · Env prod · Kontext heine',
    )
    await ui.unmount()
  }
})

test('the value reaches hort by stdin and nowhere else', async ($, on) => {
  const { runs, messages, events } = setUp($, on)
  await ask($, [API_KEY])
  const ui = await $.ui.mount({ ...BAND, surface: 'desktop' })

  await ui.input({ key: API_KEY_FIELD, text: VALUE })

  expect(runs).toHaveLength(1)
  expect(runs[0].argv).toEqual([
    'hort', '--set-secret', 'api-key', '--value-stdin',
    '--description', 'API-Key für Foo', '--env', 'prod', '--context', 'heine',
  ])
  expect(runs[0].init?.stdin).toBe(VALUE)
  expect(messages).toEqual(['Secret gespeichert als api-key.'])

  // Asked again once the value exists, the tool's answer still lacks it.
  const answer = await $.tool.call({ tool: TOOL, secrets: [API_KEY] })
  expect(answer.result).toContain('api-key')
  expect(JSON.stringify(answer)).not.toContain(VALUE)

  // Beyond the engine's own carriers of the typing, no event holds the value.
  const carrying = events.filter(e => e.text.includes(VALUE)).map(e => e.name)
  expect(new Set(carrying)).toEqual(new Set(['ui.input', 'process.run']))
  expect(events.some(e => e.name === 'state.set')).toBe(true)
})

test('the field is gone once the value is stored', async ($, on) => {
  setUp($, on)
  await ask($, [API_KEY, TOKEN])
  const ui = await $.ui.mount({ ...BAND, surface: 'terminal' })

  await ui.input({ key: API_KEY_FIELD, text: VALUE })

  expect(await ui.find({ key: API_KEY_FIELD })).toBeUndefined()
  expect(await ui.find({ key: TOKEN_FIELD })).toBeDefined()
})

test('Enter on an empty field stores nothing', async ($, on) => {
  const { runs, messages } = setUp($, on)
  await ask($, [TOKEN])
  const ui = await $.ui.mount({ ...BAND, surface: 'terminal' })

  await ui.input({ key: TOKEN_FIELD, text: '' })

  expect(runs).toEqual([])
  expect(messages).toEqual([])
  expect(await ui.find({ key: TOKEN_FIELD })).toBeDefined()
})

test('a locked vault says so', async ($, on) => {
  const { messages } = setUp($, on, { exitCode: 2, stderr: `locked ${VALUE}` })
  await ask($, [TOKEN])
  const ui = await $.ui.mount({ ...BAND, surface: 'desktop' })

  await ui.input({ key: TOKEN_FIELD, text: VALUE })

  expect(messages).toEqual([
    'Hort ist gesperrt, token wurde nicht gespeichert. Nach „hort unlock“ im Terminal die Eingabe neu anfordern.',
  ])
})

test('a hort error never carries stderr into the chat', async ($, on) => {
  const { messages } = setUp($, on, { exitCode: 1, stderr: `bad value ${VALUE}` })
  await ask($, [TOKEN])
  const ui = await $.ui.mount({ ...BAND, surface: 'desktop' })

  await ui.input({ key: TOKEN_FIELD, text: VALUE })

  expect(messages).toEqual(['Hort konnte token nicht speichern (Exit-Code 1).'])
})

test('hort that cannot start is reported without the error text', async ($, on) => {
  const { messages } = setUp($, on, new Error(`spawn failed ${VALUE}`))
  await ask($, [TOKEN])
  const ui = await $.ui.mount({ ...BAND, surface: 'desktop' })

  await ui.input({ key: TOKEN_FIELD, text: VALUE })

  expect(messages).toEqual([
    'Hort ließ sich nicht ausführen, token wurde nicht gespeichert. Ist hort installiert und im PATH?',
  ])
})

test('cancelling stores nothing and tells the chat', async ($, on) => {
  const { runs, messages } = setUp($, on)
  await ask($, [API_KEY])
  const ui = await $.ui.mount({ ...BAND, surface: 'desktop' })

  await ui.press({ key: API_KEY_CANCEL })

  expect(runs).toEqual([])
  expect(messages).toEqual(['Eingabe für api-key abgebrochen, nichts gespeichert.'])
  expect(await ui.find({ key: API_KEY_FIELD })).toBeUndefined()
})

test('a name that starts with a dash is refused', async ($, on) => {
  const { runs } = setUp($, on)
  const answer = await ask($, [{ name: '--delete', description: 'x' }])

  expect(answer.deny).toContain('„--delete“')
  expect(runs).toEqual([])
  await expectNoBand($)
})

test('without a terminal or desktop the tool says the input needs the Mac', async ($, on) => {
  setUp($, on, { exitCode: 0 }, ['mobile', 'vscode'])
  const answer = await ask($, [API_KEY])

  expect(answer.deny).toContain('am Mac nötig')
  await expectNoBand($)
})

test('a terminal beside a phone is enough', async ($, on) => {
  setUp($, on, { exitCode: 0 }, ['terminal', 'mobile'])
  const answer = await ask($, [API_KEY])

  expect(answer.deny).toBeUndefined()
})

test('a leading dash in description, env and context stays one argv element', async ($, on) => {
  const { runs } = setUp($, on)
  await ask($, [{ name: 'dash', description: '-d', env: '-e', context: '-c' }])
  const ui = await $.ui.mount({ ...BAND, surface: 'desktop' })

  await ui.input({ key: `value:${JSON.stringify(['dash', '-e', '-c'])}`, text: VALUE })

  expect(runs[0].argv).toEqual([
    'hort', '--set-secret', 'dash', '--value-stdin',
    '--description', '-d', '--env', '-e', '--context', '-c',
  ])
})

test('without env and context the argv names neither', async ($, on) => {
  const { runs } = setUp($, on)
  await ask($, [TOKEN])
  const ui = await $.ui.mount({ ...BAND, surface: 'desktop' })

  await ui.input({ key: TOKEN_FIELD, text: VALUE })

  expect(runs[0].argv).toEqual([
    'hort', '--set-secret', 'token', '--value-stdin', '--description', 'Token für Bar',
  ])
})

test('a control character in any field is refused and draws nothing', async ($, on) => {
  setUp($, on)

  for (const field of ['name', 'description', 'env', 'context']) {
    const answer = await ask($, [{ ...API_KEY, [field]: 'a\u0007b' }])

    expect(answer.deny).toContain('Steuerzeichen')
  }
  await expectNoBand($)
})

test('whitespace in a name is refused', async ($, on) => {
  setUp($, on)
  const answer = await ask($, [{ name: 'api key', description: 'x' }])

  expect(answer.deny).toContain('Leerzeichen')
  await expectNoBand($)
})

test('the same secret twice in one call is refused', async ($, on) => {
  setUp($, on)
  const answer = await ask($, [API_KEY, API_KEY])

  expect(answer.deny).toContain('nur einmal')
  await expectNoBand($)
})

test('one name for two environments is two secrets', async ($, on) => {
  setUp($, on)
  const answer = await ask($, [API_KEY, { ...API_KEY, env: 'staging' }])

  expect(answer.deny).toBeUndefined()
})

test('the tool result names the secrets and asks for no value', async ($, on) => {
  setUp($, on)
  const answer = await ask($, [API_KEY, TOKEN])

  expect(answer.result).toContain('api-key, token')
})
