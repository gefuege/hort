import { atom, read, update } from 'claude-code'
import type { ElementTable, EngineInterface, Register } from 'claude-code'

import type { SecretRequest } from '../types'

const TOOL = 'request_secrets'
const EXIT_LOCKED = 2

// Holds what the model asked for, never a value: a value lives only in the
// onSubmit call that hands it to hort.
const pending = atom({ plugin: 'hort-secrets', key: 'pending' } as const, [])

const keyOf = ({ name, env, context }: SecretRequest) =>
  JSON.stringify([name, env, context])

const isOptionalText = (value: unknown) =>
  value === undefined || typeof value === 'string'

// The engine refuses a drawing that holds a control character, and with it the
// whole band: such a request must never reach `pending`.
const hasControl = (value: unknown) =>
  typeof value === 'string' && /\p{Cc}/u.test(value)

const parseRequest = (raw: unknown): SecretRequest | string => {
  const { name, description, env, context } = (raw ?? {}) as Record<string, unknown>

  if (typeof name !== 'string' || name === '') {
    return 'Jedes Secret braucht einen Namen.'
  }
  if (typeof description !== 'string' || description === '') {
    return `Das Secret „${name}“ braucht eine Beschreibung.`
  }
  if (!isOptionalText(env) || !isOptionalText(context)) {
    return `Env und Kontext von „${name}“ müssen Text sein.`
  }
  if ([name, description, env, context].some(hasControl)) {
    return 'Name, Beschreibung, Env und Kontext dürfen keine Steuerzeichen enthalten.'
  }
  if (name.startsWith('-')) {
    return `Der Name „${name}“ ist ungültig: Er darf nicht mit „-“ beginnen.`
  }
  if (/\s/.test(name)) {
    return `Der Name „${name}“ ist ungültig: Er darf keine Leerzeichen enthalten.`
  }

  return {
    name,
    description,
    ...(env ? { env: env as string } : {}),
    ...(context ? { context: context as string } : {}),
  }
}

const remove = ($: EngineInterface, request: SecretRequest) =>
  update($, pending, requests =>
    requests.filter(other => keyOf(other) !== keyOf(request)),
  )

// Only the exit code decides the message: hort's stderr is not read, so
// nothing it prints can reach the chat.
const store = async ($: EngineInterface, request: SecretRequest, value: string) => {
  const { name, description, env, context } = request
  const argv = ['hort', '--set-secret', name, '--value-stdin', '--description', description]

  if (env) {
    argv.push('--env', env)
  }
  if (context) {
    argv.push('--context', context)
  }

  try {
    const { exitCode } = await $.process.run(argv, { stdin: value })

    if (exitCode === 0) {
      return `Secret gespeichert als ${name}.`
    }
    if (exitCode === EXIT_LOCKED) {
      return `Hort ist gesperrt, ${name} wurde nicht gespeichert. Nach „hort unlock“ im Terminal die Eingabe neu anfordern.`
    }

    return `Hort konnte ${name} nicht speichern (Exit-Code ${exitCode}).`
  } catch {
    return `Hort ließ sich nicht ausführen, ${name} wurde nicht gespeichert. Ist hort installiert und im PATH?`
  }
}

export const register: Register = on => {
  on('session.start', async ($, e, next) => {
    await $.tool.register({
      name: TOOL,
      isDeferred: false,
      description:
        'Fragt Secrets bei der Person ab, ohne dass der Wert in den Chat gelangt. Nutze das Tool immer, statt im Chat nach einem Secret zu fragen. Über dem Prompt am Mac erscheint je Secret ein Feld. Das Tool kehrt sofort zurück; gespeicherte Namen, Abbruch und Fehler kommen danach als eigene Nachricht.',
      inputSchema: {
        type: 'object',
        properties: {
          secrets: {
            type: 'array',
            minItems: 1,
            items: {
              type: 'object',
              properties: {
                name: { type: 'string', description: 'Name in Hort' },
                description: { type: 'string', description: 'Wofür das Secret ist' },
                env: { type: 'string', description: 'Environment, z. B. prod' },
                context: { type: 'string', description: 'Kontext, z. B. ein Tenant' },
              },
              required: ['name', 'description'],
            },
          },
        },
        required: ['secrets'],
      },
    })

    return next(e)
  })

  on('tool.call', { tool: `mcp__hort-secrets__${TOOL}` }, async ($, e) => {
    const { secrets } = e as { secrets?: unknown }
    const surfaces = await $.session.surfaces()

    if (!surfaces.includes('terminal') && !surfaces.includes('desktop')) {
      return { deny: 'Die Eingabe ist am Mac nötig: Hier gibt es keine Bar über dem Prompt.' }
    }
    if (!Array.isArray(secrets) || secrets.length === 0) {
      return { deny: 'Es wurde kein Secret angefragt.' }
    }

    const parsed = secrets.map(parseRequest)
    const problem = parsed.find(entry => typeof entry === 'string')

    if (problem !== undefined) {
      return { deny: problem as string }
    }

    const requests = parsed as SecretRequest[]
    const asked = new Set(requests.map(keyOf))

    if (asked.size < requests.length) {
      return { deny: 'Jedes Secret darf je Env und Kontext nur einmal angefragt werden.' }
    }

    await update($, pending, open => [
      ...open.filter(other => !asked.has(keyOf(other))),
      ...requests,
    ])

    return {
      result: `Die Eingabe für ${requests.map(r => r.name).join(', ')} ist über dem Prompt am Mac offen. Warte auf die Nachricht mit dem Ergebnis, frage nicht im Chat nach dem Wert.`,
    }
  })

  on('ui.render', { component: 'AbovePrompt' }, async ($, e, next) => {
    const requests = await read($, pending)

    if (requests.length === 0 || e.props.hasSurvey) {
      return next(e)
    }

    const { Box, Button, Input, Text } = $.ui.resolve(e) as ElementTable<'desktop'>

    const save = async (request: SecretRequest, value: string) => {
      if (value === '') {
        return
      }

      // Gone from the band before hort runs, so the field empties at once. A
      // second Enter before the redraw can still start a second run.
      await remove($, request)
      await $.prompt.submit({ text: await store($, request, value) })
    }

    const cancel = async (request: SecretRequest) => {
      await remove($, request)
      await $.prompt.submit({
        text: `Eingabe für ${request.name} abgebrochen, nichts gespeichert.`,
      })
    }

    const detail = ({ description, env, context }: SecretRequest) =>
      [description, env && `Env ${env}`, context && `Kontext ${context}`]
        .filter(Boolean)
        .join(' · ')

    return (
      <Box flexDirection="column">
        <Text dimColor>
          Secret eintragen: Klick ins Feld oder ctrl+x tab, nicht in den Prompt
          tippen. Enter speichert in Hort.
        </Text>
        {requests.map((request, index) => (
          <Box key={keyOf(request)} flexDirection="column">
            <Text dimColor>{detail(request)}</Text>
            <Box>
              <Input
                key={`value:${keyOf(request)}`}
                label={request.name}
                submitLabel="speichern"
                {...(index === 0 ? { autoFocus: true as const } : {})}
                onSubmit={value => save(request, value)}
              />
              <Button
                key={`cancel:${keyOf(request)}`}
                label="Abbrechen"
                onPress={() => cancel(request)}
              />
            </Box>
          </Box>
        ))}
      </Box>
    )
  })
}
