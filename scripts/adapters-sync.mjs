#!/usr/bin/env node
/**
 * Compile `src/plugin-adapters/<plugin>/adapter.mjs` declarations into the two
 * places that decide whether a same-origin path rides the paired-device channel:
 *
 *   - lib/client.js  : shouldRewriteFetchPath (browser fetch wrapper)
 *   - lib/index.js   : the boot script's `sf(p)` (server-injected into index.html)
 *
 * The package ships a prebuilt lib/, so this script is the build step for
 * adapters. It is idempotent: every generated region is wrapped in
 * `/* wj-adapters:start *\/ ... /* wj-adapters:end *\/` and replaced wholesale.
 *
 * usage:
 *   node scripts/adapters-sync.mjs           # rewrite the artifacts
 *   node scripts/adapters-sync.mjs --check   # exit 1 when the artifacts drifted
 */
import { readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)))
const ADAPTERS_DIR = join(ROOT, 'src/plugin-adapters')
const CLIENT_FILE = join(ROOT, 'lib/client.js')
const BOOT_FILE = join(ROOT, 'lib/index.js')
const CHECK = process.argv.includes('--check')

const CLIENT_ANCHOR = '\t\t\tif (pathname.startsWith(RULES.petPrefix) || pathname === "/pet") return true;\n'
const BOOT_ANCHOR = 'return false}function sw(p)'
const CLIENT_BLOCK_RE = /^\t*\/\* wj-adapters:start \*\/\n[\s\S]*?^\t*\/\* wj-adapters:end \*\/\n/gm
const BOOT_BLOCK_RE = /\/\*wj-adapters:start\*\/[\s\S]*?\/\*wj-adapters:end\*\//g

const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
const escapeSlash = (value) => value.replace(/\//g, '\\/')

/** Build the anchored regex source for one adapter (used verbatim in a literal). */
function regexSourceOf(adapter) {
  const prefix = escapeSlash(escapeRegex(adapter.prefix))
  const paths = [...adapter.allow, ...(Array.isArray(adapter.gated) ? adapter.gated : [])]
  const allow = paths.map((item) => escapeSlash(escapeRegex(item))).join('|')
  return `^${prefix}\\/(?:${allow})(?:\\/|$)`
}

/** The file text of a condition lives inside a single-quoted JS string; double the backslashes. */
function bootConditionOf(adapter) {
  const source = regexSourceOf(adapter).replace(/\\\//g, '\\\\/')
  return `if(/${source}/.test(p))return true;`
}

async function loadAdapters() {
  if (!existsSync(ADAPTERS_DIR)) return []
  const adapters = []
  for (const entry of readdirSync(ADAPTERS_DIR, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    if (!entry.isDirectory()) continue
    const file = join(ADAPTERS_DIR, entry.name, 'adapter.mjs')
    if (!existsSync(file)) continue
    const module = await import(pathToFileURL(file).href)
    const adapter = module.default ?? module.adapter
    if (adapter === undefined) throw new Error(`${file} must default-export an adapter object`)
    if (typeof adapter.id !== 'string' || adapter.id === '') throw new Error(`${file}: id is required`)
    if (typeof adapter.prefix !== 'string' || !adapter.prefix.startsWith('/')) throw new Error(`${file}: prefix must be an absolute path`)
    if (!Array.isArray(adapter.allow) || adapter.allow.length === 0) throw new Error(`${file}: allow must be a non-empty array`)
    if (adapter.gated !== undefined && !Array.isArray(adapter.gated)) throw new Error(`${file}: gated must be an array`)
    for (const item of [...adapter.allow, ...(adapter.gated ?? [])]) {
      if (typeof item !== 'string' || item === '' || item.startsWith('/')) {
        throw new Error(`${file}: allow entries are relative path segments, got ${JSON.stringify(item)}`)
      }
    }
    adapters.push(adapter)
  }
  return adapters
}

function clientBlockOf(adapters) {
  if (adapters.length === 0) return ''
  const lines = ['\t\t\t/* wj-adapters:start */']
  for (const adapter of adapters) {
    lines.push(`\t\t\tif (/${regexSourceOf(adapter)}/.test(pathname)) return true;`)
  }
  lines.push('\t\t\t/* wj-adapters:end */')
  return lines.join('\n') + '\n'
}

function bootBlockOf(adapters) {
  if (adapters.length === 0) return ''
  const body = adapters.map((adapter) => bootConditionOf(adapter)).join('')
  return `/*wj-adapters:start*/${body}/*wj-adapters:end*/`
}

function applyAdapters(source, block, file) {
  const stripped = source.replace(CLIENT_BLOCK_RE, '').replace(BOOT_BLOCK_RE, '')
  if (block === '') return stripped
  if (file === 'client') {
    if (!stripped.includes(CLIENT_ANCHOR)) throw new Error('client anchor not found — upstream build changed')
    return stripped.replace(CLIENT_ANCHOR, CLIENT_ANCHOR + block)
  }
  const at = stripped.indexOf(BOOT_ANCHOR)
  if (at === -1) throw new Error('boot anchor not found — upstream build changed')
  return `${stripped.slice(0, at)}${block}${stripped.slice(at)}`
}

const adapters = await loadAdapters()
if (adapters.length === 0) console.warn('adapters-sync: no adapters found under src/plugin-adapters/*/adapter.mjs')

const targets = [
  { file: 'client', path: CLIENT_FILE, block: clientBlockOf(adapters) },
  { file: 'boot', path: BOOT_FILE, block: bootBlockOf(adapters) },
]

let drifted = false
for (const target of targets) {
  const before = readFileSync(target.path, 'utf8')
  const after = applyAdapters(before, target.block, target.file)
  if (before === after) {
    console.log(`adapters-sync: ${target.file} up to date`)
    continue
  }
  drifted = true
  if (CHECK) {
    console.error(`adapters-sync: ${target.file} is out of date — run \`pnpm adapters:sync\``)
    continue
  }
  writeFileSync(target.path, after)
  console.log(`adapters-sync: ${target.file} updated`)
}

if (CHECK && drifted) process.exit(1)
