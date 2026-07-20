import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { delimiter, dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const webDir = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const tauriCli = join(webDir, 'node_modules', '@tauri-apps', 'cli', 'tauri.js')
const bundles = process.platform === 'win32' ? 'nsis' : process.platform === 'linux' ? 'appimage,deb' : ''
if (!bundles) throw new Error(`Unsupported desktop build platform: ${process.platform}`)

const env = process.platform === 'linux' ? linuxBuildEnvironment() : process.env
const result = spawnSync(process.execPath, [tauriCli, 'build', '--bundles', bundles], { cwd: webDir, env, stdio: 'inherit' })
if (result.error) throw result.error
process.exit(result.status ?? 1)

function linuxBuildEnvironment() {
  const env = { ...process.env, NO_STRIP: '1' }
  const pkgConfig = 'pkg-config'
  const binaryDir = commandText(pkgConfig, ['--variable=gdk_pixbuf_binarydir', 'gdk-pixbuf-2.0'])
  if (!binaryDir || existsSync(binaryDir)) return env

  const pkgDir = commandText(pkgConfig, ['--variable=pcfiledir', 'gdk-pixbuf-2.0'])
  if (!pkgDir) return env
  const sourcePath = join(pkgDir, 'gdk-pixbuf-2.0.pc')
  if (!existsSync(sourcePath)) return env

  const compatibilityDir = join(webDir, 'src-tauri', 'target', 'appimage-pkgconfig')
  const compatibilityBinaryDir = join(compatibilityDir, 'gdk-pixbuf-2.0', '2.10.0')
  mkdirSync(join(compatibilityBinaryDir, 'loaders'), { recursive: true })
  writeFileSync(join(compatibilityBinaryDir, 'loaders.cache'), '')
  const definition = readFileSync(sourcePath, 'utf8')
    .replace(/^gdk_pixbuf_binarydir=.*$/m, 'gdk_pixbuf_binarydir=${pcfiledir}/gdk-pixbuf-2.0/2.10.0')
  writeFileSync(join(compatibilityDir, 'gdk-pixbuf-2.0.pc'), definition)
  env.PKG_CONFIG_PATH = [compatibilityDir, process.env.PKG_CONFIG_PATH].filter(Boolean).join(delimiter)
  console.log(`Using AppImage gdk-pixbuf compatibility metadata: ${compatibilityDir}`)
  return env
}

function commandText(command, args) {
  const result = spawnSync(command, args, { encoding: 'utf8' })
  return result.status === 0 ? result.stdout.trim() : ''
}
