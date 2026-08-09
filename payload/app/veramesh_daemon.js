#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const PACKAGE = 'VeraMesh';
const VERSION = '0.1.0-0003';
const MODE = 'SAFE_IDLE_UNPAIRED';
const varDir = process.env.VERAMESH_VAR || '/var/packages/VeraMesh/var';
const uiDir = process.env.VERAMESH_UI_DIR || '/var/packages/VeraMesh/target/ui';
const stateDir = path.join(varDir, 'state');
const stateFile = path.join(stateDir, 'runtime.json');
const uiStateFile = path.join(uiDir, 'runtime-status.json');

function mkdirPrivate(dir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  try { fs.chmodSync(dir, 0o700); } catch {}
}

function atomicWrite(file, data, mode = 0o600) {
  const parent = path.dirname(file);
  fs.mkdirSync(parent, { recursive: true });
  const tmp = path.join(parent, `.${path.basename(file)}.tmp.${process.pid}.${crypto.randomBytes(4).toString('hex')}`);
  let fd;
  try {
    fd = fs.openSync(tmp, 'wx', mode);
    fs.writeFileSync(fd, data);
    fs.fsyncSync(fd);
    fs.fchmodSync(fd, mode);
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(tmp, file);
    const dfd = fs.openSync(parent, 'r');
    try { fs.fsyncSync(dfd); } finally { fs.closeSync(dfd); }
  } catch (error) {
    if (fd !== undefined) { try { fs.closeSync(fd); } catch {} }
    try { fs.unlinkSync(tmp); } catch {}
    throw error;
  }
}

function state(serviceState, extra = {}) {
  const now = new Date().toISOString();
  return {
    schema: 'VERAMESH_TARGET_FIRST_STATUS_V1',
    package: PACKAGE,
    version: VERSION,
    serviceState,
    meshState: MODE,
    pairingEnabled: false,
    transportEnabled: false,
    listener: null,
    runtime: `node ${process.version}`,
    architecture: process.arch,
    pid: serviceState === 'RUNNING' ? process.pid : null,
    updatedAt: now,
    ...extra,
  };
}

function writeState(value) {
  mkdirPrivate(varDir);
  mkdirPrivate(stateDir);
  atomicWrite(stateFile, `${JSON.stringify(value, null, 2)}\n`, 0o600);
  // DSM desktop assets are package-owned and local. 0644 lets DSM's web UI read this diagnostic snapshot.
  atomicWrite(uiStateFile, `${JSON.stringify(value, null, 2)}\n`, 0o644);
}

function writeStopped(reason = 'operator_or_dsm_stop') {
  writeState(state('STOPPED', { reason }));
}

if (process.argv.includes('--write-stopped')) {
  writeStopped(process.argv[process.argv.indexOf('--write-stopped') + 1] || 'stopped');
  process.exit(0);
}

if (process.argv.includes('--self-test')) {
  process.stdout.write(`${JSON.stringify(state('SELF_TEST'))}\n`);
  process.exit(0);
}

let stopping = false;
const startedAt = new Date().toISOString();

function stop(signal) {
  if (stopping) return;
  stopping = true;
  try { writeState(state('STOPPED', { startedAt, stoppedAt: new Date().toISOString(), reason: signal })); }
  catch (error) { process.stderr.write(`status_write_failed:${error.message}\n`); }
  process.exit(0);
}

process.on('SIGTERM', () => stop('SIGTERM'));
process.on('SIGINT', () => stop('SIGINT'));
process.on('SIGHUP', () => {
  try { writeState(state('RUNNING', { startedAt, reason: 'safe_idle_unpaired' })); }
  catch (error) { process.stderr.write(`status_refresh_failed:${error.message}\n`); }
});
process.on('uncaughtException', error => {
  try { writeState(state('ERROR', { startedAt, reason: String(error && error.message ? error.message : error) })); }
  catch {}
  process.stderr.write(`uncaught_exception:${error && error.stack ? error.stack : error}\n`);
  process.exit(1);
});
process.on('unhandledRejection', error => {
  try { writeState(state('ERROR', { startedAt, reason: String(error && error.message ? error.message : error) })); }
  catch {}
  process.stderr.write(`unhandled_rejection:${error && error.stack ? error.stack : error}\n`);
  process.exit(1);
});

// Install signal/error handlers before declaring RUNNING so Package Center cannot race a just-created state file.
writeState(state('RUNNING', { startedAt, reason: 'safe_idle_unpaired' }));

// Keep exactly one lightweight package process alive. No listener, polling loop, queue, or heartbeat writes.
setInterval(() => {}, 60 * 60 * 1000);
