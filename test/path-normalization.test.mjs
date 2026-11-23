import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { canonicalGuardPath, classifyPath, guardFileTool, guardPaths } from '../src/agent-guard.mjs';

const windows = {
  paths: guardPaths({ home: 'C:\\Users\\user', trustdexRoot: 'C:\\tools\\trustdex' }),
  options: { home: 'C:\\Users\\user', cwd: 'C:\\Users\\user\\project' }
};
const linux = { paths: guardPaths({ home: '/home/user' }), options: { home: '/home/user', cwd: '/home/user/project' } };
const mac = { paths: guardPaths({ home: '/Users/user' }), options: { home: '/Users/user', cwd: '/Users/user/project' } };

function assertSameTarget(platform, spellings, kinds) {
  for (const spelling of spellings) {
    assert.deepEqual(classifyPath(spelling, platform.paths, platform.options), kinds, spelling);
  }
}

test('Windows drive letters, namespace prefixes, UNC shares, and case name the same file', () => {
  assertSameTarget(windows, [
    'C:\\Users\\user\\.aws\\credentials',
    'c:\\users\\USER\\.AWS\\Credentials',
    'C:/Users/user/.aws/credentials',
    '\\\\?\\C:\\Users\\user\\.aws\\credentials',
    '\\\\.\\C:\\Users\\user\\.aws\\credentials',
    '\\??\\C:\\Users\\user\\.aws\\credentials',
    '//?/c:/Users/user/.aws/credentials',
    '\\\\?\\UNC\\localhost\\C$\\Users\\user\\.aws\\credentials',
    '\\\\localhost\\c$\\Users\\user\\.aws\\credentials',
    '\\\\127.0.0.1\\C$\\Users\\user\\.aws\\credentials'
  ], ['secret']);
  assertSameTarget(windows, ['\\\\?\\c:\\TOOLS\\trustdex\\src\\claude-hook.mjs', 'C:\\tools\\trustdex\\'], ['config']);
});

test('Windows trailing dots, spaces, and data streams do not hide a file', () => {
  assertSameTarget(windows, [
    'C:\\Users\\user\\.aws\\credentials.',
    'C:\\Users\\user\\.aws\\credentials . ',
    'C:\\Users\\user\\.aws\\credentials::$DATA',
    'C:\\Users\\user\\.aws.\\credentials'
  ], ['secret']);
  assert.deepEqual(classifyPath('C:\\Users\\user\\.claude\\settings.json::$DATA', windows.paths, windows.options), ['config']);
});

test('.. and drive-relative paths resolve without leaving the drive', () => {
  assertSameTarget(windows, [
    'C:\\Users\\user\\project\\..\\.aws\\credentials',
    '..\\.aws\\credentials',
    'C:..\\.aws\\credentials',
    'C:\\..\\..\\Users\\user\\.aws\\credentials'
  ], ['secret']);
  assert.equal(canonicalGuardPath('C:\\..\\..\\Users', windows.options), '/C:/Users');
  assert.equal(canonicalGuardPath('D:notes.txt', windows.options), '/D:/notes.txt');
  assert.deepEqual(classifyPath('D:\\Users\\user\\.aws\\credentials', windows.paths, windows.options), []);
  assertSameTarget(linux, ['/home/user/project/../.aws/credentials', '../.aws/credentials', '//home//user/./.aws/credentials'], ['secret']);
});

test('home directory notation expands on every platform', () => {
  assertSameTarget(windows, [
    '~\\.aws\\credentials',
    '%USERPROFILE%\\.aws\\credentials',
    '%userprofile%\\.aws\\credentials',
    '$env:USERPROFILE\\.aws\\credentials',
    '${env:USERPROFILE}\\.aws\\credentials',
    '%HOMEDRIVE%%HOMEPATH%\\.aws\\credentials',
    '~user\\.aws\\credentials'
  ], ['secret']);
  assertSameTarget(linux, ['~/.aws/credentials', '$HOME/.aws/credentials', '${HOME}/.aws/credentials', '~user/.aws/credentials'], ['secret']);
  assert.deepEqual(classifyPath('~other/.aws/credentials', linux.paths, linux.options), []);
});

test('kernel and firmlink aliases name the same file', () => {
  assertSameTarget(linux, [
    '/proc/self/root/home/user/.aws/credentials',
    '/proc/thread-self/root/home/user/.aws/credentials',
    '/proc/1/root/home/user/.aws/credentials',
    '/proc/self/cwd/../.aws/credentials'
  ], ['secret']);
  assert.deepEqual(classifyPath('/proc/self/root/etc/crontab', linux.paths, linux.options), ['persistence']);
  assertSameTarget(mac, ['/System/Volumes/Data/Users/user/.aws/credentials', '/users/USER/.AWS/credentials'], ['secret']);
  assertSameTarget(mac, ['/private/etc/crontab'], ['persistence']);
  assertSameTarget(mac, ['/private/etc/claude-code/managed-settings.json'], ['config']);
});

test('an ordinary project file stays unclassified in every notation', () => {
  assertSameTarget(windows, ['C:\\Users\\user\\project\\src\\a.js', '\\\\?\\C:\\Users\\user\\project\\src\\a.js', 'src\\a.js'], []);
  assertSameTarget(linux, ['/home/user/project/src/a.js', 'src/a.js', '/proc/self/root/home/user/project/src/a.js'], []);
});

test('a symbolic link to a protected file is classified like its target', { skip: process.platform === 'win32' }, (t) => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'trustdex-paths-')));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const home = path.join(root, 'home');
  const linkedHome = path.join(root, 'linked-home');
  const project = path.join(home, 'project');
  fs.mkdirSync(path.join(home, '.aws'), { recursive: true });
  fs.mkdirSync(path.join(home, '.claude'), { recursive: true });
  fs.mkdirSync(project);
  fs.writeFileSync(path.join(home, '.aws', 'credentials'), 'placeholder\n');
  fs.symlinkSync(path.join(home, '.aws', 'credentials'), path.join(project, 'notes.txt'));
  fs.symlinkSync(path.join(home, '.claude'), path.join(project, 'cfg'));
  fs.symlinkSync(home, linkedHome);

  const options = { home, cwd: project };
  const paths = guardPaths({ home });
  assert.deepEqual(classifyPath('notes.txt', paths, options), ['secret']);
  assert.deepEqual(classifyPath(path.join(project, 'cfg', 'settings.json'), paths, options), ['config']);
  assert.deepEqual(guardFileTool('Read', { file_path: path.join(project, 'notes.txt') }, paths, options)[0].signals, ['secret-access']);
  assert.deepEqual(guardFileTool('Write', { file_path: 'cfg/settings.json' }, paths, options)[0].signals, ['guard-tamper']);

  // The home given to TrustDex can itself be a link; targets are compared in its notation.
  const linkedOptions = { home: linkedHome, cwd: path.join(linkedHome, 'project') };
  const linkedPaths = guardPaths({ home: linkedHome });
  assert.deepEqual(classifyPath('notes.txt', linkedPaths, linkedOptions), ['secret']);
  assert.deepEqual(classifyPath(path.join(home, '.aws', 'credentials'), linkedPaths, linkedOptions), ['secret']);
  assert.deepEqual(classifyPath('src/a.js', linkedPaths, linkedOptions), []);
});
