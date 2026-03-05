import { describe, it, expect } from 'vitest';

// Current approach with arrays
const priorityDirsArr = ['Desktop', 'Documents', 'Downloads', 'Projects', 'Development', 'Code', 'src', 'components', 'icons'];
const skipDirsArr = ['.git', '.svn', '.hg', 'node_modules', '__pycache__', 'target', 'dist', 'build', '.cache', '.npm', '.yarn', 'Library', 'System', 'Applications', '.Trash'];
const allowedHiddenDirsArr = ['.github', '.vscode', '.idea', '.config', '.gitlab', '.circleci', '.azure', '.jenkins'];
const commonExtensionsArr = ['txt', 'md', 'js', 'ts', 'jsx', 'tsx', 'py', 'java', 'cpp', 'c', 'h', 'css', 'html', 'json', 'xml', 'yaml', 'yml', 'toml', 'ini', 'cfg', 'sh', 'bat', 'ps1', 'rb', 'go', 'rs', 'php', 'sql', 'r', 'scala', 'swift', 'kt', 'dart', 'vue', 'svelte', 'astro', 'scss', 'less', 'readme', 'license', 'changelog', 'contributing', 'gitignore', 'dockerignore', 'editorconfig', 'prettierrc', 'eslintrc', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'webp', 'bmp', 'tiff', 'tif', 'ai', 'eps', 'sketch', 'fig', 'xd', 'psd', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'];
const knownFilesArr = ['readme', 'license', 'changelog', 'contributing', 'dockerfile', 'makefile'];

// Optimized approach with Sets
const priorityDirsSet = new Set(priorityDirsArr);
const skipDirsSet = new Set(skipDirsArr);
const allowedHiddenDirsSet = new Set(allowedHiddenDirsArr);
const commonExtensionsSet = new Set(commonExtensionsArr);
const knownFilesSet = new Set(knownFilesArr);

function runArrayVersion(items: string[], depth: number) {
  let skipCount = 0;
  const skipDirsAtDepth = depth > 2 ? ['.git', '.svn', '.hg', 'node_modules', '__pycache__'] : skipDirsArr;

  for (const item of items) {
    if (skipDirsAtDepth.includes(item)) {
      skipCount++;
      continue;
    }
    if (item.startsWith('.') && !allowedHiddenDirsArr.includes(item)) {
      skipCount++;
      continue;
    }
    const hasExtension = item.includes('.');
    const ext = item.split('.').pop()?.toLowerCase();
    if (hasExtension && ext && commonExtensionsArr.includes(ext)) {
      continue;
    }
    if (!hasExtension && knownFilesArr.includes(item.toLowerCase())) {
      continue;
    }
  }
  return skipCount;
}

function runSetVersion(items: string[], depth: number) {
  let skipCount = 0;
  const skipDirsAtDepthSet = depth > 2 ? new Set(['.git', '.svn', '.hg', 'node_modules', '__pycache__']) : skipDirsSet;

  for (const item of items) {
    if (skipDirsAtDepthSet.has(item)) {
      skipCount++;
      continue;
    }
    if (item.startsWith('.') && !allowedHiddenDirsSet.has(item)) {
      skipCount++;
      continue;
    }
    const hasExtension = item.includes('.');
    const ext = item.split('.').pop()?.toLowerCase();
    if (hasExtension && ext && commonExtensionsSet.has(ext)) {
      continue;
    }
    if (!hasExtension && knownFilesSet.has(item.toLowerCase())) {
      continue;
    }
  }
  return skipCount;
}

describe('MentionPopover Performance Benchmark', () => {
  const numItems = 10000;
  const iterations = 1000;
  const mockItems = Array.from({ length: numItems }, (_, i) => {
    if (i % 10 === 0) return '.git';
    if (i % 10 === 1) return 'node_modules';
    if (i % 10 === 2) return 'index.ts';
    if (i % 10 === 3) return 'README.md';
    if (i % 10 === 4) return 'src';
    if (i % 10 === 5) return '.vscode';
    if (i % 10 === 6) return 'package.json';
    if (i % 10 === 7) return 'some_random_file.txt';
    if (i % 10 === 8) return '.hidden_file';
    return `file_${i}.dat`;
  });

  it('compares array vs set performance', () => {
    console.log(`Running benchmark with ${numItems} items and ${iterations} iterations...`);

    const startArr = performance.now();
    for (let i = 0; i < iterations; i++) {
      runArrayVersion(mockItems, 0);
    }
    const endArr = performance.now();
    const timeArr = endArr - startArr;

    const startSet = performance.now();
    for (let i = 0; i < iterations; i++) {
      runSetVersion(mockItems, 0);
    }
    const endSet = performance.now();
    const timeSet = endSet - startSet;

    console.log(`Array version: ${timeArr.toFixed(2)}ms`);
    console.log(`Set version: ${timeSet.toFixed(2)}ms`);
    console.log(`Improvement: ${(((timeArr - timeSet) / timeArr) * 100).toFixed(2)}%`);

    expect(timeSet).toBeLessThan(timeArr);
  });
});
