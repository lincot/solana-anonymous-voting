import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  dts: { entry: 'src/index.ts' },
  sourcemap: true,
  minify: true,
  clean: true,
  treeshake: true,
  outDir: 'dist',
  target: 'es2020',
  platform: 'neutral',
  external: [
    '@coral-xyz/anchor',
    '@solana/web3.js',
    'viem',
  ],
  outExtension({ format }) {
    return format === 'esm' ? { js: '.mjs' } : { js: '.cjs' };
  },
});

