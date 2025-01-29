// @ts-check
import { defineConfig } from 'astro/config';

import node from '@astrojs/node';

import tailwind from '@astrojs/tailwind';

import db from '@astrojs/db';

import auth from 'auth-astro';

// https://astro.build/config
export default defineConfig({
  output: 'server',
  security: {
    checkOrigin: false,
  },
  adapter: node({
    mode: 'standalone'
  }),
  integrations: [tailwind(), db(), auth()]
});
