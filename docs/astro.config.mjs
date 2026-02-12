// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightClientMermaid from '@pasqal-io/starlight-client-mermaid';

export default defineConfig({
	integrations: [
		starlight({
			title: 'Sonar Catalog',
			description: 'Petabyte-scale sonar file catalog with deduplication across distributed NFS systems',
			social: [
				{ icon: 'github', label: 'GitHub', href: 'https://github.com/brandonrc/sonar-catalog' },
			],
			plugins: [starlightClientMermaid()],
			customCss: ['./src/styles/custom.css'],
			sidebar: [
				{
					label: 'Getting Started',
					items: [
						{ label: 'Welcome', slug: 'docs' },
						{ label: 'Quickstart', slug: 'docs/getting-started/quickstart' },
						{ label: 'Installation', slug: 'docs/getting-started/installation' },
						{ label: 'Configuration', slug: 'docs/getting-started/configuration' },
						{ label: 'Architecture', slug: 'docs/getting-started/architecture' },
					],
				},
				{
					label: 'Guides',
					items: [
						{ label: 'Crawling Files', slug: 'docs/guides/crawling' },
						{ label: 'Host Discovery', slug: 'docs/guides/discovery' },
						{ label: 'Searching & Dedup', slug: 'docs/guides/searching' },
						{ label: 'Nav Extraction', slug: 'docs/guides/nav-extraction' },
						{ label: 'Exporting Data', slug: 'docs/guides/exporting' },
						{ label: 'Demo Mode', slug: 'docs/guides/demo-mode' },
					],
				},
				{
					label: 'Sonar Formats',
					items: [
						{ label: 'Supported Formats', slug: 'docs/formats/overview' },
						{ label: 'Custom Formats', slug: 'docs/formats/custom' },
					],
				},
				{
					label: 'Plugin System',
					items: [
						{ label: 'Overview', slug: 'docs/plugins/overview' },
						{ label: 'Writing a Plugin', slug: 'docs/plugins/writing-a-plugin' },
						{ label: 'Hook Reference', slug: 'docs/plugins/hooks' },
						{ label: 'Manifest Format', slug: 'docs/plugins/manifest' },
					],
				},
				{
					label: 'Web Interface',
					items: [
						{ label: 'Search UI', slug: 'docs/web/search-ui' },
						{ label: 'CesiumJS Globe', slug: 'docs/web/globe' },
					],
				},
				{
					label: 'Reference',
					items: [
						{ label: 'CLI Commands', slug: 'docs/reference/cli' },
						{ label: 'REST API', slug: 'docs/reference/api' },
						{ label: 'Database Schema', slug: 'docs/reference/database' },
						{ label: 'Environment & Config', slug: 'docs/reference/environment' },
					],
				},
			],
		}),
	],
});
