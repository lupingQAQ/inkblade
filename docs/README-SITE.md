# Documentation site

The site is generated from the Markdown guides in this directory and published
with GitHub Pages from `main` (`/docs`).

## Build

```bash
python scripts/build-docs-site.py          # regenerate docs/*.html + index.html
python scripts/build-docs-site.py --check  # CI: fail when committed output is stale
python scripts/check-docs-links.py         # no external references, no broken links
```

`scripts/build-docs-site.py` owns `docs/index.html`, `docs/assets/style.css` and one
`docs/<name>.html` per Markdown guide listed in `PAGES`. Edit the Markdown, not the
HTML; the HTML is overwritten.

## What the published site contains

- `index.html` — bilingual landing page with the quick-start commands.
- One page per guide: install, usage, features, workflow, modules, architecture,
  agent/LLM configuration, vulnerability coverage, pilot kit, plugin SDK, FAQ, versioning.
- `assets/style.css` — the dark theme. No webfonts, no CDN, no analytics.
- `.nojekyll` — Pages serves the files as-is.

## Rules

1. **No external references.** No absolute URL with a network scheme in `href`, `src`, CSS
   `url()` or `@import`, and none in body text. The site must render with the network unplugged.
   A link to another project belongs in a code sample or nowhere.
2. **Relative links only.** `scripts/check-docs-links.py` resolves every relative
   link and fragment against the committed files.
3. **No internal material.** Screenshots of real clusters, customer names, internal
   paths and unpublished findings never go in this directory.
4. **Regenerate, then commit.** A stale site fails the docs check in CI.

## 中文

站点由本目录下的 Markdown 生成，随 `main` 分支的 `/docs` 目录发布。

```bash
python scripts/build-docs-site.py          # 重新生成 docs/*.html 与 index.html
python scripts/build-docs-site.py --check  # CI：生成结果与提交不一致时报错
python scripts/check-docs-links.py         # 检查零外链与相对链接
```

规则：不出现任何外链；只用相对链接；不放内部材料（真实集群截图、客户名、内部路径、未公开发现）；
改 Markdown 后重新生成再提交。
