# BOMBE Docs

## Install Dependencies (uv)

```sh
uv sync --frozen
```

## Run Local Server

```sh
uv run mkdocs serve
```

## Build (strict)

```sh
uv run mkdocs build --strict
```

## Deploy to GitHub Pages

```sh
# This will push to the gh-pages branch
uv run mkdocs gh-deploy
```
