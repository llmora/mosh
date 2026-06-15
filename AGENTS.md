We are conscious of developing small steps at a time, do not over-engineer.

Implement testing for all functionalities, so we do not regress.

Use `uv` for development. Run the test suite with:

```bash
uv run python -m unittest discover -v
```

Build Docker tool images with:

```bash
./scripts/setup.sh --force-docker
```

Do not repeat yourself, keep code simple. Also Maintain DRY persisted state. Do not duplicate canonical entity data across JSON artifacts.

We want to maintain a small number of documents, but these need to be kept in sync with changes:

* SPEC.md records the product spec, design and anything necessary to develope the product from scratch. We maintain a roadmap section with future functionalities.

* README.md: user-facing document describing the product, how to use it and example usage. It also has a small section towards the end on how can developers engage and contribute to the product.
