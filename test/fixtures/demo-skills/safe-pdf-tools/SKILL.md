---
name: safe-pdf-tools
description: Extracts text and tables from PDF files and converts them to markdown. Use when the user asks to process, read, or convert PDF documents.
license: MIT
---

# PDF Tools

## Extract text

Run `scripts/extract_text.py input.pdf` to extract the text layer of a PDF
into a UTF-8 markdown file. The script only reads local files.

## Extract tables

Run `scripts/extract_tables.py input.pdf --page 3` to pull tables into CSV.
Requires `pdfplumber==0.11.0` (see requirements.txt).

## Notes

- Output is written next to the input file with a `.md` / `.csv` suffix.
- See [REFERENCE.md](REFERENCE.md) for advanced options.
