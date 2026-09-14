/**
 * Heuristic deobfuscation for "string array obfuscation" — a real,
 * common evasion technique (what `javascript-obfuscator.io` and similar
 * tools produce): every string literal in a bundle is hoisted into one
 * array and referenced by index (directly, or through a trivial decoder
 * function), specifically so a naive scan for literal endpoint/secret
 * strings finds nothing. Variable and function renaming survives
 * minification trivially and defeats nothing here; moving the *string
 * literal itself* out of line is what actually hides it from
 * `js-intel.ts`'s pattern matching, which only ever looks at literal
 * quoted strings.
 *
 * `resolveStringArrayObfuscation` is a pre-processing step, not a second
 * analysis engine: its output is plain JavaScript text with the array
 * references inlined back to literal strings, fed straight into the
 * existing, unmodified `analyzeJavaScript` (js-intel.ts) — deobfuscation
 * and endpoint/secret extraction stay two separate, single-purpose
 * functions, never merged into one.
 *
 * Deliberately narrow: this resolves the single most common real-world
 * shape (a top-level array-of-string-literals declaration, referenced by a
 * literal numeric index either directly or through one level of decoder
 * function) via regex/text substitution, not a JS parser or interpreter —
 * consistent with `js-intel.ts`'s own pragmatic, non-AST approach. A
 * reference that isn't a literal number (a computed or offset index) is
 * left alone rather than guessed at.
 */

const STRING_ARRAY_DECLARATION =
  /(?:var|let|const)\s+(_?\$?[A-Za-z_][\w$]*)\s*=\s*(\[\s*(?:(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')\s*,?\s*)+\]);/g;

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const SIMPLE_ESCAPES: Readonly<Record<string, string>> = {
  n: '\n',
  r: '\r',
  t: '\t',
  b: '\b',
  f: '\f',
  v: '\v',
  '0': '\0',
  '\\': '\\',
  "'": "'",
  '"': '"',
};

/**
 * Decodes one quoted JS string literal (quotes included), handling `\xNN`
 * and `\uNNNN` escapes explicitly — real obfuscators (and real evasive
 * hand-written code) routinely hex/unicode-escape string-array contents
 * specifically so the endpoint/secret text never appears as readable text
 * in the source, which is what actually defeats a plain literal-string
 * regex scan (a plain quoted literal, unescaped, does not — `js-intel.ts`'s
 * own patterns already scan every string literal regardless of where it's
 * declared). `JSON.parse` cannot be reused here: `\xNN` is a valid JS
 * escape but not a valid JSON one.
 */
function decodeJsStringLiteral(literal: string): string {
  const inner = literal.slice(1, -1);
  let result = '';
  for (let i = 0; i < inner.length; i += 1) {
    if (inner[i] !== '\\' || i + 1 >= inner.length) {
      result += inner[i];
      continue;
    }
    const next = inner[i + 1];
    if (next === 'x' && i + 3 < inner.length) {
      result += String.fromCharCode(Number.parseInt(inner.slice(i + 2, i + 4), 16));
      i += 3;
      continue;
    }
    if (next === 'u' && i + 5 < inner.length) {
      result += String.fromCharCode(Number.parseInt(inner.slice(i + 2, i + 6), 16));
      i += 5;
      continue;
    }
    result += SIMPLE_ESCAPES[next as string] ?? next;
    i += 1;
  }
  return result;
}

/** Parses a bracketed, comma-separated list of quoted string literals — never arbitrary code, only what `STRING_ARRAY_DECLARATION` already matched — into a real string array. */
function parseStringArrayLiteral(arrayLiteral: string): readonly string[] | undefined {
  const literals = arrayLiteral.match(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/g);
  return literals?.map(decodeJsStringLiteral);
}

export interface DeobfuscationResult {
  readonly code: string;
  /** How many distinct string-array declarations were found and resolved -- 0 means this bundle does not use this obfuscation shape (the overwhelmingly common case for an unobfuscated bundle). */
  readonly resolvedArrayCount: number;
  /** Total indexed/decoder-function references successfully inlined back to a literal string. */
  readonly resolvedReferenceCount: number;
}

export function resolveStringArrayObfuscation(code: string): DeobfuscationResult {
  let result = code;
  let resolvedArrayCount = 0;
  let resolvedReferenceCount = 0;

  for (const match of code.matchAll(STRING_ARRAY_DECLARATION)) {
    const [, varName, arrayLiteral] = match;
    if (!varName || !arrayLiteral) continue;
    const values = parseStringArrayLiteral(arrayLiteral);
    if (!values || values.length === 0) continue;
    resolvedArrayCount += 1;

    const inline = (indexStr: string): string | undefined => {
      const index = Number(indexStr);
      const value = values[index];
      return value !== undefined ? JSON.stringify(value) : undefined;
    };

    // Direct indexing: varName[N]
    const directIndexPattern = new RegExp(`\\b${escapeRegExp(varName)}\\s*\\[\\s*(\\d+)\\s*\\]`, 'g');
    result = result.replace(directIndexPattern, (full, indexStr: string) => {
      const inlined = inline(indexStr);
      if (inlined !== undefined) resolvedReferenceCount += 1;
      return inlined ?? full;
    });

    // One-level decoder function: function fnName(n){return varName[n];} -- then calls like fnName(N).
    const decoderFnPattern = new RegExp(
      `function\\s+(_?\\$?[A-Za-z_][\\w$]*)\\s*\\(\\s*(_?\\$?[A-Za-z_][\\w$]*)\\s*\\)\\s*\\{\\s*return\\s+${escapeRegExp(varName)}\\[\\s*\\2\\s*\\]\\s*;?\\s*\\}`,
    );
    const decoderMatch = decoderFnPattern.exec(result);
    if (decoderMatch?.[1]) {
      const fnName = decoderMatch[1];
      const callPattern = new RegExp(`\\b${escapeRegExp(fnName)}\\s*\\(\\s*(\\d+)\\s*\\)`, 'g');
      result = result.replace(callPattern, (full, indexStr: string) => {
        const inlined = inline(indexStr);
        if (inlined !== undefined) resolvedReferenceCount += 1;
        return inlined ?? full;
      });
    }
  }

  return { code: result, resolvedArrayCount, resolvedReferenceCount };
}
