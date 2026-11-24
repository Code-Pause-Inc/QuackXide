import { describe, expect, it } from "vitest";
import type { ConnectorView } from "./client";
import {
  type DictionaryColumn,
  MAX_COLUMN_DESCRIPTION_CHARS,
  MAX_DICTIONARY_COLUMNS,
  connectorPrefill,
  dictionaryProblem,
  uploadPrefill,
  exampleQuery,
  isColumnName,
  quotedTableName,
  sameColumns,
} from "./dictionary";

const column = (name: string, description = ""): DictionaryColumn => ({
  name,
  type: "int64",
  description,
});

describe("isColumnName", () => {
  it("bounds names in UTF-8 bytes, as the API does", () => {
    expect(isColumnName("a")).toBe(true);
    expect(isColumnName("x".repeat(128))).toBe(true);
    expect(isColumnName("é".repeat(64))).toBe(true);
    expect(isColumnName("")).toBe(false);
    expect(isColumnName("x".repeat(129))).toBe(false);
    expect(isColumnName("é".repeat(65))).toBe(false);
  });

  it("refuses control characters but keeps spaces and case", () => {
    expect(isColumnName("First Name")).toBe(true);
    expect(isColumnName(" age ")).toBe(true);
    for (const bad of ["tab\there", "line\nbreak", "nul\u0000", "del\u007f", "c1\u0085"]) {
      expect(isColumnName(bad)).toBe(false);
    }
  });
});

describe("dictionaryProblem", () => {
  it("accepts no columns, and every bound exactly", () => {
    expect(dictionaryProblem([])).toBeNull();
    const widest = Array.from({ length: MAX_DICTIONARY_COLUMNS }, (_, i) =>
      column(`c${i}`, "é".repeat(MAX_COLUMN_DESCRIPTION_CHARS)),
    );
    expect(dictionaryProblem(widest)).toBeNull();
  });

  it.each([
    ["too many columns", Array.from({ length: 513 }, (_, i) => column(`c${i}`)), /at most 512/],
    ["an empty name", [column("age"), column("")], /Column 2 needs a name/],
    ["a repeated name", [column("age"), column("age")], /Column 2 repeats/],
    ["a long description", [column("age", "d".repeat(501))], /over 500 characters/],
  ])("names %s", (_, columns, message) => {
    expect(dictionaryProblem(columns)).toMatch(message);
  });

  it("counts a description's characters after trimming, not its UTF-16 units", () => {
    expect(dictionaryProblem([column("age", ` ${"😀".repeat(500)} `)])).toBeNull();
    expect(dictionaryProblem([column("age", "😀".repeat(501))])).toMatch(/over 500/);
  });

  it("tells names apart exactly", () => {
    expect(dictionaryProblem([column("Age"), column("age"), column("age ")])).toBeNull();
  });
});

describe("table names and the example query", () => {
  it("quotes any slug, which SQL then reads as exactly that name", () => {
    expect(quotedTableName("health")).toBe('"health"');
    expect(quotedTableName("2026-cohorts")).toBe('"2026-cohorts"');
    expect(quotedTableName('odd"name')).toBe('"odd""name"');
  });

  it("counts the whole table with the genuine COUNT(*) AS n the gate needs", () => {
    expect(exampleQuery("health")).toBe("SELECT COUNT(*) AS n FROM health");
    expect(exampleQuery('"crm-2"')).toBe('SELECT COUNT(*) AS n FROM "crm-2"');
  });
});

describe("connectorPrefill", () => {
  const connectors: ConnectorView[] = [
    {
      slug: "quickbooks",
      display_name: "QuickBooks",
      kind: "accounting",
      columns: [
        { name: "id", type: "string" },
        { name: "total", type: "float64" },
      ],
    },
    { slug: "research_extract", display_name: "Research Extract", kind: "health", columns: [] },
  ];

  it("starts a connector dataset from its mapper's columns, undescribed", () => {
    expect(connectorPrefill(connectors, "quickbooks")).toEqual({
      source: "the QuickBooks connector",
      columns: [
        { name: "id", type: "string", description: "" },
        { name: "total", type: "float64", description: "" },
      ],
    });
  });

  it("has nothing for an upload or a connector without a mapper", () => {
    expect(connectorPrefill(connectors, "upload_cohorts")).toBeNull();
    expect(connectorPrefill(connectors, "research_extract")).toBeNull();
    expect(connectorPrefill([], "quickbooks")).toBeNull();
  });
});

describe("uploadPrefill", () => {
  const datasets = [
    {
      dataset: "upload_cohorts",
      schema: [
        { name: "condition", type: "string" as const },
        { name: "age", type: "int64" as const },
      ],
    },
    { dataset: "quickbooks", schema: null },
    { dataset: "upload_broken", schema: null },
  ];

  it("starts an upload from the schema it declared, undescribed", () => {
    expect(uploadPrefill(datasets, "upload_cohorts")).toEqual({
      source: "the uploaded file",
      columns: [
        { name: "condition", type: "string", description: "" },
        { name: "age", type: "int64", description: "" },
      ],
    });
  });

  it("has nothing without a declared schema", () => {
    expect(uploadPrefill(datasets, "quickbooks")).toBeNull();
    expect(uploadPrefill(datasets, "upload_broken")).toBeNull();
    expect(uploadPrefill(datasets, "upload_unknown")).toBeNull();
  });
});

describe("sameColumns", () => {
  it("compares names, types and descriptions in order", () => {
    const a = [column("age"), column("cost", "cents")];
    expect(sameColumns(a, [column("age"), column("cost", "cents")])).toBe(true);
    expect(sameColumns(a, [column("cost", "cents"), column("age")])).toBe(false);
    expect(sameColumns(a, [column("age"), column("cost")])).toBe(false);
    expect(sameColumns(a, [column("age"), { ...column("cost", "cents"), type: "string" }])).toBe(
      false,
    );
    expect(sameColumns(a, [column("age")])).toBe(false);
  });
});
