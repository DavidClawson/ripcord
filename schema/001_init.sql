-- ripcord warehouse schema, migration 001
--
-- Minimal initial schema: just the functions table, one row per function
-- per target binary. Everything else (basic_blocks, calls, xrefs, strings,
-- register_accesses, mmio_events, etc.) will be added by later migrations
-- as Ghidra extraction grows to cover them.
--
-- This file is idempotent: safe to run on an existing database. Every
-- CREATE uses IF NOT EXISTS.

CREATE TABLE IF NOT EXISTS functions (
    source              VARCHAR NOT NULL,   -- target name from config.yaml
    addr                BIGINT  NOT NULL,   -- entry point address
    name                VARCHAR NOT NULL,   -- Ghidra's name (FUN_xxxx if unrecognized)
    size                BIGINT,             -- bytes in function body
    is_thunk            BOOLEAN,
    is_external         BOOLEAN,
    num_params          INTEGER,
    has_varargs         BOOLEAN,
    calling_convention  VARCHAR,
    basic_block_count   INTEGER,
    signature           VARCHAR,
    extracted_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (source, addr)
);

CREATE INDEX IF NOT EXISTS idx_functions_source ON functions(source);
CREATE INDEX IF NOT EXISTS idx_functions_size   ON functions(size);
CREATE INDEX IF NOT EXISTS idx_functions_name   ON functions(name);
