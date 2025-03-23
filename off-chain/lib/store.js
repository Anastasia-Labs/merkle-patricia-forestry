import assert from "node:assert";
import { Level } from "level";
import { NULL_HASH } from "./helpers.js";
import pg from "pg";

export class Store {
  #batch;
  #db;

  constructor(dbType, options) {
    if (dbType === "memory") {
      this.#db = inMemoryMap();
    } else if (dbType === "level" && options) {
      try {
        this.#db = new Level(options.filename, { valueEncoding: "json" });
      } catch (e) {
        throw e;
      }
    } else if (dbType === "pg" && options) {
      this.#db = pgMap();
    } else {
      throw new Error("unrecognized db type or missing options");
    }
  }

  async ready() {
    return this.#db.open ? this.#db.open() : Promise.resolve();
  }

  async batch(callback) {
    assert(this.#batch === undefined, "batch already ongoing");

    this.#batch = [];

    let result;
    try {
      result = await callback();
    } catch (e) {
      this.#batch = undefined;
      throw e;
    }

    await this.#db.batch(this.#batch);

    this.#batch = undefined;

    return result;
  }

  async get(key, deserialise) {
    return deserialise(
      key,
      await this.#db.get((key ?? NULL_HASH).toString("hex")),
      this
    );
  }

  async put(key, value) {
    (key = (key ?? NULL_HASH).toString("hex")), (value = value.serialise());

    if (this.#batch !== undefined) {
      this.#batch.push({ type: "put", key, value });
    } else {
      this.#db.put(key, value);
    }
  }

  async del(key) {
    key = (key ?? NULL_HASH).toString("hex");

    if (this.#batch !== undefined) {
      this.#batch.push({ type: "del", key });
    } else {
      this.#db.del(key);
    }
  }

  async size() {
    return this.#db.size !== undefined
      ? this.#db.size
      : this.#db
          .keys()
          .all()
          .then((it) => it.length);
  }
}

function inMemoryMap() {
  const db = new Map();

  return {
    get(k) {
      return db.get(k);
    },

    put(k, v) {
      db.set(k, v);
    },

    del(k) {
      db.delete(k);
    },

    batch(ops) {
      ops.forEach(({ type, key, value }) => {
        this[type](key, value);
      });
    },

    get size() {
      return db.size;
    },
  };
}

function createTableQuery(tableName) {
  const validTableName = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

  if (tableName && validTableName.test(tableName)) {
    return `
CREATE TABLE IF NOT EXISTS ${tableName} (
    key BYTEA NOT NULL,
    value BYTEA NOT NULL,
    PRIMARY KEY (key)
  );`;
  } else {
    throw new Error("invalid table name");
  }
}

async function pgMap(options) {
  const t = options.tableName;
  return {
    async open() {
      try {
        const db = new pg.Pool({
          host: options.host,
          user: options.user,
          password: options.password,
          database: options.database,
          max: options.max,
          idleTimeoutMillis: options.idleTimeoutMillis,
          connectionTimeoutMillis: options.connectionTimeoutMillis,
        });
        await db.query(createTableQuery(t));
      } catch (e) {
        throw e;
      }
    },

    async get(k) {
      const { rows } = await db.query(`SELECT value FROM ${t} WHERE key = $1`, [
        k,
      ]);
      return rows[0]?.value;
    },

    async put(k, v) {
      await db.query(
        `INSERT INTO ${t} (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2`,
        [k, v]
      );
    },

    async del(k) {
      await db.query(`DELETE FROM ${t} WHERE key = $1`, [k]);
    },

    async batch(ops) {
      await db.query("BEGIN");
      for (const { type, key, value } of ops) {
        await this[type](key, value);
      }
      await db.query("COMMIT");
    },

    async size() {
      const { rows } = await db.query(`SELECT COUNT(*) FROM ${t}`);
      return rows[0].count;
    },
  };
}
