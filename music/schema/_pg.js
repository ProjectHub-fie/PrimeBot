/**
 * Minimal Mongoose-compatible model backed by PostgreSQL.
 *
 * The vendored Linix music code addresses its persistence through mongoose
 * models (`db.find`, `db.findOne`, `new db({...}).save()`, `doc.deleteOne()`,
 * `db.updateOne`, `db.create`). PrimeBot has no MongoDB — every feature uses a
 * dedicated Postgres pool. This module implements just the subset of the
 * mongoose model API the music code uses, so those files stay byte-identical.
 *
 * Each model owns one table, created on first use (`CREATE TABLE IF NOT EXISTS`)
 * so the feature works on a fresh database without a migration step.
 */

const { resolveDbUrl } = require('../../server/resolveDbUrl');
const { createPool } = require('../../server/createPool');

let pool = null;
function getPool() {
    if (pool) return pool;
    const cs = resolveDbUrl('MUSIC_DATABASE_URL');
    if (!cs) {
        // A stub keeps the model importable (and the bot bootable) when no
        // database is configured; every query then fails with a clear message.
        pool = {
            query: async () => { throw new Error('MUSIC_DATABASE_URL (or FALLBACK_DATABASE_URL/DATABASE_URL) is not set.'); },
        };
        return pool;
    }
    pool = createPool(cs, { label: 'MUSIC DB' });
    return pool;
}

/** Memoized per-table DDL so a table is created at most once per process. */
const ensured = new Set();
async function ensureTable(model) {
    if (ensured.has(model.table)) return;
    const cols = model.columns.map(([name, type]) => `"${name}" ${type}`).join(', ');
    await getPool().query(`CREATE TABLE IF NOT EXISTS ${model.table} (${cols});`);
    ensured.add(model.table);
}

function rowToDoc(model, row) {
    if (!row) return null;
    const doc = new model();
    for (const [name] of model.columns) {
        doc[name] = row[name] === undefined ? null : row[name];
    }
    if (model.idColumn && row[model.idColumn] !== undefined) {
        Object.defineProperty(doc, '_id', { value: row[model.idColumn], enumerable: false, configurable: true });
    }
    return doc;
}

function buildWhere(model, query) {
    const keys = Object.keys(query || {}).filter((k) => model.columnSet.has(k));
    if (!keys.length) return { clause: '', values: [] };
    const clause = keys.map((k, i) => `"${k}" = $${i + 1}`).join(' AND ');
    return { clause: `WHERE ${clause}`, values: keys.map((k) => query[k]) };
}

/**
 * Create a model class for a table.
 *
 * @param {object} spec
 * @param {string} spec.table            physical table name
 * @param {Array<[string,string]>} spec.columns  [name, sqlType] pairs
 * @param {string} [spec.idColumn]       column used as `_id` (default `id`)
 * @param {Array<[string, (value:any)=>any]>} [spec.serialize]
 *        column → encoder applied on insert/update (e.g. JSON stringify)
 * @param {Array<[string, (value:any)=>any]>} [spec.deserialize]
 *        column → decoder applied when a row is read back
 */
function createModel(spec) {
    const table = spec.table;
    const columns = spec.columns;
    const columnSet = new Set(columns.map(([n]) => n));
    const idColumn = spec.idColumn || 'id';
    const encoders = new Map(spec.serialize || []);
    const decoders = new Map(spec.deserialize || []);

    class Model {
        constructor(values = {}) {
            for (const [name] of columns) {
                if (values[name] !== undefined) this[name] = values[name];
            }
        }

        async save() {
            await ensureTable(Model);
            const keys = Object.keys(this).filter((k) => columnSet.has(k));
            if (!keys.length) return this;
            const values = keys.map((k) => (encoders.has(k) ? encoders.get(k)(this[k]) : this[k]));
            const placeholders = keys.map((_, i) => `$${i + 1}`);
            const updates = keys.map((k) => `"${k}" = EXCLUDED."${k}"`).join(', ');
            const sql = `INSERT INTO ${table} (${keys.map((k) => `"${k}"`).join(', ')})
                         VALUES (${placeholders.join(', ')})
                         ON CONFLICT ("${idColumn}") DO UPDATE SET ${updates}
                         RETURNING *;`;
            const res = await getPool().query(sql, values);
            const stored = res.rows[0];
            for (const [name] of columns) {
                if (stored[name] !== undefined) this[name] = decoders.has(name) ? decoders.get(name)(stored[name]) : stored[name];
            }
            Object.defineProperty(this, '_id', { value: stored[idColumn], enumerable: false, configurable: true });
            return this;
        }

        async deleteOne() {
            await ensureTable(Model);
            if (this._id === undefined || this._id === null) return { deletedCount: 0 };
            const res = await getPool().query(`DELETE FROM ${table} WHERE "${idColumn}" = $1;`, [this._id]);
            return { deletedCount: res.rowCount || 0 };
        }

        toObject() {
            const out = {};
            for (const [name] of columns) if (this[name] !== undefined) out[name] = this[name];
            return out;
        }
    }

    Model.table = table;
    Model.columns = columns;
    Model.columnSet = columnSet;
    Model.idColumn = idColumn;

    Model.find = async function find(query = {}) {
        await ensureTable(Model);
        const { clause, values } = buildWhere(Model, query);
        const res = await getPool().query(`SELECT * FROM ${table} ${clause} ORDER BY "${idColumn}" ASC;`, values);
        return res.rows.map((row) => {
            const doc = rowToDoc(Model, row);
            for (const [name, decode] of decoders) if (doc[name] !== null) doc[name] = decode(doc[name]);
            return doc;
        });
    };

    Model.findOne = async function findOne(query = {}) {
        await ensureTable(Model);
        const { clause, values } = buildWhere(Model, query);
        const res = await getPool().query(`SELECT * FROM ${table} ${clause} ORDER BY "${idColumn}" ASC LIMIT 1;`, values);
        const doc = rowToDoc(Model, res.rows[0]);
        if (!doc) return null;
        for (const [name, decode] of decoders) if (doc[name] !== null) doc[name] = decode(doc[name]);
        return doc;
    };

    Model.create = async function create(values = {}) {
        const doc = new Model(values);
        await doc.save();
        return doc;
    };

    /** Supports `$set` and `$pull` — the only operators the music code uses. */
    Model.updateOne = async function updateOne(query = {}, update = {}) {
        await ensureTable(Model);
        const { clause, values } = buildWhere(Model, query);
        if (update.$pull) {
            const key = Object.keys(update.$pull)[0];
            if (!key) return { modifiedCount: 0 };
            const encoder = encoders.get(key) || ((v) => v);
            const removed = encoder(update.$pull[key]);
            const res = await getPool().query(
                `UPDATE ${table}
                    SET "${key}" = COALESCE((
                        SELECT jsonb_agg(elem)
                          FROM jsonb_array_elements(COALESCE("${key}", '[]'::jsonb)) elem
                         WHERE elem <> $${values.length + 1}::jsonb
                    ), '[]'::jsonb)
                  ${clause};`,
                [...values, JSON.stringify(removed)],
            );
            return { modifiedCount: res.rowCount || 0 };
        }
        const set = update.$set || update;
        const keys = Object.keys(set).filter((k) => columnSet.has(k));
        if (!keys.length) return { modifiedCount: 0 };
        const assignments = keys.map((k, i) => `"${k}" = $${values.length + i + 1}`).join(', ');
        const setValues = keys.map((k) => (encoders.has(k) ? encoders.get(k)(set[k]) : set[k]));
        const res = await getPool().query(`UPDATE ${table} SET ${assignments} ${clause};`, [...values, ...setValues]);
        return { modifiedCount: res.rowCount || 0 };
    };

    Model.deleteOne = async function deleteOne(query = {}) {
        await ensureTable(Model);
        const { clause, values } = buildWhere(Model, query);
        const res = await getPool().query(`DELETE FROM ${table} ${clause};`, values);
        return { deletedCount: res.rowCount || 0 };
    };

    Model.deleteMany = Model.deleteOne;

    return Model;
}

module.exports = { createModel, getPool };
