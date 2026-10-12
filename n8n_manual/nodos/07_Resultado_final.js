const data = $input.first().json;
const inicio = $('INICIO').first().json;
const collection = $('INTERPRETAR SALIDA').first().json;
const normalized = $('NORMALIZAR').first().json;

// Evitar mezclar resultados de distintas ejecuciones.
for (const [name, value] of [
  ['Recolección', collection],
  ['Normalización', normalized],
  ['Comprobación', data],
]) {
  if (
    value.target_id !== inicio.target_id ||
    value.run_id !== inicio.run_id
  ) {
    throw new Error(name + ': target o run_id no coincide con INICIO');
  }
}

if (
  !normalized.scope ||
  !normalized.counts ||
  !Array.isArray(normalized.hosts) ||
  !Array.isArray(normalized.candidates) ||
  !Array.isArray(data.records)
) {
  throw new Error('Faltan datos necesarios para el resultado final');
}

if (!Number.isFinite(inicio.started_ms)) {
  throw new Error('INICIO no contiene un started_ms válido');
}

if (!['completed', 'partial', 'no_authorized_hosts'].includes(data.status)) {
  throw new Error('Estado de comprobación inesperado: ' + data.status);
}

const records = data.records;
const allowed = new Set(normalized.scope.allowed_hosts);

// Comprobar también el alcance de los registros recibidos.
if (records.some(record => !allowed.has(record.host))) {
  throw new Error('Se recibió un registro de un host fuera del alcance');
}

const collectionStatus =
  collection.collection_status ??
  (normalized.scope.mode === 'lab' ? 'synthetic' : 'unknown');

const sourceProblem = Object.values(collection.sources ?? {}).some(
  source => ['error', 'timeout', 'partial'].includes(source.status)
);

const collectionProblem =
  collectionStatus === 'partial' ||
  collectionStatus === 'unknown' ||
  sourceProblem;

const checkPerformed = data.check_performed === true;
const parseErrors = data.parse_errors ?? [];

const checkProblem = checkPerformed && (
  !['ok', 'skipped'].includes(data.httpx_status) ||
  parseErrors.length > 0 ||
  records.some(record => record.http_state === 'inconclusive')
);

const checksStatus = !checkPerformed
  ? 'not_run'
  : checkProblem
    ? 'partial'
    : 'completed';

const status = collectionProblem || checkProblem || data.status === 'partial'
  ? 'partial'
  : !checkPerformed
    ? 'no_authorized_hosts'
    : 'completed';

const finishedMs = Date.now();

const report = {
  schema_version: '1.1',
  target_id: inicio.target_id,
  run_id: inicio.run_id,

  status,
  collection_status: collectionStatus,
  checks_status: checksStatus,
  check_performed: checkPerformed,

  started_at: inicio.started_at,
  collected_at: collection.collected_at,
  checks_finished_at: data.finished_at ?? null,
  result_prepared_at: new Date(finishedMs).toISOString(),

  scope: normalized.scope,
  sources: collection.sources,
  provided_targets:
    collection.provided_targets ?? [],

  counts: {
    ...normalized.counts,
    checked_records: records.length,
    dns_resolved: records.filter(
      record => record.dns_status === 'resolved'
    ).length,
    http_responding: records.filter(
      record => record.http_observed === true
    ).length,
    http_no_response_observed: records.filter(
      record => record.http_state === 'no_response_observed'
    ).length,
    http_inconclusive: records.filter(
      record => record.http_state === 'inconclusive'
    ).length,
  },

  timings_ms: {
    collection: collection.collection_ms,
    normalization: normalized.normalization_ms,
    dns: data.dns_ms ?? null,
    httpx: data.httpx_ms ?? null,
    probe: data.probe_ms ?? null,
    elapsed_until_result: finishedMs - inicio.started_ms,
  },

  raw: collection.raw,
  candidates: normalized.candidates,
  authorized_hosts: normalized.hosts,
  pending_authorization: normalized.pending,
  rejected: normalized.rejected,
  records,

  diagnostics: {
    httpx_status: data.httpx_status ?? 'not_run',
    parse_errors: parseErrors,
    message: data.message ?? null,
  },
};

return [{ json: report }];