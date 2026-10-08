const target_id = 'T1';

if (!/^(T1|T2|P1|P2)$/.test(target_id)) {
  throw new Error('Identificador de target no permitido');
}

const started_ms = Date.now();

const run_id =
  String(started_ms) +
  '_' +
  Math.random().toString(16).slice(2, 10);

return [
  {
    json: {
      target_id,
      run_id,
      started_at: new Date(started_ms).toISOString(),
      started_ms
    }
  }
];