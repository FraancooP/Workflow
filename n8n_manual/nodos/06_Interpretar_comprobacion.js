const response = $input.first().json;

if (
  typeof response.stdout !== 'string' ||
  response.stdout.trim() === ''
) {
  throw new Error(
    'El trabajador no devolvió contenido en stdout'
  );
}

let data;

try {
  data = JSON.parse(response.stdout);
} catch {
  throw new Error(
    'La comprobación no devolvió un JSON válido'
  );
}

if (
  data === null ||
  typeof data !== 'object' ||
  Array.isArray(data)
) {
  throw new Error(
    'Se esperaba un objeto JSON como resultado'
  );
}

if (data.fatal) {
  throw new Error(
    'El trabajador rechazó la comprobación: ' + data.fatal
  );
}

if (!Array.isArray(data.records)) {
  throw new Error(
    'La respuesta no contiene la lista records'
  );
}

return [{ json: data }];