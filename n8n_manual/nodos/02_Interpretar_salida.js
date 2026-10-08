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
    'La salida del trabajador no contiene un JSON válido'
  );
}

if (
  data === null ||
  typeof data !== 'object' ||
  Array.isArray(data)
) {
  throw new Error(
    'Se esperaba un objeto JSON como respuesta'
  );
}

if (data.fatal) {
  throw new Error(
    'El trabajador rechazó la operación: ' + data.fatal
  );
}

if (!Array.isArray(data.raw)) {
  throw new Error(
    'La respuesta no contiene la lista raw esperada'
  );
}

return [{ json: data }];