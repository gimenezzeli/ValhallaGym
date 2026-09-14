const COOKIE_NAME = "vg_session";
const SESSION_SECONDS = 60 * 60 * 24 * 7;
const encoder = new TextEncoder();

function base64UrlEncode(bytes) {
  let binary = "";

  for (const byte of new Uint8Array(bytes)) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64UrlDecode(value) {
  const base64 =
    value.replace(/-/g, "+").replace(/_/g, "/") +
    "=".repeat((4 - (value.length % 4)) % 4);

  const binary = atob(base64);

  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

async function getKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign", "verify"]
  );
}

async function createSession(secret) {
  const exp =
    Math.floor(Date.now() / 1000) + SESSION_SECONDS;

  const nonce = crypto.randomUUID();
  const data = `${exp}.${nonce}`;

  const key = await getKey(secret);

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(data)
  );

  return `${data}.${base64UrlEncode(signature)}`;
}

async function verifySession(token, secret) {
  if (!token) return false;

  const parts = token.split(".");

  if (parts.length !== 3) return false;

  const [exp, nonce, signature] = parts;

  if (
    !/^\d+$/.test(exp) ||
    Number(exp) < Math.floor(Date.now() / 1000)
  ) {
    return false;
  }

  try {
    const key = await getKey(secret);

    return await crypto.subtle.verify(
      "HMAC",
      key,
      base64UrlDecode(signature),
      encoder.encode(`${exp}.${nonce}`)
    );
  } catch {
    return false;
  }
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";

  for (const part of header.split(";")) {
    const [key, ...rest] = part.trim().split("=");

    if (key === name) {
      return rest.join("=");
    }
  }

  return null;
}

function loginPage(error = false) {
  return `<!doctype html>

<html lang="es">

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width, initial-scale=1.0">

<title>Acceso | Valhalla Gym</title>

<style>

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  min-height: 100vh;

  display: grid;
  place-items: center;

  background: #111;
  color: #fff;

  font-family: Arial, sans-serif;
}

.login {
  width: min(92%, 420px);

  padding: 32px;

  background: #1b1b1b;

  border: 1px solid #333;

  border-radius: 18px;

  text-align: center;

  box-shadow:
    0 15px 50px rgba(0,0,0,.35);
}

.brand {
  font-weight: 900;

  letter-spacing: 3px;

  font-size: 22px;

  margin-bottom: 28px;
}

h1 {
  margin: 0 0 8px;

  font-size: 30px;
}

p {
  color: #bbb;
}

input {
  width: 100%;

  padding: 14px 16px;

  border-radius: 10px;

  border: 1px solid #444;

  background: #111;

  color: #fff;

  font-size: 16px;

  margin: 12px 0;
}

button {
  width: 100%;

  padding: 14px;

  border: 0;

  border-radius: 10px;

  background: #fff;

  color: #111;

  font-weight: 800;

  font-size: 15px;

  cursor: pointer;
}

.error {
  color: #ff7676;

  font-size: 14px;
}

</style>

</head>

<body>

<main class="login">

<div class="brand">
VALHALLA GYM
</div>

<h1>
Acceso privado
</h1>

<p>
Ingresá la contraseña para continuar.
</p>

<form method="POST" action="/login">

<input
  type="password"
  name="password"
  placeholder="Contraseña"
  autocomplete="current-password"
  required
>

<button type="submit">
INGRESAR
</button>

</form>

${error
  ? '<p class="error">Contraseña incorrecta.</p>'
  : ''}

</main>

</body>

</html>`;
}

export default {

  async fetch(request, env) {

    if (!env.PASSWORD) {
  return new Response(
    "Falta configurar el secret PASSWORD en Cloudflare.",
    { status: 500 }
  );
    }

    const url = new URL(request.url);

    // Procesar inicio de sesión
    if (
      url.pathname === "/login" &&
      request.method === "POST"
    ) {

      const form = await request.formData();

      const password = form.get("password");

      if (
        typeof password !== "string" ||
        password !== env.PASSWORD
      ) {

        return new Response(
          loginPage(true),
          {
            status: 401,

            headers: {
              "Content-Type":
                "text/html; charset=UTF-8",

              "Cache-Control":
                "no-store"
            }
          }
        );

      }

      const token =
        await createSession(env.PASSWORD);

      return new Response(null, {

        status: 303,

        headers: {

          Location: "/",

          "Set-Cookie":
            `${COOKIE_NAME}=${token}; ` +
            `Path=/; ` +
            `Max-Age=${SESSION_SECONDS}; ` +
            `HttpOnly; Secure; SameSite=Lax`,

          "Cache-Control":
            "no-store"
        }

      });

    }

    // Comprobar si ya inició sesión
    const token =
      getCookie(request, COOKIE_NAME);

    const valid =
      await verifySession(
        token,
        env.PASSWORD
      );

    // Si no está autenticado,
    // mostrar pantalla de contraseña
    if (!valid) {

      return new Response(
        loginPage(false),
        {

          status: 200,

          headers: {

            "Content-Type":
              "text/html; charset=UTF-8",

            "Cache-Control":
              "no-store"

          }

        }
      );

    }

    // Si está autenticado,
    // mostrar la página de Valhalla Gym
    return env.ASSETS.fetch(request);

  }

};
