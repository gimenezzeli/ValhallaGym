const COOKIE_NAME = "vg_session";
const SESSION_SECONDS = 60 * 60 * 24 * 30;
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
  return `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">

  <title>Acceso | Valhalla Gym</title>

  <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;500;700;900&display=swap" rel="stylesheet">

  <style>
    :root {
      --primary: #f1c40f;
      --text: #fff;
      --text-light: #ccc;
      --text-muted: #aaa;
      --bg: #000;
      --card: rgba(20,20,20,.88);
      --transition: .3s ease;
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      min-height: 100vh;

      font-family: 'Poppins', sans-serif;
      color: var(--text);

      display: flex;
      align-items: center;
      justify-content: center;

      padding: 25px;

      background:
        linear-gradient(
          rgba(0,0,0,.78),
          rgba(0,0,0,.95)
        ),
        url("https://gimenezzeli.github.io/ValhallaGym/img/hero.png");

      background-size: cover;
      background-position: center;
      background-repeat: no-repeat;
    }

    .login-container {
      width: 100%;
      max-width: 430px;
      text-align: center;
      animation: fade .8s ease;
    }

    @keyframes fade {
      from {
        opacity: 0;
        transform: translateY(20px);
      }

      to {
        opacity: 1;
        transform: none;
      }
    }

    .logo {
      width: 75px;
      height: 75px;
      object-fit: contain;

      margin-bottom: 10px;

      filter:
        drop-shadow(
          0 0 10px
          rgba(241,196,15,.65)
        );
    }

    .brand {
      margin: 0 0 35px;

      color: var(--primary);

      font-size: 1.5rem;
      font-weight: 700;
      letter-spacing: 1px;
    }

    .login-card {
      padding: 35px 30px;

      background: var(--card);

      border: 1px solid
        rgba(241,196,15,.25);

      border-radius: 20px;

      box-shadow:
        0 0 30px
        rgba(241,196,15,.08);
    }

    .login-card h1 {
      margin: 0;

      font-size: clamp(1.8rem, 6vw, 2.4rem);
      font-weight: 900;

      letter-spacing: .5px;
    }

    .login-card h1 span {
      color: var(--primary);
    }

    .login-line {
      width: 80px;
      height: 4px;

      margin: 15px auto 25px;

      background: var(--primary);

      border-radius: 20px;
    }

    .description {
      margin: 0 0 28px;

      color: var(--text-muted);

      font-size: .95rem;
      line-height: 1.6;
    }

    .input-group {
      text-align: left;
      margin-bottom: 20px;
    }

    .input-group label {
      display: block;

      margin-bottom: 8px;

      color: var(--text-light);

      font-size: .9rem;
      font-weight: 500;
    }

    .password-input {
      width: 100%;

      padding: 13px 16px;

      border: 1px solid
        rgba(241,196,15,.25);

      border-radius: 12px;

      outline: none;

      background: rgba(0,0,0,.7);

      color: var(--text);

      font-family: inherit;
      font-size: 1rem;

      transition: var(--transition);
    }

    .password-input:focus {
      border-color: var(--primary);

      box-shadow:
        0 0 15px
        rgba(241,196,15,.18);
    }

    .password-input::placeholder {
      color: #777;
    }

    .btn {
      width: 100%;

      padding: 12px 28px;

      border: 2px solid var(--primary);
      border-radius: 50px;

      color: var(--primary);
      background: transparent;

      font-family: inherit;
      font-size: 1rem;
      font-weight: 600;

      cursor: pointer;

      transition: var(--transition);
    }

    .btn:hover {
      background: var(--primary);
      color: var(--bg);

      box-shadow:
        0 0 30px
        rgba(241,196,15,.3);
    }

    .error {
      margin: 18px 0 0;

      padding: 10px 12px;

      border-radius: 10px;

      background: rgba(220,50,50,.1);
      border: 1px solid rgba(220,50,50,.3);

      color: #ff8a8a;

      font-size: .85rem;
    }

    .footer-text {
      margin-top: 25px;

      color: #777;

      font-size: .75rem;
    }

    @media (max-width: 600px) {

      body {
        padding: 20px;
      }

      .logo {
        width: 65px;
        height: 65px;
      }

      .brand {
        font-size: 1.3rem;
        margin-bottom: 25px;
      }

      .login-card {
        padding: 30px 22px;
      }
    }
  </style>
</head>

<body>

  <main class="login-container">

    <img
      src="https://gimenezzeli.github.io/ValhallaGym/img/logo.png"
      alt="Valhalla Gym"
      class="logo"
    >

    <h2 class="brand">VALHALLA GYM</h2>

    <section class="login-card">

      <h1>ACCESO <span>PRIVADO</span></h1>

      <div class="login-line"></div>

      <p class="description">
        Ingresá la contraseña para acceder
        a las rutinas de entrenamiento.
      </p>

      <form method="POST" action="/login">

        <div class="input-group">

          <label for="password">
            Contraseña
          </label>

          <input
            id="password"
            name="password"
            type="password"
            class="password-input"
            placeholder="Ingresá tu contraseña"
            autocomplete="current-password"
            required
            autofocus
          >

        </div>

        <button type="submit" class="btn">
          INGRESAR
        </button>

      </form>

      ${
        error
          ? `<p class="error">
               Contraseña incorrecta. Intentá nuevamente.
             </p>`
          : ""
      }

    </section>

    <p class="footer-text">
      Valhalla Gym · Entrenamiento y superación
    </p>

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
