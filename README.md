## Caso 1
En el siguiente código se muestra un ejemplo de un sistema de autenticación de usuario basicos.

``` python
FUNCTION authenticateUser(username, password):
QUERY database WITH username AND password
IF found RETURN True
ELSE RETURN False
```

### Analisis SAST

- En el código, obtener directamente el usuario y concatenarlo directamente a la consulta representa un fallo de inyección SQL si el código de la consulta es como el siguiente:

``` sql
SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
```

- Inyectar en el username el siguiente valor: ' OR '1'='1' provocará que la base de datos ignore la verificación del usuario y contraseña al ser una expresión que siempre será verdadera.
- La contraseña se está almacenando en texto plano, lo cual es otro fallo de seguridad; para lo cual se debe implementar un sistema de hash para almacenar la contraseña.
- El código no controla errores que eviten exponer información sensible.

### Analisis DAST

- Para evitar el problema de inyección SQL se pueden utilizar consultas parametrizadas, ya que la base de datos tratará la consulta como cadena y no como código SQL; por otra parte, un ORM ayudaría de mejor manera a evitar este tipo de problemas, ya que se encarga de generar las consultas SQL abstraiendo e interactuando con la base de datos como objetos y no como código SQL directamente.
- Existe una vulnerabilidad al permitir ataques por fuerza bruta; para evitar esto se debe hacer una implementación que limite el número de intentos de inicio de sesión.
- Se debe implementar una política de contraseñas seguras, que incluyan mayúsculas, minúsculas, números y caracteres especiales.
- Se recomienda el uso de roles y permisos para limitar el acceso a la información sensible.

Ejemplo de código Java con las recomendaciones anteriores:

Esta parte representa la implementación de un ORM para evitar la inyección SQL
``` java
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
}
```
En esta clase se implementa el límite de intentos de sesión; se asume que en la tabla de usuarios existe un campo failedAttempts que nos permite llevar el control de los intentos fallidos, al igual que el campo role, que nos permite limitar el acceso a la información sensible.

``` java
   @Service
public class AuthenticationService {

    private static final int MAX_FAILED_ATTEMPTS = 3;

    @Autowired
    private UserRepository userRepository;

    public User authenticateUser(String username, String password) {
        User user = userRepository.findByUsername(username);

        if (user != null) {
            if (user.getFailedAttempts() >= MAX_FAILED_ATTEMPTS) {
                System.out.println("User account locked due to too many failed attempts.");
                return null;
            }

            if (user.verifyPassword(password)) {
                user.resetFailedAttempts();
                userRepository.save(user); 
                return user;
            } else {
                user.incrementFailedAttempts();
                userRepository.save(user); 
            }
        }
        return null;
    }

    public boolean authorizeUser(User user, User.Role requiredRole) {
        if (user.getRole() == requiredRole) {
            return true;
        } else {
            System.out.println("User does not have the required permissions.");
            return false;
        }
    }
}
```
Código de la clase que implementa la autenticación de usuario

``` java
    public String login(@RequestParam String username, @RequestParam String password, @RequestParam String role) {
        User.Role requiredRole;
        
        try {
            requiredRole = User.Role.valueOf(role.toUpperCase());
        } catch (IllegalArgumentException e) {
            return "Invalid role specified";
        }

        User user = authenticationService.authenticateUser(username, password);

        if (user == null) {
            return "Login failed. Please check your username and password.";
        }

        if (authenticationService.authorizeUser(user, requiredRole)) {
            return "Welcome, " + user.getUsername() + "! You have " + user.getRole() + " access.";
        } else {
            return "Access denied. Insufficient permissions.";
        }
    }
    
   
```

## Caso 2

``` python
DEFINE FUNCTION generateJWT(userCredentials):
IF validateCredentials(userCredentials):
SET tokenExpiration = currentTime + 3600 // Token expires in one hour
RETURN encrypt(userCredentials + tokenExpiration, secretKey)
ELSE:
RETURN error
```

### Analisis de problemas de seguridad SAST

- userCredentials es un dato sesible que no deberia ir en el payload del jwt ya que esto solo se envia en base 64.
- El uso de una clave secreta (secretKey) puede ser vulnerable si no se maneja correctamente. Usar una clave robusta y bien protegida es esencial.
- Ya que jwt e un estandar se debe seguir la estructura (header, payload, signature)
- Se debe incluir la expiración y considerar métodos para la revocación de tokens.
- Los errores no deben revelar información sensible.

### Analisis de problemas de seguridad DAST

- En lugar de generar y firmar manualmente el JWT, usa una biblioteca estándar que siga las mejores prácticas de seguridad. Ejemplo: java-jwt en Java.
- La clave secreta debe ser fuerte y mantenerse segura (por ejemplo, en un almacén de secretos).
- El payload debe incluir solo la información mínima y necesaria, como el ID del usuario y el rol, evitando datos sensibles.
- Los errores no deben revelar información sensible.

Ejemplo de código Java con las recomendaciones anteriores:

``` java
public static DecodedJWT verifyJWT(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer("your-app")
                    .build();

            DecodedJWT jwt = verifier.verify(token);

            String role = jwt.getClaim("role").asString();
            if (role == null || (!role.equals("admin") && !role.equals("user"))) {
                throw new JWTVerificationException("Invalid role");
            }

            return jwt;

        } catch (JWTVerificationException exception) {
            System.out.println("Invalid JWT: " + exception.getMessage());
            return null;
        } catch (JWTDecodeException exception) {
            System.out.println("Error decoding JWT: " + exception.getMessage());
            return null;
        }
    }
```
## Caso 3
    
``` python
PLAN secureDataCommunication:
IMPLEMENT SSL/TLS for all data in transit
USE encrypted storage solutions for data at rest
ENSURE all data exchanges comply with HTTPS protocols
```

### Analisis de problemas de seguridad SAST

- Se debe verificar que el certificado SSL/TLS esté emitido por una autoridad de certificación confiable (CA) y que no esté autofirmado (esto es inseguro en entornos de producción).
- Asegurarse de que la implementación use TLS 1.2 o superior. Las versiones anteriores, como TLS 1.0 y 1.1, y SSL, están obsoletas y tienen vulnerabilidades de seguridad conocidas.
- Revisar el código y la configuración del servidor para deshabilitar cifrados débiles, como DES, RC4 y MD5, y permite solo cifrados fuertes como AES256.

### Analisis de problemas de seguridad DAST

- Usar una herramienta DAST como SSL Labs o OWASP ZAP para escanear el servidor en busca de problemas SSL/TLS.
- Intentar acceder a la aplicación usando HTTP para verificar que todas las rutas redirigen a HTTPS.
- Asegúrarse de que el encabezado HSTS esté presente en las respuestas HTTP y verifica su configuración.
- Simular un ataque MITM para verificar que el cifrado TLS/SSL esté funcionando correctamente y que el servidor rechace cualquier intento de conexión sin un certificado válido.
- Verificar que los datos almacenados en la base de datos y archivos sensibles estén encriptados correctamente.