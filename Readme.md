ssh_data docs
Esta es una biblioteca Ruby para procesar claves y certificados SSH.

El alcance de este proyecto se limita al procesamiento y uso directo de claves y certificados. Puede usarse para generar claves privadas SSH, verificar firmas usando claves públicas, firmar datos usando claves privadas, emitir certificados usando claves privadas y analizar certificados y claves públicas y privadas. Esta biblioteca admite claves RSA, DSA, ECDSA y ED25519 * . Esta biblioteca no ofrece ni tiene la intención de ofrecer funcionalidad para la conectividad SSH, el procesamiento de datos de protocolo de cable SSH o el procesamiento de otros formatos o tipos de claves.

Estado del proyecto: utilizado por @github en producción

Instalación
gem install ssh_data
Uso
requiere  "ssh_data"

key_data  =  Archivo . read ( "~ / .ssh / id_rsa.pub" ) 
clave  =  SSHData :: PublicKey . parse_openssh ( key_data ) 
# => <SSHData :: PublicKey :: RSA>

cert_data  =  =  Archivo . read ( "~ / .ssh / id_rsa-cert.pub" ) 
cert  =  SSHData :: Certificate . parse_openssh ( cert_data ) 
# => <SSHData :: PublicKey :: Certificado>

cert . key_id 
# => "mastahyeti"

cert . public_key 
# => <SSHData :: PublicKey :: RSA>
Soporte ED25519
La biblioteca estándar de Ruby no incluye soporte para ED25519, aunque el algoritmo es implementado por ed25519Gem . Esta biblioteca puede analizar las claves públicas y privadas de ED25519 por sí misma, pero para generar claves o firmar o verificar mensajes, la aplicación que realiza la llamada debe cargar la ed25519propia Gema. Esto evita la necesidad de instalar o cargar esta dependencia de terceros cuando la aplicación que realiza la llamada solo está interesada en analizar claves.

requiere  "ssh_data"

key_data  =  Archivo . read ( "~ / .ssh / id_ed25519" ) 
clave  =  SSHData :: PrivateKey . parse_openssh ( key_data ) 
# => <SSHData :: PrivateKey :: ED25519>

SSHData :: PrivateKey :: ED25519 . generate 
# => aumenta SSHData :: AlgorithmError

requiere  "ed25519"

SSHData :: PrivateKey :: ED25519 . generar 
# => <SSHData :: PrivateKey :: ED25519>
Contribuciones
Actualmente, este proyecto no busca contribuciones para nuevas características o funcionalidades, aunque las correcciones de errores son bienvenidas. Consulte CONTRIBUTING.md para obtener más información.

Licencia
Este proyecto está publicado bajo la licencia MIT. Consulte LICENSE.md para obtener más información.
