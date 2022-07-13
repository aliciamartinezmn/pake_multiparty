# PAKE multiparte

## Implementación en Python de un protocolo PAKE para varios usuarios
Esta implementación está realizada en Python y permite realizar un intercambio de claves con autenticación basada en contraseña (PAKE) para un grupo de varios usuarios. Está basada en PakeMail [^1], SPAKE2 [^2] y un compilador propuesto por Abdalla et al. [^3] que permite pasar de un protocolo PAKE bipartito a uno multipartito.
### Requisitos para ejecutar el código:
- **Python 3.6**.
- Es necesario instalar los paquetes **spake2**, **pyyaml**, **python-gnupg**, **pynacl**.
SPAKE2 [^4] se puede instalar mediante el comando `pip install spake2`.
- Es necesario tener en el mismo directorio el código de **PakeMail** [^5] y del **Commitment Scheme** [^6].
### Instrucciones de uso
Al ejecutar el fichero, se muestra un menú con dos opciones. Se debe introducir por teclado el número correspondiente a la opción deseada. La primera opción realiza un intercambio de claves para 3 usuarios, mientras que la segunda opción realiza el intercambio para el número de usuarios que se introduzca por teclado. 
### Referencias
[^1] Itzel Vazquez Sandoval, Arash Atashpendar, Gabriele Lenzini, and Peter YA Ryan. PakeMail: authentication and key management in decentralized secure email and messaging via PAKE. *arXiv preprint arXiv:2107.06090*, 2021.
[^2] Michel Abdalla and Manuel Barbosa. Perfect forward security of SPAKE2. PhD thesis, IACR Cryptology ePrint Archive, 2019.
[^3] Michel Abdalla, Jens-Matthias Bohli, Maria Isabel Gonzalez Vasco, and Rainer Steinwandt. (Password) authenticated key establishment: from 2-party to group. In Theory of Cryptography Conference, pages 499–514. Springer, 2007.
[^4] Brian Warner. Spake2. Github, 2018. https://github.com/warner/python-spake2. (Visitado 20-06-2022).
[^5] CryptographySandbox. Pakemail. Github, 2020. https://github.com/CryptographySandbox/PakeMail. (Visitado 20-06-2022).
[^6] Raphael Coelho. Commitment scheme. Github, 2017. https://github.com/raphaelrrcoelho/commitment-scheme. (Visitado 20-06-2022).
