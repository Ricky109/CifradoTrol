package com.example.trolonciobot.crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * RSA-2048 implementado desde cero con una modificación:
 * el exponente público e se deriva de un PIN compartido entre los usuarios
 * en lugar del valor estándar fijo 65537.
 *
 * Esto añade un factor secreto adicional: aunque alguien obtenga la clave
 * pública (n), sin conocer el PIN no puede calcular el e correcto y por
 * tanto no puede cifrar mensajes para ese receptor.
 *
 * Uso en el proyecto:
 *   - Se ejecuta UNA SOLA VEZ por sesión para intercambiar la clave AES.
 *   - El receptor genera el par de claves y comparte la pública por QR.
 *   - El emisor cifra la clave AES con la clave pública del receptor.
 *   - El receptor descifra con su clave privada y obtiene la clave AES.
 *   - A partir de ahí, todo el cifrado usa AES (más rápido).
 */
public class RSAManager {

    private static final int  BITS_PRIMO   = 1024; // p y q de 1024 bits → n de 2048 bits
    private static final int  CERTEZA      = 50;   // probabilidad de error < 2^-100
    private static final long E_MINIMO     = 65537L;

    // Par de claves (se generan juntas, se almacenan por separado)
    public static class ParClaves {
        public final BigInteger n;  // módulo — público
        public final BigInteger e;  // exponente público
        public final BigInteger d;  // exponente privado — nunca sale del dispositivo
        public ParClaves(BigInteger n, BigInteger e, BigInteger d) {
            this.n = n; this.e = e; this.d = d;
        }
    }

    // ──────────────────────────────────────────────────────────
    //  GENERACIÓN DE CLAVES
    // ──────────────────────────────────────────────────────────

    /**
     * Genera el par de claves RSA-2048 con exponente derivado del PIN.
     *
     * Pasos:
     *   1. Generar primos p y q de 1024 bits cada uno
     *   2. n = p × q
     *   3. φ(n) = (p-1) × (q-1)
     *   4. e = derivado del PIN (primer primo > hash(PIN) coprimo con φ(n))
     *   5. d = inverso modular de e respecto a φ(n)  [algoritmo de Euclides extendido]
     *   6. Descartar p, q, φ(n) — solo quedan (n,e) y (n,d)
     */
    public static ParClaves generarParClaves(String pin) throws Exception {
        SecureRandom random = new SecureRandom();

        // Generar p y q distintos
        BigInteger p, q;
        do {
            p = BigInteger.probablePrime(BITS_PRIMO, random);
            q = BigInteger.probablePrime(BITS_PRIMO, random);
        } while (p.equals(q));

        BigInteger n   = p.multiply(q);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        BigInteger e = derivarExponente(pin, phi);
        BigInteger d = inversoModular(e, phi);

        // p, q y phi se descartan aquí — solo sobreviven n, e, d
        return new ParClaves(n, e, d);
    }

    // ──────────────────────────────────────────────────────────
    //  DERIVACIÓN DEL EXPONENTE DESDE EL PIN
    // ──────────────────────────────────────────────────────────

    /**
     * Deriva el exponente público e a partir del PIN.
     *
     * Proceso:
     *   1. Calcular SHA-256 del PIN
     *   2. Tomar los primeros 8 bytes del hash como número semilla
     *   3. Si la semilla es menor que E_MINIMO, usar E_MINIMO como punto de partida
     *   4. Buscar el siguiente número impar primo que sea coprimo con φ(n)
     *
     * La condición mcd(e, φ(n)) = 1 es obligatoria para que exista el inverso
     * modular d. Sin ella, el descifrado es matemáticamente imposible.
     */
    private static BigInteger derivarExponente(String pin, BigInteger phi) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(pin.getBytes("UTF-8"));

        // Usar los primeros 8 bytes del hash como semilla para e
        BigInteger candidato = new BigInteger(1, Arrays.copyOf(hash, 8));

        // Garantizar que el candidato esté por encima del mínimo seguro
        if (candidato.compareTo(BigInteger.valueOf(E_MINIMO)) < 0) {
            candidato = BigInteger.valueOf(E_MINIMO);
        }

        // e debe ser impar (los primos pares > 2 no existen)
        if (candidato.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
            candidato = candidato.add(BigInteger.ONE);
        }

        // Buscar el primer primo coprimo con φ(n) a partir del candidato
        while (!esPrimoProbable(candidato) || !candidato.gcd(phi).equals(BigInteger.ONE)) {
            candidato = candidato.add(BigInteger.TWO);
        }

        return candidato;
    }

    // Test de primalidad probabilístico — error < 2^-100 con CERTEZA=50 iteraciones
    private static boolean esPrimoProbable(BigInteger n) {
        return n.isProbablePrime(CERTEZA);
    }

    // ──────────────────────────────────────────────────────────
    //  ALGORITMO EXTENDIDO DE EUCLIDES — cálculo del inverso modular
    // ──────────────────────────────────────────────────────────

    /**
     * Calcula el inverso modular de e respecto a m.
     * Es decir, encuentra d tal que: e × d ≡ 1 (mod m)
     *
     * Usa el algoritmo extendido de Euclides implementado de forma iterativa.
     *
     * Fundamento: si mcd(e, m) = 1, existen x, y enteros tales que
     *   e×x + m×y = 1  →  e×x ≡ 1 (mod m)  →  x es el inverso de e
     */
    private static BigInteger inversoModular(BigInteger e, BigInteger m) throws Exception {
        BigInteger viejo_r = e,  r = m;
        BigInteger viejo_s = BigInteger.ONE, s = BigInteger.ZERO;

        while (!r.equals(BigInteger.ZERO)) {
            BigInteger cociente = viejo_r.divide(r);

            BigInteger tmp_r = r;
            r = viejo_r.subtract(cociente.multiply(r));
            viejo_r = tmp_r;

            BigInteger tmp_s = s;
            s = viejo_s.subtract(cociente.multiply(s));
            viejo_s = tmp_s;
        }

        // viejo_r es el mcd; si no es 1, el inverso no existe
        if (!viejo_r.equals(BigInteger.ONE)) {
            throw new Exception("No existe inverso modular: mcd(e, φ(n)) ≠ 1");
        }

        // viejo_s puede ser negativo; lo llevamos al rango [0, m)
        return viejo_s.mod(m);
    }

    // ──────────────────────────────────────────────────────────
    //  CIFRADO Y DESCIFRADO
    // ──────────────────────────────────────────────────────────

    /**
     * Cifra datos usando la clave pública (n, e).
     * En el proyecto se usa para cifrar la clave AES de 32 bytes.
     * C = M^e mod n
     */
    public static byte[] cifrar(byte[] datos, BigInteger n, BigInteger e) {
        BigInteger M = new BigInteger(1, datos);  // 1 = positivo siempre
        BigInteger C = M.modPow(e, n);
        return bigIntegerABytes(C, n);
    }

    /**
     * Descifra usando la clave privada (n, d).
     * M = C^d mod n
     */
    public static byte[] descifrar(byte[] datosCifrados, BigInteger n, BigInteger d) {
        BigInteger C = new BigInteger(1, datosCifrados);
        BigInteger M = C.modPow(d, n);
        // Recuperar exactamente 32 bytes (tamaño de la clave AES)
        byte[] resultado = M.toByteArray();
        return normalizarA32Bytes(resultado);
    }

    // ──────────────────────────────────────────────────────────
    //  SERIALIZACIÓN — para almacenamiento y QR
    // ──────────────────────────────────────────────────────────

    /**
     * Serializa la clave pública (n, e) a String Base64 para el QR.
     * Formato: Base64(longitud_n [4 bytes] | bytes_n | bytes_e)
     */
    public static String clavePublicaAString(BigInteger n, BigInteger e) {
        byte[] bytesN = n.toByteArray();
        byte[] bytesE = e.toByteArray();

        byte[] buffer = new byte[4 + bytesN.length + bytesE.length];
        // Guardar longitud de n en los primeros 4 bytes para separar n de e al leer
        buffer[0] = (byte)(bytesN.length >> 24);
        buffer[1] = (byte)(bytesN.length >> 16);
        buffer[2] = (byte)(bytesN.length >>  8);
        buffer[3] = (byte)(bytesN.length);
        System.arraycopy(bytesN, 0, buffer, 4, bytesN.length);
        System.arraycopy(bytesE, 0, buffer, 4 + bytesN.length, bytesE.length);

        return java.util.Base64.getEncoder().encodeToString(buffer);
    }

    /**
     * Reconstruye (n, e) desde el String Base64 del QR.
     * Devuelve un array de dos BigInteger: [n, e]
     */
    public static BigInteger[] stringAClavePublica(String base64) {
        byte[] buffer = java.util.Base64.getDecoder().decode(base64);

        int longN = ((buffer[0] & 0xFF) << 24)
                | ((buffer[1] & 0xFF) << 16)
                | ((buffer[2] & 0xFF) <<  8)
                |  (buffer[3] & 0xFF);

        byte[] bytesN = Arrays.copyOfRange(buffer, 4, 4 + longN);
        byte[] bytesE = Arrays.copyOfRange(buffer, 4 + longN, buffer.length);

        return new BigInteger[]{ new BigInteger(bytesN), new BigInteger(bytesE) };
    }

    /**
     * Serializa la clave privada d a String Base64 para guardar en el dispositivo.
     */
    public static String clavePrivadaAString(BigInteger d) {
        return java.util.Base64.getEncoder().encodeToString(d.toByteArray());
    }

    public static BigInteger stringAClavePrivada(String base64) {
        return new BigInteger(java.util.Base64.getDecoder().decode(base64));
    }

    public static String moduloAString(BigInteger n) {
        return java.util.Base64.getEncoder().encodeToString(n.toByteArray());
    }

    public static BigInteger stringAModulo(String base64) {
        return new BigInteger(java.util.Base64.getDecoder().decode(base64));
    }

    // ──────────────────────────────────────────────────────────
    //  UTILIDADES
    // ──────────────────────────────────────────────────────────

    /**
     * Convierte un BigInteger a bytes con longitud fija igual al tamaño de n.
     * BigInteger.toByteArray() puede añadir un byte 0x00 al inicio (signo positivo).
     * Aquí garantizamos que la longitud sea siempre la misma para facilitar
     * el descifrado en el otro extremo.
     */
    private static byte[] bigIntegerABytes(BigInteger valor, BigInteger n) {
        int longitud  = (n.bitLength() + 7) / 8; // longitud en bytes del módulo
        byte[] bytes  = valor.toByteArray();

        if (bytes.length == longitud) return bytes;

        byte[] resultado = new byte[longitud];
        if (bytes.length > longitud) {
            // Quitar byte de signo si sobra
            System.arraycopy(bytes, bytes.length - longitud, resultado, 0, longitud);
        } else {
            // Rellenar con ceros a la izquierda si falta
            System.arraycopy(bytes, 0, resultado, longitud - bytes.length, bytes.length);
        }
        return resultado;
    }

    /**
     * Normaliza el resultado del descifrado a exactamente 32 bytes (clave AES-256).
     * Maneja el byte de signo que BigInteger puede añadir o quitar.
     */
    private static byte[] normalizarA32Bytes(byte[] bytes) {
        if (bytes.length == 32) return bytes;

        byte[] resultado = new byte[32];
        if (bytes.length > 32) {
            System.arraycopy(bytes, bytes.length - 32, resultado, 0, 32);
        } else {
            System.arraycopy(bytes, 0, resultado, 32 - bytes.length, bytes.length);
        }
        return resultado;
    }
}
