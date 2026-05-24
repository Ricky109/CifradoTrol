package com.example.trolonciobot.crypto;

import java.util.Base64;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

/**
 * Orquestador del sistema HybridCrypt.
 *
 * Coordina las tres capas de cifrado en el orden correcto:
 *
 *   CIFRAR:   texto → AES → ThirdLayer → HMAC → Base64
 *   DESCIFRAR: Base64 → verificar HMAC → ThirdLayer⁻¹ → AES⁻¹ → texto
 *
 * El paquete final tiene esta estructura:
 *   [ HMAC (32 bytes) | timestamp (8 bytes) | ciphertext ]
 *
 * El timestamp viaja junto al mensaje porque ThirdLayer lo necesita
 * para reconstruir Clave_L3 y descifrar correctamente.
 *
 * RSA se usa aparte, solo para el intercambio inicial de la clave AES.
 */
public class HybridCrypt {

    private static final int HMAC_SIZE      = 32; // bytes — SHA-256 siempre produce 32
    private static final int TIMESTAMP_SIZE =  8; // bytes — long de Java = 8 bytes
    private static final int HEADER_SIZE    = HMAC_SIZE + TIMESTAMP_SIZE; // 40 bytes

    // ──────────────────────────────────────────────────────────
    //  CIFRADO DE MENSAJES
    // ──────────────────────────────────────────────────────────

    /**
     * Cifra un mensaje de texto y devuelve el resultado en Base64.
     *
     * El resultado puede pegarse directamente en cualquier app de chat.
     * Soporta cualquier texto UTF-8: letras, ñ, tildes, emojis, etc.
     *
     * @param texto    Mensaje en texto plano
     * @param claveAES Clave de sesión de 32 bytes
     * @return         String en Base64 listo para enviar
     */
    public static String cifrar(String texto, byte[] claveAES) throws Exception {
        // 1. Convertir texto a bytes UTF-8
        byte[] textBytes = texto.getBytes("UTF-8");

        // 2. Capturar el timestamp de este momento
        long timestamp = System.currentTimeMillis();

        // 3. Cifrar con AES-256 (con S-Box dinámica derivada de claveAES)
        AESModified aes = new AESModified(claveAES);
        byte[] cifradoAES = aes.cifrar(textBytes);

        // 4. Aplicar la tercera capa (confusión dinámica con claveAES + timestamp)
        byte[] cifradoL3 = ThirdLayer.cifrar(cifradoAES, claveAES, timestamp);

        // 5. Calcular HMAC del ciphertext final para garantizar integridad
        byte[] hmac = HMACHelper.calcular(cifradoL3, claveAES);

        // 6. Ensamblar el paquete: HMAC | timestamp | ciphertext
        byte[] paquete = ensamblarPaquete(hmac, timestamp, cifradoL3);

        return Base64.getEncoder().encodeToString(paquete);
    }

    // ──────────────────────────────────────────────────────────
    //  DESCIFRADO DE MENSAJES
    // ──────────────────────────────────────────────────────────

    /**
     * Descifra un mensaje en Base64 y devuelve el texto original.
     *
     * Verifica el HMAC antes de descifrar. Si el mensaje fue alterado
     * en tránsito o la clave es incorrecta, lanza SecurityException.
     *
     * @param base64   Mensaje cifrado en Base64
     * @param claveAES Clave de sesión de 32 bytes
     * @return         Texto original descifrado
     */
    public static String descifrar(String base64, byte[] claveAES) throws Exception {
        // 1. Decodificar Base64
        byte[] paquete = Base64.getDecoder().decode(base64);

        if (paquete.length < HEADER_SIZE) {
            throw new IllegalArgumentException("Paquete demasiado corto para ser válido.");
        }

        // 2. Separar los componentes del paquete
        byte[] hmacRecibido = extraerHMAC(paquete);
        long   timestamp    = extraerTimestamp(paquete);
        byte[] cifradoL3    = extraerCiphertext(paquete);

        // 3. Verificar HMAC — lanza SecurityException si no coincide
        HMACHelper.verificar(cifradoL3, claveAES, hmacRecibido);

        // 4. Revertir la tercera capa (necesita el mismo timestamp del cifrado)
        AESModified aes = new AESModified(claveAES);
        byte[] cifradoAES = ThirdLayer.descifrar(cifradoL3, claveAES, timestamp);

        // 5. Descifrar AES y recuperar los bytes originales
        byte[] textBytes = aes.descifrar(cifradoAES);

        // 6. Convertir bytes a String UTF-8
        return new String(textBytes, "UTF-8");
    }

    // ──────────────────────────────────────────────────────────
    //  INTERCAMBIO DE CLAVE AES VÍA RSA
    // ──────────────────────────────────────────────────────────

    /**
     * Genera una clave AES-256 aleatoria y criptográficamente segura.
     * Se llama una vez por sesión. El resultado se cifra con RSA y se envía
     * al contacto como primer mensaje especial (prefijo "KEY:").
     */
    public static byte[] generarClaveAES() {
        byte[] clave = new byte[32];
        new SecureRandom().nextBytes(clave);
        return clave;
    }

    /**
     * Cifra la clave AES con la clave pública RSA del contacto.
     * El resultado va como primer mensaje de la sesión con prefijo "KEY:".
     */
    public static String cifrarClaveAES(byte[] claveAES, BigInteger n, BigInteger e) {
        byte[] cifrado = RSAManager.cifrar(claveAES, n, e);
        return "KEY:" + Base64.getEncoder().encodeToString(cifrado);
    }

    /**
     * Descifra la clave AES recibida usando la clave privada RSA propia.
     * Se llama cuando llega un mensaje con prefijo "KEY:".
     */
    public static byte[] descifrarClaveAES(String mensajeKey, BigInteger n, BigInteger d) {
        String base64 = mensajeKey.substring(4); // quitar el prefijo "KEY:"
        byte[] cifrado = Base64.getDecoder().decode(base64);
        return RSAManager.descifrar(cifrado, n, d);
    }

    /**
     * Verifica si un mensaje es un intercambio de clave RSA.
     */
    public static boolean esMensajeDeClave(String mensaje) {
        return mensaje != null && mensaje.startsWith("KEY:");
    }

    // ──────────────────────────────────────────────────────────
    //  ENSAMBLADO Y DESGLOSE DEL PAQUETE
    // ──────────────────────────────────────────────────────────

    // Estructura: [ hmac (32) | timestamp (8) | ciphertext (variable) ]
    private static byte[] ensamblarPaquete(byte[] hmac, long timestamp, byte[] ciphertext) {
        byte[] paquete = new byte[HEADER_SIZE + ciphertext.length];
        System.arraycopy(hmac, 0, paquete, 0, HMAC_SIZE);
        byte[] tsBytes = ByteBuffer.allocate(8).putLong(timestamp).array();
        System.arraycopy(tsBytes, 0, paquete, HMAC_SIZE, TIMESTAMP_SIZE);
        System.arraycopy(ciphertext, 0, paquete, HEADER_SIZE, ciphertext.length);
        return paquete;
    }

    private static byte[] extraerHMAC(byte[] paquete) {
        byte[] hmac = new byte[HMAC_SIZE];
        System.arraycopy(paquete, 0, hmac, 0, HMAC_SIZE);
        return hmac;
    }

    private static long extraerTimestamp(byte[] paquete) {
        return ByteBuffer.wrap(paquete, HMAC_SIZE, TIMESTAMP_SIZE).getLong();
    }

    private static byte[] extraerCiphertext(byte[] paquete) {
        int longitud = paquete.length - HEADER_SIZE;
        byte[] ct = new byte[longitud];
        System.arraycopy(paquete, HEADER_SIZE, ct, 0, longitud);
        return ct;
    }
}
