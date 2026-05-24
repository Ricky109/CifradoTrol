package com.example.trolonciobot.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;

/**
 * Calcula y verifica el HMAC-SHA256 de los mensajes cifrados.
 * Garantiza que el mensaje no fue alterado en tránsito.
 */
public class HMACHelper {

    private static final String ALGORITMO = "HmacSHA256";

    /**
     * Calcula el HMAC-SHA256 de los datos usando la clave AES de sesión.
     * Devuelve siempre 32 bytes.
     */
    public static byte[] calcular(byte[] datos, byte[] clave) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(clave, ALGORITMO);
        Mac mac = Mac.getInstance(ALGORITMO);
        mac.init(keySpec);
        return mac.doFinal(datos);
    }

    /**
     * Verifica que el HMAC recibido coincide con el calculado.
     * Usa comparación en tiempo constante para evitar timing attacks:
     * un atacante no puede medir cuántos bytes coinciden antes de fallar.
     *
     * @throws SecurityException si el mensaje fue alterado o la clave es incorrecta
     */
    public static void verificar(byte[] datos, byte[] clave, byte[] hmacEsperado) throws Exception {
        byte[] hmacCalculado = calcular(datos, clave);

        // MessageDigest.isEqual compara todos los bytes siempre,
        // sin cortocircuito, independientemente de dónde difieren
        if (!MessageDigest.isEqual(hmacCalculado, hmacEsperado)) {
            throw new SecurityException("HMAC inválido: el mensaje fue alterado o la clave es incorrecta.");
        }
    }
}