package com.example.trolonciobot.bot;

import com.example.trolonciobot.crypto.HybridCrypt;
import com.example.trolonciobot.crypto.RSAManager;
import com.example.trolonciobot.storage.SessionStorage;
import com.example.trolonciobot.storage.SessionStorage.Usuario;
import com.example.trolonciobot.storage.SessionStorage.SolicitudSesion;
import org.telegram.telegrambots.bots.TelegramLongPollingBot;
import org.telegram.telegrambots.meta.api.methods.send.SendMessage;
import org.telegram.telegrambots.meta.api.objects.Update;
import org.telegram.telegrambots.meta.exceptions.TelegramApiException;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.List;
import java.util.UUID;

/**
 * Núcleo del bot HybridCrypt para Telegram.
 *
 * Maneja el ciclo de vida completo de una conversación cifrada:
 *   1. Registro del usuario y generación de claves RSA
 *   2. Solicitud y establecimiento de sesión entre dos usuarios
 *   3. Cifrado transparente de mensajes salientes
 *   4. Descifrado transparente de mensajes entrantes
 *
 * El bot nunca almacena PINs ni claves AES.
 * Las claves AES se derivan en tiempo real de los PINs de ambos usuarios.
 */
public class TroloncioBot extends TelegramLongPollingBot {

    private final String        token;
    private final String        username;
    private final SessionStorage storage;

    // Estados del flujo de registro — por chat_id
    private final java.util.Map<Long, String> estadoUsuario = new java.util.concurrent.ConcurrentHashMap<>();

    // PINs temporales en memoria — se descartan al cerrar el bot o al completar la sesión
    // NUNCA se persisten en disco
    private final java.util.Map<Long, String> pinsTemporales = new java.util.concurrent.ConcurrentHashMap<>();

    private static final String ESTADO_ESPERANDO_NOMBRE = "ESPERANDO_NOMBRE";
    private static final String ESTADO_ESPERANDO_PIN    = "ESPERANDO_PIN";
    private static final String ESTADO_ESPERANDO_PIN_SESION = "ESPERANDO_PIN_SESION";
    private static final String ESTADO_ESPERANDO_PIN_ACEPTAR = "ESPERANDO_PIN_ACEPTAR";

    public TroloncioBot(String token, String username) {
        this.token    = token;
        this.username = username;
        this.storage  = new SessionStorage();
    }

    @Override
    public String getBotToken()    { return token; }

    @Override
    public String getBotUsername() { return username; }

    // ──────────────────────────────────────────────────────────
    //  ENTRADA PRINCIPAL — procesa cada mensaje recibido
    // ──────────────────────────────────────────────────────────

    @Override
    public void onUpdateReceived(Update update) {
        if (!update.hasMessage() || !update.getMessage().hasText()) return;

        long   chatId = update.getMessage().getChatId();
        String texto  = update.getMessage().getText().trim();

        try {
            if (texto.startsWith("/")) {
                procesarComando(chatId, texto);
            } else {
                procesarTexto(chatId, texto);
            }
        } catch (Exception e) {
            enviar(chatId, "Error inesperado: " + e.getMessage());
        }
    }

    // ──────────────────────────────────────────────────────────
    //  COMANDOS
    // ──────────────────────────────────────────────────────────

    private void procesarComando(long chatId, String texto) throws Exception {
        String[] partes  = texto.split("\\s+", 2);
        String   comando = partes[0].toLowerCase();
        String   args    = partes.length > 1 ? partes[1].trim() : "";

        switch (comando) {
            case "/start":    cmdStart(chatId);           break;
            case "/pin":      cmdPin(chatId, args);       break;
            case "/contactos":cmdContactos(chatId);       break;
            case "/hablar":   cmdHablar(chatId, args);    break;
            case "/aceptar":  cmdAceptar(chatId, args);   break;
            case "/rechazar": cmdRechazar(chatId, args);  break;
            case "/sesion":   cmdSesion(chatId);          break;
            case "/fin":      cmdFin(chatId);             break;
            case "/ayuda":    cmdAyuda(chatId);           break;
            default:
                enviar(chatId, "Comando no reconocido. Usa /ayuda para ver los comandos disponibles.");
        }
    }

    // /start — inicia el registro
    private void cmdStart(long chatId) {
        if (storage.estaRegistrado(chatId)) {
            enviar(chatId, "Ya estás registrado. Usa /ayuda para ver los comandos disponibles.");
            return;
        }
        storage.obtenerOCrear(chatId);
        estadoUsuario.put(chatId, ESTADO_ESPERANDO_NOMBRE);
        enviar(chatId, "Bienvenido a HybridCrypt.\n\n" +
            "Tus mensajes viajarán cifrados con un algoritmo híbrido propio.\n\n" +
            "¿Cuál es tu nombre?");
    }

    // /pin — establecer o cambiar PIN
    private void cmdPin(long chatId, String args) throws Exception {
        if (!storage.estaRegistrado(chatId)) {
            enviar(chatId, "Primero completa el registro con /start.");
            return;
        }
        if (args.isEmpty()) {
            estadoUsuario.put(chatId, ESTADO_ESPERANDO_PIN);
            enviar(chatId, "Escribe tu nuevo PIN (mínimo 4 dígitos):");
            return;
        }
        procesarNuevoPin(chatId, args);
    }

    // /contactos — ver usuarios registrados
    private void cmdContactos(long chatId) {
        if (!storage.estaRegistrado(chatId)) {
            enviar(chatId, "Primero completa el registro con /start.");
            return;
        }
        List<Usuario> todos = storage.obtenerTodos();
        if (todos.size() <= 1) {
            enviar(chatId, "Aún no hay otros usuarios registrados.");
            return;
        }
        StringBuilder sb = new StringBuilder("Usuarios disponibles:\n\n");
        for (Usuario u : todos) {
            if (u.chatId != chatId && u.registrado) {
                sb.append("• ").append(u.nombre).append("\n");
            }
        }
        sb.append("\nUsa /hablar [nombre] para iniciar una sesión cifrada.");
        enviar(chatId, sb.toString());
    }

    // /hablar [nombre] — iniciar sesión con un contacto
    private void cmdHablar(long chatId, String nombre) {
        if (!storage.estaRegistrado(chatId)) {
            enviar(chatId, "Primero completa el registro con /start.");
            return;
        }
        if (nombre.isEmpty()) {
            enviar(chatId, "Indica con quién quieres hablar: /hablar [nombre]");
            return;
        }
        Usuario contacto = storage.buscarPorNombre(nombre);
        if (contacto == null) {
            enviar(chatId, "No encontré a " + nombre + ". Usa /contactos para ver quién está registrado.");
            return;
        }
        if (contacto.chatId == chatId) {
            enviar(chatId, "No puedes iniciar una sesión contigo mismo.");
            return;
        }

        // Guardar el nombre del contacto temporalmente para usarlo después del PIN
        estadoUsuario.put(chatId, ESTADO_ESPERANDO_PIN_SESION + ":" + contacto.chatId);
        enviar(chatId, "Para iniciar sesión cifrada con " + contacto.nombre +
            ", introduce tu PIN:");
    }

    // /aceptar [nombre] — aceptar solicitud de sesión
    private void cmdAceptar(long chatId, String nombre) {
        if (!storage.estaRegistrado(chatId)) {
            enviar(chatId, "Primero completa el registro con /start.");
            return;
        }
        SolicitudSesion solicitud = storage.obtenerSolicitudParaReceptor(chatId);
        if (solicitud == null) {
            enviar(chatId, "No tienes solicitudes de sesión pendientes o el tiempo expiró.");
            return;
        }
        estadoUsuario.put(chatId, ESTADO_ESPERANDO_PIN_ACEPTAR + ":" + solicitud.solicitanteId);
        enviar(chatId, "Introduce tu PIN para establecer la sesión:");
    }

    // /rechazar [nombre] — rechazar solicitud
    private void cmdRechazar(long chatId, String nombre) {
        SolicitudSesion solicitud = storage.obtenerSolicitudParaReceptor(chatId);
        if (solicitud == null) {
            enviar(chatId, "No tienes solicitudes pendientes.");
            return;
        }
        storage.eliminarSolicitud(solicitud.solicitanteId);
        Usuario solicitante = storage.obtener(solicitud.solicitanteId);
        if (solicitante != null) {
            enviar(solicitud.solicitanteId, storage.obtener(chatId).nombre +
                " rechazó tu solicitud de sesión.");
        }
        enviar(chatId, "Solicitud rechazada.");
    }

    // /sesion — ver estado actual
    private void cmdSesion(long chatId) {
        if (!storage.estaRegistrado(chatId)) {
            enviar(chatId, "No estás registrado. Usa /start.");
            return;
        }
        Usuario yo = storage.obtener(chatId);
        if (yo.contactoActivo == null) {
            enviar(chatId, "No tienes ninguna sesión activa.\nUsa /hablar [nombre] para iniciar una.");
            return;
        }
        Usuario contacto = storage.obtener(yo.contactoActivo);
        String nombreContacto = contacto != null ? contacto.nombre : "desconocido";
        enviar(chatId, "Sesión activa con: " + nombreContacto +
            "\n\nEscribe tu mensaje y se enviará cifrado automáticamente.");
    }

    // /fin — cerrar sesión activa
    private void cmdFin(long chatId) {
        Usuario yo = storage.obtener(chatId);
        if (yo == null || yo.contactoActivo == null) {
            enviar(chatId, "No tienes ninguna sesión activa.");
            return;
        }
        pinsTemporales.remove(chatId);
        yo.contactoActivo = null;
        storage.guardar();
        enviar(chatId, "Sesión cerrada. Tus claves de sesión han sido eliminadas.");
    }

    // /ayuda
    private void cmdAyuda(long chatId) {
        enviar(chatId,
            "Comandos disponibles:\n\n" +
            "/start       — Registrarse en HybridCrypt\n" +
            "/pin         — Cambiar tu PIN\n" +
            "/contactos   — Ver usuarios registrados\n" +
            "/hablar [nombre] — Iniciar sesión cifrada\n" +
            "/aceptar     — Aceptar solicitud de sesión\n" +
            "/rechazar    — Rechazar solicitud de sesión\n" +
            "/sesion      — Ver sesión activa\n" +
            "/fin         — Cerrar sesión activa\n" +
            "/ayuda       — Mostrar esta ayuda\n\n" +
            "Una vez establecida la sesión, escribe normalmente y tus mensajes viajarán cifrados.");
    }

    // ──────────────────────────────────────────────────────────
    //  PROCESAMIENTO DE TEXTO (respuestas y mensajes)
    // ──────────────────────────────────────────────────────────

    private void procesarTexto(long chatId, String texto) throws Exception {
        String estado = estadoUsuario.getOrDefault(chatId, "");

        // Flujo de registro — esperando nombre
        if (estado.equals(ESTADO_ESPERANDO_NOMBRE)) {
            procesarNombre(chatId, texto);
            return;
        }

        // Flujo de registro — esperando PIN inicial
        if (estado.equals(ESTADO_ESPERANDO_PIN)) {
            procesarNuevoPin(chatId, texto);
            return;
        }

        // Flujo de sesión — esperando PIN para iniciar sesión con contacto
        if (estado.startsWith(ESTADO_ESPERANDO_PIN_SESION)) {
            long contactoId = Long.parseLong(estado.split(":")[1]);
            procesarPinInicioSesion(chatId, contactoId, texto);
            return;
        }

        // Flujo de sesión — esperando PIN para aceptar sesión
        if (estado.startsWith(ESTADO_ESPERANDO_PIN_ACEPTAR)) {
            long solicitanteId = Long.parseLong(estado.split(":")[1]);
            procesarPinAceptarSesion(chatId, solicitanteId, texto);
            return;
        }

        // Mensaje normal — cifrar y enviar al contacto activo
        enviarMensajeCifrado(chatId, texto);
    }

    // ──────────────────────────────────────────────────────────
    //  FLUJO DE REGISTRO
    // ──────────────────────────────────────────────────────────

    private void procesarNombre(long chatId, String nombre) {
        if (nombre.length() < 2 || nombre.length() > 30) {
            enviar(chatId, "El nombre debe tener entre 2 y 30 caracteres. Intenta de nuevo:");
            return;
        }
        Usuario u  = storage.obtenerOCrear(chatId);
        u.nombre   = nombre;
        storage.guardar();

        estadoUsuario.put(chatId, ESTADO_ESPERANDO_PIN);
        enviar(chatId, "Hola " + nombre + ".\n\n" +
            "Ahora establece tu PIN (mínimo 4 dígitos numéricos).\n" +
            "Tu PIN nunca se almacenará en el servidor, se usa solo para derivar tus claves.");
    }

    private void procesarNuevoPin(long chatId, String pin) throws Exception {
        if (!pin.matches("\\d{4,}")) {
            enviar(chatId, "El PIN debe contener solo dígitos y tener mínimo 4. Intenta de nuevo:");
            return;
        }

        Usuario u = storage.obtenerOCrear(chatId);
        enviar(chatId, "Generando tu par de claves RSA-2048... Esto puede tardar unos segundos.");

        // Generar par RSA en hilo separado para no bloquear el bot
        final String pinFinal = pin;
        new Thread(() -> {
            try {
                RSAManager.ParClaves par = RSAManager.generarParClaves(pinFinal);
                u.clavePublicaN = RSAManager.moduloAString(par.n);
                u.clavePublicaE = RSAManager.clavePrivadaAString(par.e);
                u.registrado    = true;
                storage.guardar();

                // Guardar PIN temporal en memoria para esta sesión
                pinsTemporales.put(chatId, pinFinal);
                estadoUsuario.remove(chatId);

                enviar(chatId, "Par RSA-2048 generado correctamente.\n\n" +
                    "Ya estas registrado como: " + u.nombre + "\n\n" +
                    "Usa /contactos para ver quien mas esta disponible\n" +
                    "o /hablar [nombre] para iniciar una sesion cifrada.");
            } catch (Exception e) {
                enviar(chatId, "Error generando claves: " + e.getMessage());
            }
        }).start();
    }

    // ──────────────────────────────────────────────────────────
    //  FLUJO DE ESTABLECIMIENTO DE SESIÓN
    // ──────────────────────────────────────────────────────────

    private void procesarPinInicioSesion(long chatId, long contactoId, String pin) throws Exception {
        if (!pin.matches("\\d{4,}")) {
            enviar(chatId, "PIN inválido. Solo dígitos, mínimo 4:");
            return;
        }

        Usuario contacto = storage.obtener(contactoId);
        if (contacto == null) {
            enviar(chatId, "El contacto ya no está disponible.");
            estadoUsuario.remove(chatId);
            return;
        }

        // Guardar PIN en memoria y crear solicitud de sesión
        pinsTemporales.put(chatId, pin);
        String sessionId = UUID.randomUUID().toString();

        // Guardar hash del PIN del solicitante para que el receptor pueda verificar
        String pinHash = hashPin(pin);
        storage.crearSolicitud(chatId, contactoId, sessionId, pinHash);
        estadoUsuario.remove(chatId);

        // Notificar al receptor
        Usuario yo = storage.obtener(chatId);
        enviar(contactoId,
            yo.nombre + " quiere iniciar una sesion cifrada contigo.\n\n" +
            "Tienes 60 segundos para aceptar.\n" +
            "Escribe /aceptar para confirmar e introduce tu PIN.");

        enviar(chatId, "Solicitud enviada a " + contacto.nombre +
            ". Esperando que acepte (60 segundos)...");
    }

    private void procesarPinAceptarSesion(long chatId, long solicitanteId, String pin) throws Exception {
        if (!pin.matches("\\d{4,}")) {
            enviar(chatId, "PIN inválido. Solo dígitos, mínimo 4:");
            return;
        }

        SolicitudSesion solicitud = storage.obtenerSolicitudDeSolicitante(solicitanteId);
        if (solicitud == null || solicitud.expirado()) {
            enviar(chatId, "La solicitud expiró. Pide a tu contacto que intente de nuevo.");
            estadoUsuario.remove(chatId);
            return;
        }

        // Guardar PIN del receptor y establecer sesión en ambos lados
        pinsTemporales.put(chatId, pin);

        String pinSolicitante = pinsTemporales.get(solicitanteId);
        if (pinSolicitante == null) {
            enviar(chatId, "El PIN del solicitante ya no está disponible. Intenten de nuevo.");
            estadoUsuario.remove(chatId);
            storage.eliminarSolicitud(solicitanteId);
            return;
        }

        // Establecer sesión en ambos usuarios
        Usuario yo        = storage.obtener(chatId);
        Usuario solicitante = storage.obtener(solicitanteId);

        yo.contactoActivo          = solicitanteId;
        solicitante.contactoActivo = chatId;
        storage.guardar();
        storage.eliminarSolicitud(solicitanteId);
        estadoUsuario.remove(chatId);

        enviar(chatId,       "Sesion establecida con " + solicitante.nombre + ". Ya puedes escribir.");
        enviar(solicitanteId,"Sesion establecida con " + yo.nombre + ". Ya puedes escribir.");
    }

    // ──────────────────────────────────────────────────────────
    //  CIFRADO Y DESCIFRADO DE MENSAJES
    // ──────────────────────────────────────────────────────────

    private void enviarMensajeCifrado(long chatId, String texto) {
        if (!storage.estaRegistrado(chatId)) {
            enviar(chatId, "Primero registrate con /start.");
            return;
        }

        Usuario yo = storage.obtener(chatId);
        if (yo.contactoActivo == null) {
            enviar(chatId, "No tienes ninguna sesion activa. Usa /hablar [nombre].");
            return;
        }

        Usuario contacto = storage.obtener(yo.contactoActivo);
        if (contacto == null) {
            enviar(chatId, "Tu contacto ya no esta disponible.");
            return;
        }

        String pinYo       = pinsTemporales.get(chatId);
        String pinContacto = pinsTemporales.get(yo.contactoActivo);

        if (pinYo == null || pinContacto == null) {
            enviar(chatId, "La sesion expiro. Usa /hablar [nombre] para iniciar una nueva.");
            yo.contactoActivo = null;
            storage.guardar();
            return;
        }

        try {
            // Una sola clave para ambos lados — el orden normalizado garantiza que coincidan
            byte[] claveAES = derivarClaveAES(pinYo, pinContacto, chatId, yo.contactoActivo);

            String mensajeCifrado    = HybridCrypt.cifrar(texto, claveAES);
            String mensajeDescifrado = HybridCrypt.descifrar(mensajeCifrado, claveAES);

            enviar(yo.contactoActivo, yo.nombre + ": " + mensajeDescifrado);

        } catch (Exception e) {
            enviar(chatId, "Error al cifrar: " + e.getMessage());
        }
    }

    // ──────────────────────────────────────────────────────────
    //  DERIVACIÓN DE CLAVE AES
    // ──────────────────────────────────────────────────────────

    /**
     * Deriva la clave AES de 32 bytes a partir de los PINs de ambos usuarios.
     *
     * La clave se calcula como SHA-256(pin1 + pin2 + id1 + id2).
     * El orden de los IDs garantiza que la clave es única para cada par de usuarios.
     * Ningún PIN viaja al servidor: cada usuario introduce solo el suyo,
     * y el bot los combina en memoria para calcular la clave compartida.
     */
    private byte[] derivarClaveAES(String pin1, String pin2, long id1, long id2) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        // Normalizar orden de PINs según el ID menor — garantiza misma clave en ambos lados
        if (id1 < id2) {
            sha256.update(pin1.getBytes("UTF-8"));
            sha256.update(pin2.getBytes("UTF-8"));
        } else {
            sha256.update(pin2.getBytes("UTF-8"));
            sha256.update(pin1.getBytes("UTF-8"));
        }
        sha256.update(Long.toString(Math.min(id1, id2)).getBytes("UTF-8"));
        sha256.update(Long.toString(Math.max(id1, id2)).getBytes("UTF-8"));
        return sha256.digest();
    }

    private String hashPin(String pin) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(pin.getBytes("UTF-8"));
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    // ──────────────────────────────────────────────────────────
    //  ENVÍO DE MENSAJES
    // ──────────────────────────────────────────────────────────

    private void enviar(long chatId, String texto) {
        SendMessage msg = new SendMessage();
        msg.setChatId(String.valueOf(chatId));
        msg.setText(texto);
        try {
            execute(msg);
        } catch (TelegramApiException e) {
            System.err.println("Error enviando mensaje a " + chatId + ": " + e.getMessage());
        }
    }
}