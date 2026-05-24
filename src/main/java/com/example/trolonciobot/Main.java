package com.example.trolonciobot;

import com.example.trolonciobot.bot.TroloncioBot;
import org.telegram.telegrambots.meta.TelegramBotsApi;
import org.telegram.telegrambots.meta.exceptions.TelegramApiException;
import org.telegram.telegrambots.updatesreceivers.DefaultBotSession;

/**
 * Punto de entrada del bot.
 * Lee el token y username desde variables de entorno
 * para que no aparezcan en el código fuente.
 */
public class Main {

    public static void main(String[] args) {
        String token    = System.getenv("BOT_TOKEN");
        String username = System.getenv("BOT_USERNAME");

        if (token == null || token.isEmpty()) {
            System.err.println("ERROR: BOT_TOKEN no está configurado.");
            System.exit(1);
        }
        if (username == null || username.isEmpty()) {
            System.err.println("ERROR: BOT_USERNAME no está configurado.");
            System.exit(1);
        }

        try {
            TelegramBotsApi api = new TelegramBotsApi(DefaultBotSession.class);
            api.registerBot(new TroloncioBot(token, username));
            System.out.println("TroloncioBot iniciado correctamente.");
        } catch (TelegramApiException e) {
            System.err.println("Error al iniciar el bot: " + e.getMessage());
            e.printStackTrace();
        }
    }
}