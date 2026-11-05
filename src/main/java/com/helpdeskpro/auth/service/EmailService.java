
package com.helpdeskpro.auth.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    private final JavaMailSender mailSender;
    private final String fromEmail;
    private final String frontendUrl;

    public EmailService(
            JavaMailSender mailSender,
            @Value("${app.mail.from}") String fromEmail,
            @Value("${app.frontend.url}") String frontendUrl
    ) {
        this.mailSender = mailSender;
        this.fromEmail = fromEmail;
        this.frontendUrl = frontendUrl;
    }

    public void sendVerificationEmail(
            String recipientEmail,
            String token
    ) {

        String verificationLink =
                frontendUrl + "/verify-email?token=" + token;

        SimpleMailMessage message = new SimpleMailMessage();

        message.setFrom(fromEmail);
        message.setTo(recipientEmail);
        message.setSubject("Verify your HelpDesk Pro account");

        message.setText(
                "Hello,\n\n" +
                        "Thank you for registering with HelpDesk Pro.\n\n" +
                        "Please click the link below to verify your email address:\n\n" +
                        verificationLink + "\n\n" +
                        "This link expires in 30 minutes.\n\n" +
                        "If you did not create this account, you can ignore this email."
        );

        mailSender.send(message);
    }

    public void sendPasswordResetEmail(
            String recipientEmail,
            String token
    ) {

        String resetLink =
                frontendUrl + "/reset-password?token=" + token;

        SimpleMailMessage message = new SimpleMailMessage();

        message.setFrom(fromEmail);
        message.setTo(recipientEmail);
        message.setSubject("Reset your HelpDesk Pro password");

        message.setText(
                "Hello,\n\n" +
                        "We received a request to reset your HelpDesk Pro password.\n\n" +
                        "Click the link below to reset your password:\n\n" +
                        resetLink + "\n\n" +
                        "This link expires in 30 minutes.\n\n" +
                        "If you did not request a password reset, you can ignore this email."
        );

        mailSender.send(message);
    }
}
