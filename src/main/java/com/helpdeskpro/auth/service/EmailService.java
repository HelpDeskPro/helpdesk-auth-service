package com.helpdeskpro.auth.service;

import lombok.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {
    private final JavaMailSender mailSender;
    private final String fromEmail;
    private final String frontendURL;

    public EmailService(JavaMailSender mailSender,
                        @Value("${app.mail.from}")String fromEmail,
                        @Value("${app.frontend.url}") String frontendURL) {
        this.mailSender = mailSender;
        this.fromEmail = fromEmail;
        this.frontendURL = frontendURL;

    }
    public void sendVerificationEmail(String recipiantEmail, String token) {
        String verificationLink = frontendURL + "/verify-email?token" + token;
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromEmail);
        message.setTo(recipiantEmail);
        message.setSubject("Verification Email");
        message.setText("Welcome to the verification email service");
        mailSender.send(message);
    }
}
