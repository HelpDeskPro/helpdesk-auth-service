
package com.helpdeskpro.auth.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import com.helpdeskpro.auth.exception.InvalidRefreshTokenException;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    // DUPLICATE EMAIL

    @ExceptionHandler(EmailAlreadyRegisteredException.class)
    public ResponseEntity<Map<String, String>> handleDuplicateEmail(
            EmailAlreadyRegisteredException exception
    ) {
        Map<String, String> errors = new HashMap<>();

        errors.put("message", exception.getMessage());

        return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body(errors);
    }

    // INVALID LOGIN CREDENTIALS

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<Map<String, String>> handleInvalidCredentials(
            InvalidCredentialsException exception
    ) {
        Map<String, String> errors = new HashMap<>();

        errors.put("message", exception.getMessage());

        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(errors);
    }

    // ACCOUNT NOT ACTIVATED

    @ExceptionHandler(AccountNotEnabledException.class)
    public ResponseEntity<Map<String, String>> handleAccountNotEnabled(
            AccountNotEnabledException exception
    ) {
        Map<String, String> errors = new HashMap<>();

        errors.put("message", exception.getMessage());

        return ResponseEntity
                .status(HttpStatus.FORBIDDEN)
                .body(errors);
    }

    // REQUEST VALIDATION ERRORS

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, String>> handleValidationErrors(
            MethodArgumentNotValidException exception
    ) {
        Map<String, String> errors = new HashMap<>();

        exception.getBindingResult()
                .getFieldErrors()
                .forEach(error ->
                        errors.putIfAbsent(
                                error.getField(),
                                error.getDefaultMessage()
                        )
                );

        return ResponseEntity
                .badRequest()
                .body(errors);
    }
    @ExceptionHandler(InvalidRefreshTokenException.class)
    public ResponseEntity<Map<String, String>> handleInvalidRefreshToken(
            InvalidRefreshTokenException exception
    ) {
        Map<String, String> errors = new HashMap<>();

        errors.put("message", exception.getMessage());

        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(errors);
    }
}
