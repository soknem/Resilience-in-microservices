package com.api_getway.product_service.exception;


import com.api_getway.product_service.base.BasedError;
import com.api_getway.product_service.base.BasedErrorResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

@RestControllerAdvice
public class ServiceException {

    @ExceptionHandler(ResponseStatusException.class)
    ResponseEntity<?> handleServiceErrors(ResponseStatusException ex) {

        BasedError<String> basedError = new BasedError<>();
        basedError.setCode(ex.getStatusCode().toString());
        basedError.setDescription(ex.getReason());

        BasedErrorResponse basedErrorResponse = new BasedErrorResponse();
        basedErrorResponse.setError(basedError);

        return ResponseEntity.status(ex.getStatusCode())
                .body(basedErrorResponse);
    }

}

