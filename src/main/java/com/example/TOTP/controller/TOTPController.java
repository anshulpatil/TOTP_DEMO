package com.example.TOTP.controller;

import com.example.TOTP.dto.VerifyOtpDto;
import com.example.TOTP.service.TOTPService;
import dev.samstevens.totp.exceptions.CodeGenerationException;
import java.util.Date;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TOTPController {

    @Autowired
    TOTPService totpService;

    @PostMapping("/verify-otp")
    public boolean verifyOtp(@RequestBody VerifyOtpDto dto) {
        return totpService.verifyOtp(dto);
    }

    @GetMapping("/generate-secret")
    public void generateOtp() {
        totpService.generateSecret();
    }

    @PostMapping("/generate-otp")
    public String getOtp(@RequestBody GenerateOtpDto dto) throws CodeGenerationException {
        return totpService.generateOtp(dto.getDate(), dto.getSecret());
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    static class GenerateOtpDto {

        private Date date;
        private String secret;
    }
}
