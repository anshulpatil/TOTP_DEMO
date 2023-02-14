package com.example.TOTP.service;

import com.example.TOTP.CustomCodeVerifier;
import com.example.TOTP.dto.VerifyOtpDto;
import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.exceptions.CodeGenerationException;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.NtpTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;
import org.springframework.stereotype.Service;

@Service
public class TOTPService {

    public String generateSecret() {
        SecretGenerator generator = new DefaultSecretGenerator(64);
        String secret = generator.generate();
        System.out.println(secret);
        return secret;
    }

    public boolean verifyOtp(VerifyOtpDto dto) {
        try {
            TimeProvider timeProvider = new NtpTimeProvider("time.aws.com");
            CodeGenerator generator = new DefaultCodeGenerator(HashingAlgorithm.SHA512, 6);
            CustomCodeVerifier verifier = new CustomCodeVerifier(generator, timeProvider);
            verifier.setTimePeriod(30);
            verifier.setAllowedTimePeriodDiscrepancy(2);
            return verifier.isValidCode(new Date(), dto.getSecret(), dto.getOtp());
        } catch (Exception e) {
            System.out.println("Error verifying totp : " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    public String generateOtp(Date transactionTime, String secretKey) throws CodeGenerationException {
        Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        calendar.clear();
        calendar.setTime(transactionTime);
        long secondsSinceEpoch = calendar.getTimeInMillis() / 1000;
        long verifyKey = Math.floorDiv(secondsSinceEpoch, 30);
        CodeGenerator codeGenerator = new DefaultCodeGenerator(HashingAlgorithm.SHA512, 6);

        return codeGenerator.generate(secretKey, verifyKey);
    }
}
