package com.example.TOTP.service;

import com.bastiaanjansen.otp.HMACAlgorithm;
import com.bastiaanjansen.otp.TOTP;
import com.example.TOTP.CustomCodeVerifier;
import com.example.TOTP.dto.VerifyOtpDto;
import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.exceptions.CodeGenerationException;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.NtpTimeProvider;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.UnknownHostException;
import java.time.Duration;
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
        //        try {
        //            generateQr(secret);
        //        } catch (QrGenerationException | IOException e) {
        //            e.printStackTrace();
        //        }
        return secret;
    }

    public void generateQr(String secret) throws QrGenerationException, IOException {
        QrData data = new QrData.Builder()
            .label("anshul@reldyn.co")
            .secret(secret)
            .issuer("Anshul")
            .algorithm(HashingAlgorithm.SHA512)
            .digits(6)
            .period(30)
            .build();
        QrGenerator generator = new ZxingPngQrGenerator();
        byte[] imageData = generator.generate(data);

        FileOutputStream fos = new FileOutputStream(new File("/home/anshul/qr.png"));
        fos.write(imageData);
        fos.close();
    }

    public boolean verifyOtp(VerifyOtpDto dto) {
        try {
            TimeProvider timeProvider = new NtpTimeProvider("time.aws.com");
            Date date = new Date(timeProvider.getTime() * 1000L);
            System.out.println(date);
            CodeGenerator generator = new DefaultCodeGenerator(HashingAlgorithm.SHA512, 6);
            CustomCodeVerifier verifier = new CustomCodeVerifier(generator, timeProvider);
            verifier.setTimePeriod(30);
            verifier.setAllowedTimePeriodDiscrepancy(2);
            return verifier.isValidCode(dto.getDate(), dto.getSecret(), dto.getOtp());
        } catch (Exception e) {
            System.out.println("Error verifying totp : " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    public String generateOtp(Date transactionTime, String secretKey) throws CodeGenerationException {
        Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        calendar.clear();
        calendar.setTime(new Date());
        long secondsSinceEpoch = calendar.getTimeInMillis() / 1000;
        long verifyKey = Math.floorDiv(secondsSinceEpoch, 30);
        CodeGenerator codeGenerator = new DefaultCodeGenerator(HashingAlgorithm.SHA512, 6);

        return codeGenerator.generate(secretKey, verifyKey);
    }
}
