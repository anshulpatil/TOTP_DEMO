package com.example.TOTP;

import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.exceptions.CodeGenerationException;
import dev.samstevens.totp.time.TimeProvider;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

public class CustomCodeVerifier {

    private final CodeGenerator codeGenerator;
    private final TimeProvider timeProvider;
    private int timePeriod = 30;
    private int allowedTimePeriodDiscrepancy = 1;

    public CustomCodeVerifier(CodeGenerator codeGenerator, TimeProvider timeProvider) {
        this.codeGenerator = codeGenerator;
        this.timeProvider = timeProvider;
    }

    public void setTimePeriod(int timePeriod) {
        this.timePeriod = timePeriod;
    }

    public void setAllowedTimePeriodDiscrepancy(int allowedTimePeriodDiscrepancy) {
        this.allowedTimePeriodDiscrepancy = allowedTimePeriodDiscrepancy;
    }

    public boolean isValidCode(Date transactionTime, String secret, String code) {
        //Get seconds since epoch upto given date to further calculate TOTP
        Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        calendar.clear();
        calendar.setTime(transactionTime);
        long secondsSinceEpoch = calendar.getTimeInMillis() / 1000;

        // Get the current number of seconds since the epoch and
        // calculate the number of time periods passed.
        long currentBucket = Math.floorDiv(secondsSinceEpoch, timePeriod);

        // Calculate and compare the codes for all the "valid" time periods,
        // even if we get an early match, to avoid timing attacks
        boolean success = false;
        for (int i = -allowedTimePeriodDiscrepancy; i <= allowedTimePeriodDiscrepancy; i++) {
            success = checkCode(secret, currentBucket + i, code) || success;
        }

        return success;
    }

    /**
     * Check if a code matches for a given secret and counter.
     */
    private boolean checkCode(String secret, long counter, String code) {
        try {
            String actualCode = codeGenerator.generate(secret, counter);
            return timeSafeStringComparison(actualCode, code);
        } catch (CodeGenerationException e) {
            return false;
        }
    }

    /**
     * Compare two strings for equality without leaking timing information.
     */
    private boolean timeSafeStringComparison(String a, String b) {
        byte[] aBytes = a.getBytes();
        byte[] bBytes = b.getBytes();

        if (aBytes.length != bBytes.length) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < aBytes.length; i++) {
            result |= aBytes[i] ^ bBytes[i];
        }

        return result == 0;
    }
}
