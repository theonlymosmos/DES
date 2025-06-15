//Made with Love by Mousa Emarah
//https://linkedin.com/in/mousa123

//this edition displays in details the steps of the encryption and decryption process and the rounds in details.

import java.util.Scanner;

public class DESinDetails {
    
    // Initial Permutation (IP) table
    private static final int[] IP = {
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    };
    
    // Final Permutation (FP) table
    private static final int[] FP = {
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    };
    
    // Permuted Choice 1 (PC1) table
    private static final int[] PC1 = {
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    };
    
    // Permuted Choice 2 (PC2) table
    private static final int[] PC2 = {
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    };
    
    // Expansion table (E)
    private static final int[] E = {
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    };
    
    // S-boxes
    private static final int[][][] S_BOXES = {
        { // S1
            {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
            {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
            {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
            {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
        },
        { // S2
            {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
            {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
            {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
            {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
        },
        { // S3
            {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
            {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
            {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
            {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
        },
        { // S4
            {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
            {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
            {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
            {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
        },
        { // S5
            {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
            {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
            {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
            {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
        },
        { // S6
            {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
            {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
            {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
            {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
        },
        { // S7
            {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
            {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
            {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
            {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
        },
        { // S8
            {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
            {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
            {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
            {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
        }
    };
    
    // Permutation (P) table
    private static final int[] P = {
        16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25
    };
    
    // Number of left shifts for each round
    private static final int[] SHIFTS = {
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    };

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("DES Encryption/Decryption");
        System.out.print("Enter text to encrypt: ");
        String message = scanner.nextLine();
        
        System.out.print("Enter a 8-character key (exactly 8 bytes, e.g., 'mykey123'): ");
        String key = scanner.nextLine();
        
        if (key.length() != 8) {
            System.out.println("Error: Key must be exactly 8 characters!");
            scanner.close();
            return;
        }
        
        // Pad message if needed (PKCS5 padding)
        int padLength = 8 - (message.length() % 8);
        if (padLength != 8) {
            char padChar = (char)padLength;
            message = message + new String(new char[padLength]).replace('\0', padChar);
        }
        
        System.out.println("\nPlain Text: " + message.substring(0, message.length() - (message.length() > 8 ? padLength : 0)));
        
        // 1) Key generation with verbose output
        System.out.println("\n=== KEY GENERATION ===");
        long keyBits = stringToBits(key);
        System.out.println("Initial Key (64 bits): " + Long.toBinaryString(keyBits));
        
        long[] subkeys = generateSubkeys(keyBits);
        
        // 2) Message encryption with detailed round information
        System.out.println("\n=== ENCRYPTION PROCESS ===");
        StringBuilder encryptedText = new StringBuilder();
        for (int i = 0; i < message.length(); i += 8) {
            String block = message.substring(i, Math.min(i + 8, message.length()));
            System.out.println("\nProcessing block: " + block);
            long messageBits = stringToBits(block);
            System.out.println("Block (64 bits): " + padBinary(Long.toBinaryString(messageBits), 64));
            long ciphertext = desEncrypt(messageBits, subkeys, true); // Changed to true to show steps
            encryptedText.append(bitsToString(ciphertext));
        }
        
        System.out.println("\nEncrypted text (hex): " + bytesToHex(encryptedText.toString()));
        
        // 3) Decryption with detailed round information
        System.out.println("\n=== DECRYPTION PROCESS ===");
        long[] reverseSubkeys = new long[16];
        for (int i = 0; i < 16; i++) {
            reverseSubkeys[i] = subkeys[15 - i];
        }
        
        StringBuilder decryptedText = new StringBuilder();
        for (int i = 0; i < encryptedText.length(); i += 8) {
            String block = encryptedText.substring(i, Math.min(i + 8, encryptedText.length()));
            System.out.println("\nProcessing encrypted block: " + bytesToHex(block));
            long cipherBits = stringToBits(block);
            System.out.println("Block (64 bits): " + padBinary(Long.toBinaryString(cipherBits), 64));
            long decrypted = desEncrypt(cipherBits, reverseSubkeys, true); // Changed to true to show steps
            decryptedText.append(bitsToString(decrypted));
        }
        
        // Remove padding
        String finalDecrypted = decryptedText.toString();
        if (padLength != 8) {
            int lastChar = finalDecrypted.charAt(finalDecrypted.length() - 1);
            if (lastChar <= 8) {
                finalDecrypted = finalDecrypted.substring(0, finalDecrypted.length() - lastChar);
            }
        }
        
        System.out.println("\nDecrypted Text: " + finalDecrypted);
        
        scanner.close();
    }

    private static long[] generateSubkeys(long key) {
        System.out.println("\nKey Generation Steps:");
        System.out.println("1. Applying PC1 permutation (64-bit to 56-bit)");
        long permutedKey = permute(key, PC1, 64);
        System.out.println("   PC1 output: " + padBinary(Long.toBinaryString(permutedKey), 56));
        
        System.out.println("2. Splitting into C0 and D0 (28-bit halves)");
        int leftHalf = (int)((permutedKey >>> 28) & 0x0FFFFFFF);
        int rightHalf = (int)(permutedKey & 0x0FFFFFFF);
        System.out.println("   C0: " + padBinary(Integer.toBinaryString(leftHalf), 28));
        System.out.println("   D0: " + padBinary(Integer.toBinaryString(rightHalf), 28));
        
        long[] subkeys = new long[16];
        
        for (int i = 0; i < 16; i++) {
            System.out.println("\nRound " + (i+1) + ":");
            System.out.println("3. Left shifting C" + i + " and D" + i + " by " + SHIFTS[i] + " bits");
            leftHalf = leftShift(leftHalf, SHIFTS[i], 28);
            rightHalf = leftShift(rightHalf, SHIFTS[i], 28);
            System.out.println("   C" + (i+1) + ": " + padBinary(Integer.toBinaryString(leftHalf), 28));
            System.out.println("   D" + (i+1) + ": " + padBinary(Integer.toBinaryString(rightHalf), 28));
            
            System.out.println("4. Applying PC2 permutation to create subkey");
            long combined = ((long)leftHalf << 28) | rightHalf;
            subkeys[i] = permute(combined, PC2, 56);
            System.out.println("   Subkey " + (i+1) + ": " + padBinary(Long.toBinaryString(subkeys[i]), 48));
        }
        
        return subkeys;
    }

    private static long desEncrypt(long block, long[] subkeys, boolean showSteps) {
        if (showSteps) {
            System.out.println("\nInitial Permutation (IP):");
            System.out.println("Input block: " + padBinary(Long.toBinaryString(block), 64));
        }
        
        long permuted = permute(block, IP, 64);
        
        if (showSteps) {
            System.out.println("After IP: " + padBinary(Long.toBinaryString(permuted), 64));
            System.out.println("Splitting into L0 and R0 (32-bit halves)");
        }
        
        int left = (int)(permuted >>> 32);
        int right = (int)(permuted & 0xFFFFFFFFL);
        
        if (showSteps) {
            System.out.println("L0: " + padBinary(Integer.toBinaryString(left), 32));
            System.out.println("R0: " + padBinary(Integer.toBinaryString(right), 32));
        }
        
        for (int round = 0; round < 16; round++) {
            if (showSteps) {
                System.out.println("\nRound " + (round + 1) + ":");
                System.out.println("L" + round + ": " + padBinary(Integer.toBinaryString(left), 32));
                System.out.println("R" + round + ": " + padBinary(Integer.toBinaryString(right), 32));
            }
            
            int previousLeft = left;
            left = right;
            
            if (showSteps) {
                System.out.println("1. Expanding R" + round + " from 32 to 48 bits (E table)");
            }
            long expanded = permute(right, E, 32);
            
            if (showSteps) {
                System.out.println("   Expanded R" + round + ": " + padBinary(Long.toBinaryString(expanded), 48));
                System.out.println("2. XOR with subkey K" + (round+1) + ": " + padBinary(Long.toBinaryString(subkeys[round]), 48));
            }
            
            expanded ^= subkeys[round];
            
            if (showSteps) {
                System.out.println("   After XOR: " + padBinary(Long.toBinaryString(expanded), 48));
                System.out.println("3. Applying S-boxes (48-bit to 32-bit)");
            }
            
            int sboxOutput = 0;
            for (int i = 0; i < 8; i++) {
                int chunk = (int)((expanded >>> (42 - i*6)) & 0x3F);
                int row = ((chunk >> 4) & 0x2) | (chunk & 0x1);
                int col = (chunk >> 1) & 0xF;
                sboxOutput = (sboxOutput << 4) | (S_BOXES[i][row][col] & 0xF);
                
                if (showSteps) {
                    System.out.println("   S" + (i+1) + " input: " + padBinary(Integer.toBinaryString(chunk), 6) + 
                                     " (row " + row + ", col " + col + ") -> " + 
                                     padBinary(Integer.toBinaryString(S_BOXES[i][row][col]), 4));
                }
            }
            
            if (showSteps) {
                System.out.println("   S-boxes output: " + padBinary(Integer.toBinaryString(sboxOutput), 32));
                System.out.println("4. Applying P permutation");
            }
            
            int feistel = (int)permute(sboxOutput, P, 32);
            
            if (showSteps) {
                System.out.println("   After P: " + padBinary(Integer.toBinaryString(feistel), 32));
                System.out.println("5. XOR with L" + round + ": " + padBinary(Integer.toBinaryString(previousLeft), 32));
            }
            
            right = previousLeft ^ feistel;
            
            if (showSteps) {
                System.out.println("   New R" + (round+1) + ": " + padBinary(Integer.toBinaryString(right), 32));
            }
        }
        
        if (showSteps) {
            System.out.println("\nAfter 16 rounds:");
            System.out.println("L16: " + padBinary(Integer.toBinaryString(left), 32));
            System.out.println("R16: " + padBinary(Integer.toBinaryString(right), 32));
            System.out.println("Final swap and FP permutation");
        }
        
        long combined = ((long)right << 32) | (left & 0xFFFFFFFFL);
        long result = permute(combined, FP, 64);
        
        if (showSteps) {
            System.out.println("Final ciphertext: " + padBinary(Long.toBinaryString(result), 64));
        }
        
        return result;
    }
    
    // Helper method to pad binary string with leading zeros
    private static String padBinary(String binary, int length) {
        return String.format("%" + length + "s", binary).replace(' ', '0');
    }
    
    // Convert string to 64-bit long
    private static long stringToBits(String str) {
        long result = 0;
        for (int i = 0; i < 8; i++) {
            result = (result << 8) | (str.charAt(i) & 0xFF);
        }
        return result;
    }
    
    // Convert 64-bit long back to string
    private static String bitsToString(long bits) {
        char[] chars = new char[8];
        for (int i = 7; i >= 0; i--) {
            chars[i] = (char)(bits & 0xFF);
            bits >>= 8;
        }
        return new String(chars);
    }
    
    // Permutation function
    private static long permute(long input, int[] table, int inputSize) {
        long result = 0;
        for (int i = 0; i < table.length; i++) {
            int pos = inputSize - table[i];
            long bit = (input >>> pos) & 1;
            result = (result << 1) | bit;
        }
        return result;
    }
    
    // Circular left shift
    private static int leftShift(int value, int shift, int size) {
        int mask = (1 << size) - 1;
        return ((value << shift) | (value >>> (size - shift))) & mask;
    }
    
    // Helper method to convert bytes to hex
    private static String bytesToHex(String str) {
        StringBuilder hex = new StringBuilder();
        for (char c : str.toCharArray()) {
            hex.append(String.format("%02X ", (int)c));
        }
        return hex.toString();
    }
}