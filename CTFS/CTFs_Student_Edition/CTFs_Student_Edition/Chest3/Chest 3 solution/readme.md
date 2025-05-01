# Chest 3 Solution - Vault Door Decryption Code Explanation

## Overview
This solution involves reversing the scrambling process used in the `VaultDoor8` Java program to recover the original password. The scrambling process transposes pairs of bits in each character of the password. By reversing this process, we can reconstruct the original password from the scrambled password stored in the program. The recovered password is: `s0m3_m0r3_b1t_sh1fTiNg_91c642112`.

---

## Decryption Logic
The decryption process involves the following steps:

1. **Understanding the Scrambling Process**:
   - The `scramble` function in the `VaultDoor8` program transposes pairs of bits in each character of the password using the `switchBits` function.
   - The scrambling process is applied sequentially to all characters in the password.

2. **Reversing the Scrambling Process**:
   - To reverse the scrambling, the `reverse_scramble` function applies the same bit transpositions in the reverse order.
   - This reconstructs the original password from the scrambled password.

3. **Recovering the Original Password**:
   - The scrambled password is stored in the `expected` array in the `VaultDoor8` program.
   - By applying the `reverse_scramble` function to this scrambled password, we recover the original password.

---

## Key Functions and Code Explanation

### Scrambling Process
The `scramble` function transposes pairs of bits in each character of the password:
```java
public char[] scramble(String password) {
    char[] a = password.toCharArray();
    for (int b = 0; b < a.length; b++) {
        char c = a[b];
        c = switchBits(c, 1, 2);
        c = switchBits(c, 0, 3);
        c = switchBits(c, 5, 6);
        c = switchBits(c, 4, 7);
        c = switchBits(c, 0, 1);
        c = switchBits(c, 3, 4);
        c = switchBits(c, 2, 5);
        c = switchBits(c, 6, 7);
        a[b] = c;
    }
    return a;
}
```

### Reversing the Scrambling Process
The `reverse_scramble` function reverses the scrambling process by applying the bit transpositions in reverse order:
```java
public char[] reverse_scramble(String password) {
    char[] a = password.toCharArray();
    for (int b = 0; b < a.length; b++) {
        char c = a[b];
        c = switchBits(c, 6, 7);
        c = switchBits(c, 2, 5);
        c = switchBits(c, 3, 4);
        c = switchBits(c, 0, 1);
        c = switchBits(c, 4, 7);
        c = switchBits(c, 5, 6);
        c = switchBits(c, 0, 3);
        c = switchBits(c, 1, 2);
        a[b] = c;
    }
    return a;
}
```

### Switching Bits
The `switchBits` function swaps two bits in a character:
```java
public char switchBits(char c, int p1, int p2) {
    char mask1 = (char) (1 << p1);
    char mask2 = (char) (1 << p2);
    char bit1 = (char) (c & mask1);
    char bit2 = (char) (c & mask2);
    char rest = (char) (c & ~(mask1 | mask2));
    char shift = (char) (p2 - p1);
    char result = (char) ((bit1 << shift) | (bit2 >> shift) | rest);
    return result;
}
```

### Recovering the Password
The `convertPassword` function applies the `reverse_scramble` function to the scrambled password to recover the original password:
```java
public String convertPassword(char[] scrambledPassword) {
    String scrambled = new String(scrambledPassword);
    char[] reversed = reverse_scramble(scrambled);
    return new String(reversed);
}
```

### Main Method
The `main` method demonstrates how to recover the original password:
```java
public static void main(String[] args) {
    reverse_engineering re = new reverse_engineering();
    char[] scrambledPassword = {
        0xF4, 0xC0, 0x97, 0xF0, 0x77, 0x97, 0xC0, 0xE4, 0xF0, 0x77, 0xA4, 0xD0, 0xC5, 0x77, 0xF4, 0x86, 0xD0,
        0xA5, 0x45, 0x96, 0x27, 0xB5, 0x77, 0xD2, 0xD0, 0xB4, 0xE1, 0xC1, 0xE0, 0xD0, 0xD0, 0xE0
    };
    String originalPassword = re.convertPassword(scrambledPassword);
    System.out.println("Original password: " + originalPassword);
}
```

---

## Output
When the program is executed, it recovers the original password:
```
Original password: s0m3_m0r3_b1t_sh1fTiNg_91c642112
```

---

## Key
The recovered key is: `s0m3_m0r3_b1t_sh1fTiNg_91c642112`