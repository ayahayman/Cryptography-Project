# Chest 1 Solution - Decryption Code Explanation

## Overview
This solution involves decrypting an encrypted text file (`enc.txt`) using a Python script (`decryption_code.py`). The script reverses the alphabetical characters in the text while leaving non-alphabetical characters unchanged. The decrypted output is saved in a new file called `dec.txt`.

---

## Decryption Logic
The decryption process is based on reversing the position of each alphabetical character in the alphabet. For example:
- `a` becomes `z`, `b` becomes `y`, and so on.
- Similarly, `A` becomes `Z`, `B` becomes `Y`, and so on.

This is achieved using the following formula:
- For lowercase letters: `chr(219 - ord(ch))`
- For uppercase letters: `chr(155 - ord(ch))`

### Function: `reverse_alpha(ch)`
This function takes a single character as input and returns its reversed counterpart if it is an alphabetical character. If the character is not alphabetical, it is returned unchanged.

```python
def reverse_alpha(ch):
    if 'a' <= ch <= 'z':
        return chr(219 - ord(ch))  # Reverse lowercase letters
    elif 'A' <= ch <= 'Z':
        return chr(155 - ord(ch))  # Reverse uppercase letters
    else:
        return ch  # Non-alphabetical characters remain unchanged
```

---

## Key
The key is: `CMPN{i_luv_jojo}`