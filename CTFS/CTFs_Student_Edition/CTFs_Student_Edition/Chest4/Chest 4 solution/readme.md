# 🔓 Reverse Engineering Password Checker with Ghidra

## 📚 Summary

This project demonstrates how to reverse engineer a password-checking binary (`out.exe`) using **Ghidra** and recover the hidden password. The binary compares a user input to a result derived from two arrays (`local_28` and `local_48`). By analyzing the `main` and `check_pw` functions, we extracted the logic and parameters to reverse engineer the password.

The recovered password is: `CMPN{reverse_engineering}`.

---

## 🔨 Tools Used

- [Ghidra](https://ghidra-sre.org/): Reverse engineering framework
- Python 3.x

---

## 🧩 Problem Description

The binary performs the following operations to validate the password:

1. The `main` function initializes two arrays (`local_28` and `local_48`) and passes them, along with the user input, to the `check_pw` function.
2. The `check_pw` function compares the user input to the result of `local_28[i] - local_48[i]` for each character.
3. If all characters match, the password is correct.

To recover the password, we need to:

1. Decompile the binary using **Ghidra**.
2. Analyze the `main` and `check_pw` functions to extract the logic and parameters.
3. Reverse the logic of the comparison using the formula: `password[i] = local_28[i] - local_48[i]`.

---

## 💡 Solution

We wrote a Python script to reverse the logic of the binary and recover the password. The script subtracts each corresponding byte of `local_48` from `local_28` to compute the password.

### Python Script
The following Python script recovers the password:

```python
# recover_password.py
local28 = [
    0x45, 0x50, 0x52, 0x51, 0x7c, 
    0x73, 0x67, 0x7b, 0x69, 0x75,
    0x75, 0x66, 0x62, 0x6a, 0x71,
    0x68, 0x6f, 0x75, 0x68, 0x67,
    0x76, 0x68, 0x6d, 0x68, 0x7e
]

local48 = [
     0x02, 0x03, 0x02, 0x03, 0x01,
    0x01, 0x02, 0x05, 0x04, 0x03,
    0x02, 0x01, 0x03, 0x05, 0x03,
    0x01, 0x06, 0x07, 0x03, 0x02,
    0x04, 0xff, 0xff, 0x01, 0x01,
]

password = ""
for i in range(25):
    val = (local28[i] - local48[i]) % 256
    password += chr(val)

print(password)
```

---

## 🚀 Execution

To recover the password, run the Python script:

```bash
python recover_password.py
```

---

## 📝 Output

When the script is executed, it recovers the password:

```
Recovered password: CMPN{reverse_engineering}
```

---

## 🔑 Key

The recovered password is: `CMPN{reverse_engineering}`
