# Chest 2 Solution - Audio Decryption Code Explanation

## Overview
This solution involves decrypting two encrypted audio files (`output3.wav` and `output4.wav`) using a Python script (`decryption_code.py`). The script performs a bitwise XOR operation on the two audio files after ensuring they are of the same length. The decrypted audio is saved as `decrypted_flag.wav`. Additionally, the script splits the decrypted audio into chunks, reshuffles them based on a predefined order, and saves the reshuffled audio as `reshuffled_flag.wav`.

---

## Decryption Logic
The decryption process involves the following steps:

1. **Loading the Audio Files**: The script reads two audio files (`output3.wav` and `output4.wav`) and ensures they have the same sample rate.
2. **Padding the Shorter Audio**: If the two audio files have different lengths, the shorter one is padded with zeros to match the length of the longer one.
3. **Bitwise XOR Operation**: A bitwise XOR operation is performed on the two audio files to produce the decrypted audio.
4. **Saving the Decrypted Audio**: The resulting audio is saved as `decrypted_flag.wav`.
5. **Splitting the Audio**: The decrypted audio is split into 11 chunks, each of 700 milliseconds.
6. **Reshuffling the Chunks**: The chunks are reordered based on a predefined order and combined into a single audio file.
7. **Saving the Reshuffled Audio**: The reshuffled audio is saved as `reshuffled_flag.wav`.

---

## Key Functions and Code Explanation

### Padding the Shorter Audio
To ensure the XOR operation works on the entire length of both audio files, the shorter audio is padded with zeros:
```python
if len(data1) < len(data2):
    data1 = np.pad(data1, (0, len(data2) - len(data1)), mode='constant')
elif len(data2) < len(data1):
    data2 = np.pad(data2, (0, len(data1) - len(data2)), mode='constant')
```

### Bitwise XOR Operation
The XOR operation is performed on the two audio files to decrypt the data:
```python
result = np.bitwise_xor(data1, data2)
```

### Splitting the Audio into Chunks
The decrypted audio is split into 11 chunks, each of 700 milliseconds:
```python
segment_duration_ms = 700
segment_samples = int((segment_duration_ms / 1000.0) * rate)
chunks = [data[i * segment_samples:(i + 1) * segment_samples] for i in range(11)]
```

### Reshuffling the Chunks
The chunks are reordered based on the predefined order:
```python
new_order = [9, 3, 8, 5, 4, 1, 0, 6, 2, 7, 10]
reordered = np.concatenate([chunks[i] for i in new_order])
```

### Saving the Results
The decrypted and reshuffled audio files are saved:
```python
wavfile.write("decrypted_flag.wav", rate1, result)
wavfile.write("reshuffled_flag.wav", rate, reordered)
```

---

## Output Files
1. **Decrypted Audio**: `decrypted_flag.wav` - The result of the XOR operation.
2. **Reshuffled Audio**: `reshuffled_flag.wav` - The reshuffled version of the decrypted audio.

---

## Key
The reshuffling order is: `[9, 3, 8, 5, 4, 1, 0, 6, 2, 7, 10]`
The key is: `CMPN{cyber_security}`