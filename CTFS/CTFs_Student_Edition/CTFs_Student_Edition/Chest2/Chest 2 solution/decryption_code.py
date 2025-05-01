import numpy as np
from scipy.io import wavfile

# Load audio files
rate1, data1 = wavfile.read("output3.wav")
rate2, data2 = wavfile.read("output4.wav")

# Sanity check: same sample rate?
assert rate1 == rate2, "Sample rates do not match!"

# Pad the shorter audio with zeros to match the length of the longer one
if len(data1) < len(data2):
    data1 = np.pad(data1, (0, len(data2) - len(data1)), mode='constant')
elif len(data2) < len(data1):
    data2 = np.pad(data2, (0, len(data1) - len(data2)), mode='constant')

# Option 1: Subtract
result = np.bitwise_xor(data1, data2)

# Optional: normalize to prevent clipping
result = np.clip(result, -32768, 32767).astype(np.int16)

# Save result
wavfile.write("decrypted_flag.wav", rate1, result)

# Load the audio
rate, data = wavfile.read("decrypted_flag.wav")

# Convert milliseconds to number of samples
segment_duration_ms = 700
segment_samples = int((segment_duration_ms / 1000.0) * rate)

# Split audio into 11 chunks of 700ms
chunks = [data[i * segment_samples:(i + 1) * segment_samples] for i in range(11)]

# Sanity check: All segments equal?
print(f"Loaded {len(chunks)} chunks, each of length {segment_samples} samples")

# Define the reshuffling order
new_order = [9, 3, 8, 5, 4, 1, 0, 6, 2, 7, 10]

# Reorder and combine chunks
reordered = np.concatenate([chunks[i] for i in new_order])

# Save the reshuffled audio
wavfile.write("reshuffled_flag.wav", rate, reordered)
print("✅ Reshuffled file saved as 'reshuffled_flag.wav'")
