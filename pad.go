package utils

func PadBytes(data []byte, blockSize int) []byte {
	// Add padding (originally for correctness, now for simplicity)
	for len(data) % blockSize != 0 {
		data = append(data, 0x0)
	}
	return data
}
