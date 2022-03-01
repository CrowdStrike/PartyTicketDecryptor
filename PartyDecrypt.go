package main
 
import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"os"
	"flag"
)
 
func main() {
 
	encrypted_filepath := flag.String("p", "encrypted.bin", "Path to encrypted file")
	flag.Parse()
 
	fmt.Printf("Decrypting file : %s\n", *encrypted_filepath)
	key_bytes := []byte("6FBBD7P95OE8UT5QRTTEBIWAR88S74DO")
	key := hex.EncodeToString(key_bytes)
	fmt.Printf("Decryption key : %s\n", key_bytes)
 
	dat, err := os.ReadFile(*encrypted_filepath)
	if err != nil {
		fmt.Println("Unable to open file, please supply path of encrypted file with flag -p, default file path is ./encrypted.bin")
		os.Exit(3)
	}
 
	decrypted_filepath := "decrypted.bin"
	filecontents := dat
	encrypted_contents := filecontents[:len(filecontents) - 288]
	enc_size := len(encrypted_contents)
	bsize := 1048604
	cycles := enc_size / bsize
 
	if cycles == 0{ 
 
		encrypted := hex.EncodeToString(encrypted_contents)
		decrypted := decrypt(encrypted, key)
		write_output(decrypted_filepath, decrypted)
		} else {
			for i:=0; i<cycles; i++ {
				if i >= 9 {
					start := 9 * bsize
					end := enc_size
					data := string(encrypted_contents[start:end])
					write_output(decrypted_filepath, data)
					break
				}
				block_start := i * bsize
				block_end := (i+1) * bsize
				if block_end > enc_size{
					block_end := enc_size
					encrypted:=hex.EncodeToString(encrypted_contents[block_start:block_end])
					decrypted := decrypt(encrypted, key)
					write_output(decrypted_filepath, decrypted)
 
				}
 
				encrypted:=hex.EncodeToString(encrypted_contents[block_start:block_end])
				decrypted := decrypt(encrypted, key)
				write_output(decrypted_filepath, decrypted)
			}
		}
 
		fmt.Printf("Decrypted file written to : %s\n", decrypted_filepath)
 
	}
 
func write_output(filepath string, data string) {
		f, err := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic(err)
		}
		byte_data := []byte(data)
		f.Write(byte_data)
		f.Close()
}
 
func decrypt(encryptedString string, keyString string) (decryptedString string) {
 
	key, _ := hex.DecodeString(keyString)
	enc, _ := hex.DecodeString(encryptedString)
 
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := aesGCM.NonceSize()
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
 
	return fmt.Sprintf("%s", plaintext)
}

