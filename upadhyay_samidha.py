#Name: Samidha Upadhyay
#Student id: s370663
#Question no 2

def encrypt(plaintext, keyword):
    plaintext = plaintext.upper()
    keyword = keyword.upper()
    ciphertext = ""

    for i in range(len(plaintext)):
        if plaintext[i].isalpha():
            # Converting plaintext to a number 0 to 25
            plain_txt = ord(plaintext[i]) - ord('A')
            #find the relevant keyword from 0-25
            key_txt = ord(keyword[i % len(keyword)]) - ord('A')
            # shifting the plaintext character by the position of the keyword 
            encrypted_txt = (plain_txt + key_txt) % 26
            ciphertext += chr(encrypted_txt + ord('A'))
        else:
            ciphertext += plaintext[i]

    return ciphertext

def decrypt(ciphertext, keyword):
    #ciphertext = ciphertext.upper()
    keyword = keyword.upper()
    plaintext = ""

    for i in range(len(ciphertext)):
        if ciphertext[i].isalpha():
            #converting ciphertext to number 0 to 25
            cipher_txt = ord(ciphertext[i]) - ord('A')
            #find the relevant keyword from 0-25
            key_txt = ord(keyword[i % len(keyword)]) - ord('A')
            #decrypting by shifting in reverse
            decrypted_txt = (cipher_txt - key_txt) % 26
            plaintext += chr(decrypted_txt + ord('A'))
        else:
            plaintext += ciphertext[i]

    return plaintext

def main():
    plaintext = "hello"
    keyword = "KEY"
    encryptedtext = encrypt(plaintext, keyword)
    decryptedtext = decrypt(encryptedtext, keyword)
    print("Plaintext",  plaintext)
    print("Encrypted:", encryptedtext)
    print("Decrypted:", decryptedtext)
main()
