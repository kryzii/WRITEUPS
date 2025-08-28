import socket
import threading
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

HOST = '0.0.0.0'
PORT = 1600
FLAG = b"n3xt{EDITED}"

SECRET_KEY = os.urandom(16)

class OracleServer:
    def __init__(self, key):
        self.key = key

    def encrypt_the_prophecy(self):
        """Encrypts the flag with a random IV."""
        iv = os.urandom(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded_flag = pad(FLAG, AES.block_size)
        encrypted_flag = cipher.encrypt(padded_flag)
        return iv + encrypted_flag

    def check_padding(self, ciphertext_with_iv):
        """The Oracle function. Decrypts and checks padding."""
        if len(ciphertext_with_iv) % AES.block_size != 0:
            return False 
        iv = ciphertext_with_iv[:AES.block_size]
        ciphertext = ciphertext_with_iv[AES.block_size:]

        if not ciphertext:
            return False

        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        try:
            decrypted_data = cipher.decrypt(ciphertext)
            unpad(decrypted_data, AES.block_size)
            return True
        except ValueError:
            return False

def handle_client(conn, addr):
    oracle = OracleServer(SECRET_KEY)
    print(f"[+] The Oracle has a new querent: {addr}")

    try:
        prophecy = oracle.encrypt_the_prophecy().hex()
        conn.sendall(
            b"Greetings, querent. I am the Oracle.\n"
            b"I possess a prophecy, but its meaning is shrouded.\n"
            b"Here is the encrypted text. I will not give you the key.\n"
            b"However, I will tell you if any text you provide has 'valid runes' (padding).\n"
            b"Prophecy (HEX): " + prophecy.encode() + b"\n"
        )

        while True:
            conn.sendall(b"Provide new ciphertext (HEX) to check, or 'submit <guess>':\n> ")
            data = conn.recv(4096).strip().decode()
            if not data:
                break
            
            if data.lower().startswith("submit"):
                guess = data[7:].strip()
                if guess.encode() == FLAG:
                    conn.sendall(b"\n*** INCREDIBLE! You have deciphered the prophecy! ***\n")
                    print(f"[*] {addr} solved the Oracle!")
                else:
                    conn.sendall(b"That is not what the runes foretell.\n")
                break

            try:
                ciphertext_to_check = bytes.fromhex(data)
                if oracle.check_padding(ciphertext_to_check):
                    conn.sendall(b"The runes are well-formed. (Valid Padding)\n")
                else:
                    conn.sendall(b"The runes are chaotic. (Invalid Padding)\n")
            except ValueError:
                conn.sendall(b"That is not a valid hex encoding.\n")

    except (ConnectionResetError, BrokenPipeError):
        print(f"[-] Querent {addr} has vanished.")
    except Exception as e:
        print(f"[!] An error occurred with {addr}: {e}")
    finally:
        conn.close()
        print(f"[-] Connection to {addr} closed.")

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print(f"[*] The Oracle is listening on {HOST}:{PORT}")
        while True:
            conn, addr = server_socket.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[*] The Oracle is going silent.")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()
