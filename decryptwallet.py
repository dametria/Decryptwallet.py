from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import os

def decrypt_wallet(wallet_path: str, output_path: str, key: bytes):
    """
    Decrypts the Wallet.dat file using AES with Oracle Padding (PKCS7).

    Parameters:
        wallet_path (str): The path to the Wallet.dat file.
        output_path (str): The path to save the decrypted output file.
        key (bytes): The AES key used for decryption (must be 16, 24, or 32 bytes).

    Raises:
        ValueError: If the wallet_path or output_path is invalid or file does not exist.
        Exception: If decryption fails due to incorrect key or corrupted data.
    """
    # Expand user home directory in paths
    wallet_path = os.path.expanduser("/root/wallet1.001.dat")
    output_path = os.path.expanduser("/root/key.txt")

    # Check if the wallet_path is valid and the file exists
    if not os.path.isfile(wallet_path):
        raise ValueError("Invalid wallet_path or file does not exist.")

    # Check if the output_path directory is valid
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.isdir(output_dir):
        raise ValueError("Invalid output_path directory.")

    try:
        # Read the encrypted data from the Wallet.dat file
        with open(wallet_path, 'rb') as file:
            # Read IV (typically 16 bytes for AES-CBC)
            iv = file.read(16)
            encrypted_data = file.read()

        # Initialize AES cipher in CBC mode
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Decrypt and unpad the data
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

        # Write decrypted data to output file
        with open(output_path, 'wb') as file:
            file.write(decrypted_data)

        print(f"Decryption successful. Decrypted data saved to {output_path}")

    except Exception as e:
        raise Exception(f"Decryption failed: {str(e)}")

# Example usage
if __name__ == "__main__":
    # Example parameters (replace with actual key and paths)
    wallet_path = "~/root/wallet1.001.dat"
    output_path = "~/root/key.txt"
    # Example 32-byte key (replace with actual key)
    key = b"32_byte_key_here_1234567890123456"  # Must be 16, 24, or 32 bytes

    try:
        decrypt_wallet(wallet_path, output_path, key)
    except Exception as e:
        print(f"Error: {str(e)}")
