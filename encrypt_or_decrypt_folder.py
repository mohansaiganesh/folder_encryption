import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

'''
Function Name   --      encrypt_file
Description     --      Encrypts the ''.txt' file with 'key' and outputs '.txt' file 
Input           --      [
                            key - AES key, 
                            input_file_path - Complete file path of a file to be encryptyed, 
                            output_file_path - Complete file path of a file to be stored at a location after encryption
                        ]
Output          --      [
                            Returns void
                        ]
'''
def encrypt_file(key, input_file_path, output_file_path):
    chunk_size = 64 * 1024  # 64KB
    init_vector = get_random_bytes(16)

    encryptor = AES.new(key, AES.MODE_CBC, init_vector)

    with open(input_file_path, 'rb') as input_file:
        with open(output_file_path, 'wb') as output_file:
            output_file.write(init_vector)
            while True:
                chunk = input_file.read(chunk_size)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - len(chunk) % 16)
                enc_chunk = encryptor.encrypt(chunk)
                output_file.write(enc_chunk)

'''
Function Name   --      decrypt_file
Description     --      Decrypts the '.txt' file with 'key' and outputs '.txt' file 
Input           --      [
                            key - AES key, 
                            input_file_path - Complete file path of a file to be decryptyed, 
                            output_file_path - Complete file path of a file to be stored at a location after decryption
                        ]
Output          --      [
                            Returns void
                        ]
'''
def decrypt_file(key, input_file_path, output_file_path):
    chunk_size = 64 * 1024  # 64KB

    with open(input_file_path, 'rb') as input_file:
        init_vector = input_file.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, init_vector)

        with open(output_file_path, 'wb') as output_file:
            while True:
                chunk = input_file.read(chunk_size)
                if len(chunk) == 0:
                    break
                dec_chunk = decryptor.decrypt(chunk)
                output_file.write(dec_chunk)

'''
Function Name   --      crypto_action_on_directory.
Description     --      Performs encryption/decryption on a directory based on the value of 'choice'.
Input           --      [
                            directory - path of the directory on which cryptographic actions are to be taken , 
                            choice - '1' for Encryption and '2' for Decryption, 
                        ]
Output          --      [
                            Returns void
                        ]
'''
def crypto_action_on_directory(directory,choice):
    try:
        if choice == 1:
            new_root = directory + "_encrypted"
        elif choice == 2:
            new_root = directory + "_decrypted"

        #create the new directory 'directory_encrypted or directory_decrypted' outside the 'directory'
        os.makedirs(new_root, exist_ok=True)

        for root, dirs, files in os.walk(directory):
            #Mirror all the sub directories in 'directory_encrypted or directory_decrypted' same as 'directory'
            for dir_name in dirs:
                    relative_path = os.path.relpath(os.path.join(root, dir_name), directory)
                    new_folder = os.path.join(new_root, relative_path)
                    os.makedirs(new_folder, exist_ok=True)
            
            #Iterate all the files in 'directory' and perform suitable crypto actions
            for file in files:
                #name of the 'file' in 'directory' with complete path and original file extension
                file_path = os.path.join(root, file)
                file_path_without_extension, file_extension = os.path.splitext(file_path)
                #name of the 'file' in 'directory' with complete path and '.txt' file extension
                file_path_txt = file_path_without_extension + ".txt"

                # Create new folder maintaining directory structure of main directory
                relative_path = os.path.relpath(file_path, directory)

                #name of the 'file' in 'directory_encrypted/directory_decrypted' with complete path and original file extension
                new_file_path = os.path.join(new_root, relative_path)
                new_file_path_without_extension, new_file_extension = os.path.splitext(new_file_path)
                #name of the 'file' in 'directory_encrypted/directory_decrypted' with complete path and '.txt' file extension
                new_file_path_txt = new_file_path_without_extension + ".txt"
                
                #renaming the file in 'directory' to '.txt' file
                os.rename(file_path, file_path_txt)

                print("Appling crypto actions on : ",file_path)
                #Encryption/Decryption based performed based on the 'choice'
                aes_key = b''  # Change this to your desired encryption key of 128bit length
                if choice == 1:
                    encrypt_file(aes_key, file_path_txt, new_file_path_txt)
                elif choice == 2:
                    decrypt_file(aes_key, file_path_txt, new_file_path_txt)

                #renaming the files back to their original extensions
                os.rename(file_path_txt, file_path)
                os.rename(new_file_path_txt, new_file_path)

    except Exception as e:
        print(f"An error occurred: {e}")

'''
Function Name   --      encrypt_files_in_directory.
Description     --      Performs encryption on a directory provided 'choice = 1'.
Input           --      [
                            directory - path of the directory on which encryption is to be done,  
                            choice - is equal to '1'
                        ]
Output          --      [
                            Returns void
                        ]
'''
def encrypt_files_in_directory(directory,choice):
    crypto_action_on_directory(directory,choice)
    print("Encryption completed successfully!")

'''
Function Name   --      decrypt_files_in_directory.
Description     --      Performs decryption on a directory provided 'choice = 2'.
Input           --      [
                            directory - path of the directory on which decrytion is to be done, 
                            choice - is equal to '2'
                        ]
Output          --      [
                            Returns void
                        ]
'''
def decrypt_files_in_directory(directory,choice):
    crypto_action_on_directory(directory,choice)
    print("Decryption completed successfully!")

if __name__ == "__main__":

    #validation to check the inetgers provided are only '1' or '2'
    choice = 0
    while True:
        choice = int(input("Enter 1 for Encryption. 2 for Decryption."))
        if choice == 1 or choice == 2:
            break

    #validation to check whether the 'directory' is a valid one or not
    input_directory = input("Enter the directory name: ") 
    while True:
        if not os.path.exists(input_directory) or not os.path.isdir(input_directory):
            print("Invalid directory. Please enter a valid directory.")
            input_directory = input("Enter the directory name: ")
        else:
            break
    
    #Performing the crypto actions based on the choices
    if choice == 1:
        encrypt_files_in_directory(input_directory,choice)
    elif choice == 2:
        decrypt_files_in_directory(input_directory,choice)