with open(r'E:\Generate files\encrypted_3des\file_1MB.txt.enc', 'rb') as file:
    data = file.read()
    print(data)  # Menampilkan konten file dalam bentuk binary
