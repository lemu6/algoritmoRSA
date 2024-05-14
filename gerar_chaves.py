import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def gerar_par_chaves():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def salvar_chave_privada(private_key, filename, senha=None):
    encryption_algorithm = serialization.BestAvailableEncryption(senha.encode()) if senha else serialization.NoEncryption()
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=encryption_algorithm
    )
    with open(filename, 'wb') as f:
        f.write(private_key_pem)

def carregar_chave_privada(filename, senha=None):
    with open(filename, 'rb') as f:
        private_key_pem = f.read()
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=senha.encode() if senha else None,
        backend=default_backend()
    )
    return private_key

def salvar_chave_publica(public_key, filename):
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, 'wb') as f:
        f.write(public_key_pem)

def carregar_chave_publica(filename):
    with open(filename, 'rb') as f:
        public_key_pem = f.read()
    public_key = serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )
    return public_key

def criptografar_dados(public_key, dados):
    dados_cifrados = public_key.encrypt(
        dados,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return dados_cifrados

def descriptografar_dados(private_key, dados_cifrados, senha=None):
    dados = private_key.decrypt(
        dados_cifrados,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return dados

def listar_arquivos_diretorio(diretorio):
    return [f for f in os.listdir(diretorio) if os.path.isfile(os.path.join(diretorio, f))]

def pesquisar_arquivo(diretorio, nome_arquivo):
    arquivos = listar_arquivos_diretorio(diretorio)
    return nome_arquivo in arquivos

def apagar_arquivo(filepath):
    if os.path.isfile(filepath):
        os.remove(filepath)

def criptografar_arquivo(public_key_file, input_file, output_file):
    public_key = carregar_chave_publica(public_key_file)
    with open(input_file, 'rb') as f:
        dados = f.read()
    dados_cifrados = criptografar_dados(public_key, dados)
    with open(output_file, 'wb') as f:
        f.write(dados_cifrados)

def descriptografar_arquivo(private_key_file, input_file, output_file, senha=None):
    private_key = carregar_chave_privada(private_key_file, senha)
    with open(input_file, 'rb') as f:
        dados_cifrados = f.read()
    dados = descriptografar_dados(private_key, dados_cifrados, senha)
    with open(output_file, 'wb') as f:
        f.write(dados)
   

# funcao para gerar o par de chaves
#private_key, public_key = gerar_par_chaves()

# salvando as chaves em arquivos
 
#salvar_chave_privada(private_key, 'nova_chave_privada.pem', senha=None)
#salvar_chave_publica(public_key, 'nova_chave_publica.pem')

# necessario criar o arquivo ""documento.txt" com a informacao a ser cifrada
criptografar_arquivo('nova_chave_publica.pem', 'documento.txt', 'documento_cifrado.txt')

descriptografar_arquivo('nova_chave_privada.pem', 'documento_cifrado.txt', 'documento_descriptografado.txt')

