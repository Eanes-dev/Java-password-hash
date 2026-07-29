package structure;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class Hash {
    //Variável para definir o tipo de criptografia.
    private final String ALGORITHM = "SHA-256";
    //Variável para definir as repetições de um laço para fortalecimento do algoritmo
    private final int HARDENING = 10000;

    //Classe para gerar números aleatórios seguros para criptografia
    private final SecureRandom secureRandom;
    //Classe que fornece algoritmos de criptografia, utilizada para aplicar o SHA-256
    private final MessageDigest messageDigest;

    //Construtor da classe, usado para iniciar o SecureRandom e MessageDigest
    public Hash() {
        try {
            this.secureRandom = SecureRandom.getInstanceStrong();
            this.messageDigest = MessageDigest.getInstance(ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Erro ao inicializar o sistema de hash", e);
        }
    }

    //Classe pública para abstrair o processo de codificação
    public String encode(String text) {
        return this.encode(text, null);
    }

    //Classe utilizada para transformar o texto em hash criptografado
    private String encode(String text, byte[] salt) throws IllegalArgumentException {
        //Verificação de parâmetros
        if( text == null ) {
            throw new IllegalArgumentException("Senha não pode ser vazia");
        }

        //Gera um salt aleatório caso o passado seja nulo
        salt = salt == null ? this.generateSaltRandom() : salt;
        
        //Gera um hash em bytes
        byte[] hash = this.calculateHash(salt, text);

        //Transformação da array de hash e de salt em strings
        String saltBase64 = Base64.getEncoder().encodeToString(salt);
        String hashBase64 = Base64.getEncoder().encodeToString(hash);

        return saltBase64 + ':' + hashBase64;
    }

    //Gera um hash em bytes
    private byte[] calculateHash(byte[] salt, String text ) {
            //Cria uma array de bytes pela soma do tamanho das arrays de salt e de text.
            byte[] data = new byte[salt.length + text.getBytes().length];
            //Copia os elementos das arrays de salt e text para a array de dados
            System.arraycopy(salt, 0, data, 0, salt.length);
            System.arraycopy(text.getBytes(), 0, data, salt.length, text.getBytes().length);

            //Processo de transformação da array de data em uma array de hash
            byte[] hash = this.messageDigest.digest(data);

            //Fortalecimento do código
            for( int i = 0; i < this.HARDENING ; i++ ) {
                hash = this.messageDigest.digest(hash);
            }

            return hash;
    }

    //Método utilizado para comparar duas strings e validar se são a mesma string hash
    public boolean compare( String text, String hash ) throws IllegalArgumentException {
        //Divide a string em salt e hash
        String[] parts = hash.split(":");

        //Validação dos parâmetros
        if(text == null || hash == null) {
            throw new IllegalArgumentException("Invalid parameters!");
        }
        //Validação da string hash passada, verificando se a string está no formato apropriado
        if(parts.length != 2) {
            return false;
        }

        //Transformando a string em um array de bytes
        byte[] hashCode = Base64.getDecoder().decode(parts[1]);
        byte[] saltCode = Base64.getDecoder().decode(parts[0]);
        //Gerando um hash com o texto passado e o salt utilizado no hash anterior
        byte[] hashGenerated = this.calculateHash(saltCode, text);

        //Comparação de hash
        return MessageDigest.isEqual(hashCode, hashGenerated);
    }

    //Geração de salts aleatórios e seguros
    private byte[] generateSaltRandom() {
        byte[] salt = new byte[16];
        this.secureRandom.nextBytes(salt);
        return salt;
    }
}
