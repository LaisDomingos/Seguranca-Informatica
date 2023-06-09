const express = require('express');
const path = require('path');
const forge = require('node-forge');
const Sequelize = require("sequelize");
const crypto = require('crypto');
const multer = require('multer');
const fs = require('fs');
const bodyParser = require('body-parser');
const mysql = require('mysql');
const archiver = require('archiver');
const { Readable } = require('stream');

// Chamar o express
const app = express();
const port = 3000;

app.use(bodyParser.json());

// Configurações do Multer para o armazenamento do arquivo
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

app.use(bodyParser.urlencoded({ extended: true }));

// Configurações do MySQL
const db = mysql.createConnection({
    host: 'localhost', // Endereço do servidor MySQL
    user: 'root', // Usuário do banco de dados
    password: '', // Senha do banco de dados
    database: 'seguranca_informatica' // Nome do banco de dados
});

// Conectar-se ao banco de dados
db.connect((err) => {
    if (err) {
        return res.status(301).redirect('/?msg=Erro ao se conectar à base de dados!');
        throw err;
    }
    console.log('Conectado ao banco de dados MySQL');

    // Criar a tabela para armazenar as informações dos arquivos, se não existir
    const createTableQuery = `
    CREATE TABLE IF NOT EXISTS arquivos (
      id INT AUTO_INCREMENT PRIMARY KEY,
      nome VARCHAR(255) NOT NULL,
      iv VARCHAR(255) NOT NULL,
      sendTo VARCHAR(255) NOT NULL,
      encrypted BOOLEAN NOT NULL,
      zip BOOLEAN NOT NULL,
      encrypted_aes LONGBLOB NOT NULL,
      hmac VARCHAR(255) NOT NULL,
      arquivo LONGBLOB NOT NULL
    );`;
    db.query(createTableQuery, (err) => {
        if (err) {
            throw err;
        }
        console.log('Tabela "arquivos" criada ou já existe');
    });

    // Criar a tabela para armazenar as informações dos usuarios, se não existir
    const createTableUsers = `
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      token VARCHAR(255) NOT NULL,
      publicKey TEXT NOT NULL
    );`;
    db.query(createTableUsers, (err) => {
        if (err) {
            throw err;
        }
        console.log('Tabela "users" criada ou já existe');
    });
});

// Obter o caminho do html. 'templates' é a pasta que contem o .html
const pathName = path.join(__dirname, 'templates');
const pathFiles = path.join(__dirname, 'files');

// receber informações do formulario
app.use(
    express.urlencoded({
        extended: true,
    }),
);
app.use(express.json());

app.get('/', (req, res) => {
    // res.send(`Caminho: ${pathName}`)
    res.sendFile(`${pathName}/index.html`)
});

let publicKey;
let privateKey;
app.post('/generate', (req, res) => {

    // GERAR PAR DE CHAVES PARA UM TOKEN
    const token = req.body.token;

    // CONFERIR SE O TOKEN JA EXISTE NA BASE DE DADOS
    // recuperar chave publica do db
    const selectQuery = "SELECT token FROM users WHERE token = '" + token + "';";
    db.query(selectQuery, (err, result) => {
        if (err) {
            return res.status(301).redirect('/?msg=Erro ao fazer requisição à base de dados!');
        }

        // Verificar se algum token foi encontrado
        if (result.length !== 0) {
            return res.status(301).redirect('/?msg=O token "' + token + '" já está a ser utilizado, tente outro!');
        }
    })

    // Gera um par de chaves pública e privada
    const keys = forge.pki.rsa.generateKeyPair({ bits: 2048 });
    privateKey = forge.pki.privateKeyToPem(keys.privateKey);
    publicKey = forge.pki.publicKeyToPem(keys.publicKey);

    console.log("--------------- Chave pública --------------");
    console.log(publicKey);
    console.log("--------------- Fim da Chave pública --------------");

    // SALVAR NA BASE DE DADOS
    const insertQuery = 'INSERT INTO users (token, publicKey) VALUES (?, ?)';
    db.query(insertQuery, [token, publicKey], (err, result) => {
        if (err) {
            return res.status(301).redirect('/?msg=Erro ao salvar na base de dados: ' + err);
        }
    });

    // criar arquivos com as chaves
    fs.writeFile('./privateKey.pem', privateKey, function (erro) {
        if (erro) {
            console.error('Ocorreu um erro ao gravar o arquivo:', erro); 
        } else {
            console.log('Arquivo com a chave privada gravado com sucesso!');
        }
    });

    fs.writeFile('./publicKey.pem', publicKey, function (erro) {
        if (erro) {
            console.error('Ocorreu um erro ao gravar o arquivo:', erro);
        } else {
            console.log('Arquivo com a chave publica gravado com sucesso!');
        }
    });

    // zipar ficheiros
    // Cria um arquivo ZIP
    const output = fs.createWriteStream('chavesRSA.zip');
    const zip = archiver('zip', {
        zlib: { level: 9 } // Nível de compressão máximo
    });

    // Pipe o arquivo ZIP para o output (arquivo de saída)
    zip.pipe(output);

    // Adicionar os arquivos ao arquivo ZIP
    const arquivo1 = path.join(__dirname, 'publicKey.pem');
    const arquivo2 = path.join(__dirname, 'privateKey.pem');

    // nomes output
    zip.file(arquivo1, { name: 'publicKey.pem' });
    zip.file(arquivo2, { name: 'privateKey.pem' });

    // Finaliza o arquivo ZIP
    zip.finalize();

    // Download do zip com as chaves
    // Evento 'close' é disparado quando o arquivo ZIP é completamente escrito
    output.on('close', () => {
        const arquivoZip = path.join(__dirname, 'chavesRSA.zip');

        res.download(arquivoZip, 'chavesRSA_' + token + '.zip', (erro) => {
            if (erro) {
                console.error('Ocorreu um erro ao fazer o download do arquivo ZIP:', erro);
            } else {
                console.log('Arquivo ZIP baixado com sucesso.');
            }

            // Apagar arquivos após o download
            const arquivoZip = path.join(__dirname, 'chavesRSA.zip');
            const publicKeyPath = path.join(__dirname, 'publicKey.pem');
            const privateKeyPath = path.join(__dirname, 'privateKey.pem');

            fs.unlink(arquivoZip, (erro) => {
                if (erro) {
                    console.error('Ocorreu um erro ao apagar o arquivo ZIP:', erro);
                } else {
                    console.log('Arquivo ZIP apagado com sucesso!');

                    // Apaga o arquivo publicKey.pem
                    fs.unlink(publicKeyPath, (erro) => {
                        if (erro) {
                            console.error('Ocorreu um erro ao apagar o arquivo publicKey.pem:', erro);
                        } else {
                            console.log('Arquivo publicKey.pem apagado com sucesso!');

                            // Apaga o arquivo privateKey.pem
                            fs.unlink(privateKeyPath, (erro) => {
                                if (erro) {
                                    console.error('Ocorreu um erro ao apagar o arquivo privateKey.pem:', erro);
                                } else {
                                    console.log('Arquivo privateKey.pem apagado com sucesso!');
                                }
                            });
                        }
                    });
                }
            });

        });
    });
})

// Rota para lidar com o upload do arquivo
app.post('/upload', upload.single('ficheiro'), (req, res) => {

    // recuperar chave publica do db
    const selectQuery = "SELECT publicKey, token FROM users WHERE token = '" + req.body.token_dest + "';";
    db.query(selectQuery, (err, result) => {
        if (err) {
            return res.status(301).redirect('/?msg=Erro ao fazer requisição à base de dados!');
            throw err;
        }

        // Verificar se o arquivo foi encontrado
        if (result.length === 0) {
            return res.status(301).redirect('/?msg=User com esse token não encontrado!');
        }

        // Recuperar chave publica do token
        const userData = result[0];
        const publicKey = userData.publicKey;

        // Obter as informações do arquivo enviado
        const file = req.file;

        // Verificar se o arquivo existe
        if (!file) {
            return res.status(301).redirect('/?msg=Nenhum arquivo enviado');
        }

        var bufferFicheiro = file.buffer;

        const hmac = crypto.createHmac('sha256', 'chave_de_hmac');
        hmac.update(bufferFicheiro);
        const fileHMAC = hmac.digest('hex');

        // CONFERIR RADIO FORMULARIO
        if (req.body.comprimir) {
            if (req.body.comprimir == 'sim') {

                // arquivo .zip sem cifrar
                comprimir(file.buffer, file).then((bufferFicheiro) => {

                    var encrypted = false;
                    var chaveAesCifrada = 'nao aplicavel';
                    const sendTo = req.body.token_dest;

                    if (req.body.cifrado == 'nao') {
                        salvarDataBase(file.originalname + '.zip', 0, sendTo, encrypted, chaveAesCifrada, true, fileHMAC, bufferFicheiro) //este 'bufferFicheiro' == return da funcao 'comprimir()'
                    }

                    // arquivo .zip e cifrado
                    if (req.body.cifrado == 'sim') {
                        encrypted = true

                        // CIFRAR FICHEIRO COM AES
                        // Gerar chave AES aleatória
                        const chaveBytes = forge.random.getBytesSync(32);

                        // Gerar vetor de inicialização (IV) aleatório
                        const ivBytes = forge.random.getBytesSync(16);
                        console.log("IV: ", ivBytes, "\n");
                        const ivBase64 = forge.util.encode64(ivBytes);

                        // Criar um objeto de criptografia AES
                        const cipher = forge.cipher.createCipher('AES-CBC', chaveBytes);
                        cipher.start({ iv: ivBytes });

                        // Cifrar os dados
                        cipher.update(forge.util.createBuffer(bufferFicheiro));
                        cipher.finish();

                        // Obter o resultado da criptografia
                        bufferFicheiro = cipher.output.getBytes();
                        const bufferFicheiroBase64 = forge.util.encode64(bufferFicheiro);

                        // Converter a chave pública para o formato adequado do Forge
                        const publicKey = forge.pki.publicKeyFromPem(userData.publicKey);

                        // Cifrar a chave AES com a chave pública RSA
                        const encryptedAesBuffer = publicKey.encrypt(chaveBytes);

                        // Converter o resultado para uma string em base64
                        const encryptedAes = forge.util.encode64(encryptedAesBuffer);

                        salvarDataBase(file.originalname + '.zip', ivBase64, sendTo, encrypted, encryptedAes, true, fileHMAC, bufferFicheiroBase64) //este 'bufferFicheiro' == return da funcao 'comprimir()'

                    }


                }).catch((error) => {
                    console.error(error);
                });

            }
            else {
                if (req.body.cifrado == 'sim') {
                    // Salvar arquivo no banco de dados cifrado e sem comprimir
                    cifrarFicheiro_e_AES_salvarDB(userData, file)

                } else {
                    // Salvar o arquivo no banco de dados sem cifrar e sem comprimir
                    var encrypted = false;
                    const chaveAesCifrada = 'nao aplicavel';
                    const sendTo = req.body.token_dest;
                    salvarDataBase(file.originalname, false, sendTo, encrypted, chaveAesCifrada, false, fileHMAC, bufferFicheiro)
                }
            }
        } else {
            return res.status(301).redirect('/?msg=Erro na leitura do formulario!');
        }
    })

    // DEFINICAO DE FUNCOES
    function salvarDataBase(nome, iv, sendTo, encrypted, encrypted_aes, zip, fileHMAC, arquivo) {
        const insertQuery = 'INSERT INTO arquivos (nome, iv, sendTo, encrypted, encrypted_aes, zip, hmac, arquivo) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
        db.query(insertQuery, [nome, iv, sendTo, encrypted, encrypted_aes, zip, fileHMAC, arquivo], (err, result) => {
            if (err) {
                throw err;
            }
            let message = 'Arquivo enviado e salvo com sucesso!';
            if (!encrypted) {
                message += '\nHMAC: ' + fileHMAC;
            }
            return res.status(301).redirect('/?msg=' + message);
        });
    }

    function cifrarFicheiro_e_AES_salvarDB(userData, file) {
        let encrypted = true;
        var bufferFicheiro = file.buffer;

        // CIFRAR FICHEIRO COM AES
        // Gerar chave AES aleatória
        const chaveBytes = forge.random.getBytesSync(32);

        // Gerar vetor de inicialização (IV) aleatório
        const ivBytes = forge.random.getBytesSync(16);
        console.log("IV: ", ivBytes, "\n");
        const ivBase64 = forge.util.encode64(ivBytes);

        // Criar um objeto de criptografia AES
        const cipher = forge.cipher.createCipher('AES-CBC', chaveBytes);
        cipher.start({ iv: ivBytes });

        // Cifrar os dados
        cipher.update(forge.util.createBuffer(bufferFicheiro));
        cipher.finish();

        // Obter o resultado da criptografia
        bufferFicheiro = cipher.output.getBytes();
        const bufferFicheiroBase64 = forge.util.encode64(bufferFicheiro);

        // Converter a chave pública para o formato adequado do Forge
        const publicKey = forge.pki.publicKeyFromPem(userData.publicKey);

        // Cifrar a chave AES com a chave pública RSA
        const encryptedAesBuffer = publicKey.encrypt(chaveBytes);

        // Converter o resultado para uma string em base64
        const encryptedAes = forge.util.encode64(encryptedAesBuffer);

        // Salvar o arquivo cifrado no banco de dados
        const sendTo = req.body.token_dest;
        const hmac = crypto.createHmac('sha256', 'chave_de_hmac');
        hmac.update(bufferFicheiro);
        const fileHMAC = hmac.digest('hex');
        salvarDataBase(file.originalname, ivBase64, sendTo, encrypted, encryptedAes, false, fileHMAC, bufferFicheiroBase64)
    }

    function comprimir(bufferArquivo, file) {
        return new Promise((resolve, reject) => {
            const archive = archiver('zip', {
                zlib: { level: 9 }
            });

            let zipBuffer;
            archive.on('error', (error) => {
                console.error('Erro ao compactar o arquivo:', error);
                reject(error);
            }).on('data', (chunk) => {
                if (!zipBuffer) {
                    zipBuffer = chunk;
                } else {
                    zipBuffer = Buffer.concat([zipBuffer, chunk]);
                }
            }).on('end', () => {
                resolve(zipBuffer);
            });

            // Obter o nome do arquivo original
            const nomeArquivo = file.originalname;

            // Obter a extensão do arquivo original
            const extensao = path.extname(nomeArquivo);

            // Obter o nome do arquivo sem a extensão
            const nomeOriginal = path.basename(nomeArquivo, path.extname(nomeArquivo));

            // Definir o nome do arquivo ZIP com a extensão correta
            const nomeArquivoZip = `${nomeOriginal}${extensao}`;

            archive.append(bufferArquivo, { name: nomeArquivoZip });

            archive.finalize();
        });
    }
});

app.post('/listagem', (req, res) => {
    const tokenForm = req.body.token;

    // Consultar o banco de dados para obter o arquivo pelo Token
    const selectQuery = "SELECT id, nome, encrypted FROM arquivos WHERE sendTo = '" + tokenForm + "';";
    db.query(selectQuery, [tokenForm], (err, result) => {
        if (err) {
            throw err;
        }

        // Verificar se algum arquivo foi encontrado
        if (result.length === 0) {
            return res.status(301).redirect('/?msg=Nenhum arquivo encontrado'); 
        }

        // const jsonData = { id: 1, nome: "Exemplo" };
        const jsonString = JSON.stringify(result);
        const encodedJson = (jsonString);

        // Redirecionamento para a rota com o JSON como parâmetro 
        res.redirect('/?json=' + encodedJson);
    });

})

app.post('/download', upload.single('privateKeyFile'), (req, res) => {
    const fileId = req.body.id;

    // Consultar o banco de dados para obter o arquivo pelo ID
    const selectQuery = "SELECT nome, iv, arquivo, encrypted, encrypted_aes, zip FROM arquivos WHERE id = '" + fileId + "';";
    db.query(selectQuery, [fileId], (err, result) => {
        if (err) {
            throw err;
        }

        // Verificar se o arquivo foi encontrado
        if (result.length === 0) {
            return res.status(301).redirect('/?msg=Arquivo não encontrado');
        }

        // Obter as informações do arquivo do resultado da consulta
        const fileData = result[0];
        const fileName = fileData.nome;
        const ivBase64 = fileData.iv;
        const fileContentBase64 = fileData.arquivo;
        const fileContent = fileData.arquivo;
        const encrypted = fileData.encrypted;
        const encrypted_aes = fileData.encrypted_aes;
        const zip = fileData.zip;

        // Configurar os cabeçalhos da resposta
        if (zip == true) {
            res.set('Content-Type', 'application/zip');
            res.set('Content-Disposition', 'attachment; filename=' + fileName + '.zip');
        } else {
            res.setHeader('Content-disposition', `attachment; filename="${fileName}"`);
            res.setHeader('Content-type', 'application/octet-stream');
        }

        // Enviar o conteúdo do arquivo DECIFRADO como resposta
        if (encrypted == '1') {

            if (!req.file) {
                return res.status(301).redirect('/?msg=O ficheiro está cifrado, selecione uma chave!');
            }

            try {
                // Importar chave privada do formulário
                const pemPrivateKey = req.file.buffer.toString();

                // Carregar a chave privada PEM
                const privateKey = forge.pki.privateKeyFromPem(pemPrivateKey);

                // Decodificar a chave AES cifrada em base64
                const encryptedAesBase64 = forge.util.decode64(encrypted_aes.toString());

                // Decifrar a chave AES com a chave privada RSA
                const decryptedAes = privateKey.decrypt(encryptedAesBase64);

                //console.log("Buffer do ficheiro(Base 64): ", fileContentBase64.toString(), "\n");
                let fileContent = forge.util.decode64(fileContentBase64.toString());

                // Obter o IV do arquivo cifrado
                const ivBytes = forge.util.decode64(ivBase64);

                // const decipher = crypto.createDecipheriv('aes-256-cbc', decrypted_aes, iv);
                const decipher = forge.cipher.createDecipher("AES-CBC", decryptedAes);
                decipher.start({ iv: ivBytes });
                decipher.update(forge.util.createBuffer(fileContent));
                decipher.finish();

                let dadosDecifrados = Buffer.from(decipher.output.getBytes(), "binary");

                res.send(dadosDecifrados);
            }
            catch (err) {
                return res.status(301).redirect('/?msg=Erro: Chave privada inválida!');
            }
        } else {
            res.send(fileContent);
        }
    });

});

app.get('/download-menu', (req, res) => {

    const arquivo = __dirname + '/files/menu_help.pdf'; // Caminho do arquivo local

    // Define o cabeçalho de resposta para o download
    res.setHeader('Content-Disposition', 'attachment; filename=menu_help.pdf');
    res.setHeader('Content-Type', 'text/plain');

    // Envia o arquivo para o cliente
    res.sendFile(arquivo);

})

app.listen(port, () => {
    console.log(`App rodando na porta ${port}`)
})
