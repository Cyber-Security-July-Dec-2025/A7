#include <QApplication>
#include <QMainWindow>
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QComboBox>
#include <QLineEdit>
#include <QLabel>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QFileDialog>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMessageBox>
#include <QDir>
#include <QStandardPaths>
#include <QDesktopServices>
#include <QUrl>

#include <fstream>
#include <sstream>
#include <vector>
#include <cstdint>
#include <cstring>

// Crypto++
#include <cryptopp/osrng.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/queue.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/secblock.h>

#include <cryptopp/rsa.h>
#include <cryptopp/oaep.h>
#include <cryptopp/sha.h>

#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>

#include <cryptopp/dsa.h>

using namespace CryptoPP;

struct HybridHeader {
    char     magic[8];   // "RGHYBRID"
    uint32_t version;
    uint32_t encKeyLen;
    uint32_t ivLen;
    uint64_t cipherLen;
};

static const char* MAGIC = "RGHYBRID";
static const uint32_t VERSION = 1;

// Simple config holder
struct Config {
    int rsa_bits = 2048;
    QString rsa_padding = "OAEP-SHA256";
    int aes_key_bits = 256;
    int aes_iv_len = 12;
    int dsa_L = 2048;
    int dsa_N = 224;
    QString dsa_hash = "SHA1";
    size_t max_preview = 16 * 1024;
};

// Utilities
static QByteArray readAllFile(const QString& path, QString* err=nullptr) {
    QFile f(path);
    if(!f.open(QIODevice::ReadOnly)) {
        if(err) *err = "Failed to open file: " + path + " (" + f.errorString() + ")";
        return {};
    }
    return f.readAll();
}

static bool writeAllFile(const QString& path, const QByteArray& data, QString* err=nullptr) {
    QFile f(path);
    if(!f.open(QIODevice::WriteOnly)) {
        if(err) *err = "Failed to write file: " + path + " (" + f.errorString() + ")";
        return false;
    }
    if(f.write(data) != data.size()) {
        if(err) *err = "Short write for file: " + path;
        return false;
    }
    return true;
}

template <class TKey>
static bool saveKeyDER(const TKey& key, const QString& path, QString* err=nullptr) {
    try {
        ByteQueue queue;
        key.Save(queue);
        std::string out;
        out.resize(queue.CurrentSize());
        queue.Get((byte*)out.data(), out.size());
        return writeAllFile(path, QByteArray(out.data(), (int)out.size()), err);
    } catch (const Exception& e) {
        if(err) *err = "Crypto++ saveKeyDER error: " + QString::fromUtf8(e.what());
        return false;
    }
}

template <class TKey>
static bool loadKeyDER(TKey& key, const QString& path, QString* err=nullptr) {
    try {
        QByteArray der = readAllFile(path, err);
        if(der.isEmpty()) return false;
        ByteQueue q;
        q.Put((const byte*)der.data(), der.size());
        q.MessageEnd();
        key.Load(q);
        // Optionally validate (needs RNG)
        AutoSeededRandomPool rng;
        if(!key.Validate(rng, 3)) {
            if(err) *err = "Key validation failed for: " + path;
            return false;
        }
        return true;
    } catch (const Exception& e) {
        if(err) *err = "Crypto++ loadKeyDER error: " + QString::fromUtf8(e.what());
        return false;
    }
}

// Convert bytes to HEX (uppercase, no spaces)
static QString toHex(const QByteArray& data) {
    std::string out;
    StringSource((const byte*)data.data(), data.size(), true,
        new HexEncoder(new StringSink(out), false /*uppercase? true*/, 0 /*group*/));
    return QString::fromStdString(out);
}

// GUI MainWindow
class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow(QWidget* parent=nullptr) : QMainWindow(parent) {
        setWindowTitle("MacCryptoGUI — RSA & DSA (Crypto++)");
        resize(820, 600);
        loadConfig();

        auto* central = new QWidget(this);
        auto* root = new QVBoxLayout(central);

        // Operation chooser
        auto* opRow = new QHBoxLayout();
        opBox = new QComboBox();
        opBox->addItem("RSA Key-Pair Generation");
        opBox->addItem("RSA Encrypt (Hybrid AES-GCM)");
        opBox->addItem("RSA Decrypt (Hybrid AES-GCM)");
        opBox->addItem("DSA Signature Generation");
        opBox->addItem("DSA Signature Verification");
        connect(opBox, &QComboBox::currentIndexChanged, this, &MainWindow::updateVisibleFields);
        opRow->addWidget(new QLabel("Operation:"));
        opRow->addWidget(opBox, 1);
        root->addLayout(opRow);

        // File pickers (generic)
        fileRow1 = new QHBoxLayout();
        fileLabel1 = new QLabel("Input file:");
        fileEdit1 = new QLineEdit();
        auto* browse1 = new QPushButton("Upload...");
        connect(browse1, &QPushButton::clicked, this, [this]{
            QString p = QFileDialog::getOpenFileName(this, "Choose input file");
            if(!p.isEmpty()) fileEdit1->setText(p);
        });
        fileRow1->addWidget(fileLabel1);
        fileRow1->addWidget(fileEdit1, 1);
        fileRow1->addWidget(browse1);
        root->addLayout(fileRow1);

        fileRow2 = new QHBoxLayout();
        fileLabel2 = new QLabel("Key file:");
        fileEdit2 = new QLineEdit();
        auto* browse2 = new QPushButton("Upload...");
        connect(browse2, &QPushButton::clicked, this, [this]{
            QString p = QFileDialog::getOpenFileName(this, "Choose key file");
            if(!p.isEmpty()) fileEdit2->setText(p);
        });
        fileRow2->addWidget(fileLabel2);
        fileRow2->addWidget(fileEdit2, 1);
        fileRow2->addWidget(browse2);
        root->addLayout(fileRow2);

        fileRow3 = new QHBoxLayout();
        fileLabel3 = new QLabel("Signature file:");
        fileEdit3 = new QLineEdit();
        auto* browse3 = new QPushButton("Upload...");
        connect(browse3, &QPushButton::clicked, this, [this]{
            QString p = QFileDialog::getOpenFileName(this, "Choose signature file");
            if(!p.isEmpty()) fileEdit3->setText(p);
        });
        fileRow3->addWidget(fileLabel3);
        fileRow3->addWidget(fileEdit3, 1);
        fileRow3->addWidget(browse3);
        root->addLayout(fileRow3);

        // Output path
        outRow = new QHBoxLayout();
        outLabel = new QLabel("Output file:");
        outEdit = new QLineEdit();
        auto* browseOut = new QPushButton("Save As...");
        connect(browseOut, &QPushButton::clicked, this, [this]{
            QString p = QFileDialog::getSaveFileName(this, "Choose output save path");
            if(!p.isEmpty()) outEdit->setText(p);
        });
        outRow->addWidget(outLabel);
        outRow->addWidget(outEdit, 1);
        outRow->addWidget(browseOut);
        root->addLayout(outRow);

        // Buttons
        auto* btnRow = new QHBoxLayout();
        processBtn = new QPushButton("Process");
        connect(processBtn, &QPushButton::clicked, this, &MainWindow::process);
        openOutBtn = new QPushButton("Open Output");
        connect(openOutBtn, &QPushButton::clicked, this, &MainWindow::openOutputFolder);
        btnRow->addWidget(processBtn);
        btnRow->addWidget(openOutBtn);
        root->addLayout(btnRow);

        // Progress + Status
        progress = new QProgressBar();
        progress->setRange(0, 0);
        progress->setVisible(false);
        root->addWidget(progress);

        status = new QPlainTextEdit();
        status->setReadOnly(true);
        root->addWidget(new QLabel("Status / Output Preview:"));
        root->addWidget(status, 1);

        setCentralWidget(central);
        updateVisibleFields();
    }

private slots:
    void process() {
        status->clear();
        lastOutputPath.clear();

        const QString op = opBox->currentText();
        if(op == "RSA Key-Pair Generation") {
            doRSAKeyGen();
        } else if(op == "RSA Encrypt (Hybrid AES-GCM)") {
            doRSAEncryptHybrid();
        } else if(op == "RSA Decrypt (Hybrid AES-GCM)") {
            doRSADecryptHybrid();
        } else if(op == "DSA Signature Generation") {
            doDSASign();
        } else if(op == "DSA Signature Verification") {
            doDSAVerify();
        } else {
            appendErr("Unknown operation.");
        }
    }

    void openOutputFolder() {
        if(lastOutputPath.isEmpty()) {
            QMessageBox::information(this, "Open Output", "No output yet.");
            return;
        }
        QFileInfo fi(lastOutputPath);
        QDesktopServices::openUrl(QUrl::fromLocalFile(fi.absolutePath()));
    }

private:
    // Widgets
    QComboBox* opBox = nullptr;
    QHBoxLayout *fileRow1=nullptr, *fileRow2=nullptr, *fileRow3=nullptr, *outRow=nullptr;
    QLabel *fileLabel1=nullptr, *fileLabel2=nullptr, *fileLabel3=nullptr, *outLabel=nullptr;
    QLineEdit *fileEdit1=nullptr, *fileEdit2=nullptr, *fileEdit3=nullptr, *outEdit=nullptr;
    QPushButton *processBtn=nullptr, *openOutBtn=nullptr;
    QPlainTextEdit* status=nullptr;
    QProgressBar* progress=nullptr;

    // State
    Config cfg;
    QString lastOutputPath;

    void loadConfig() {
        QString cfgPath = QDir::current().absoluteFilePath("config.json");
        QFile f(cfgPath);
        if(f.open(QIODevice::ReadOnly)) {
            auto doc = QJsonDocument::fromJson(f.readAll());
            if(doc.isObject()) {
                auto o = doc.object();
                if(o.contains("rsa")) {
                    auto r = o["rsa"].toObject();
                    if(r.contains("bits")) cfg.rsa_bits = r["bits"].toInt(cfg.rsa_bits);
                    if(r.contains("padding")) cfg.rsa_padding = r["padding"].toString(cfg.rsa_padding);
                }
                if(o.contains("aes")) {
                    auto a = o["aes"].toObject();
                    if(a.contains("key_bits")) cfg.aes_key_bits = a["key_bits"].toInt(cfg.aes_key_bits);
                    if(a.contains("iv_len")) cfg.aes_iv_len = a["iv_len"].toInt(cfg.aes_iv_len);
                }
                if(o.contains("dsa")) {
                    auto d = o["dsa"].toObject();
                    if(d.contains("L")) cfg.dsa_L = d["L"].toInt(cfg.dsa_L);
                    if(d.contains("N")) cfg.dsa_N = d["N"].toInt(cfg.dsa_N);
                    if(d.contains("hash")) cfg.dsa_hash = d["hash"].toString(cfg.dsa_hash);
                }
                if(o.contains("io")) {
                    auto i = o["io"].toObject();
                    if(i.contains("max_preview_bytes")) cfg.max_preview = (size_t)i["max_preview_bytes"].toInt((int)cfg.max_preview);
                }
            }
        }
    }

    void updateVisibleFields() {
        const QString op = opBox->currentText();
        // Hide all first
        setRowVisible(fileRow1, false);
        setRowVisible(fileRow2, false);
        setRowVisible(fileRow3, false);
        setRowVisible(outRow,  false);

        if(op == "RSA Key-Pair Generation") {
            setRowVisible(outRow, true);
            outLabel->setText("Save keys into folder:");
            outEdit->setPlaceholderText("Choose a folder (keys will be written there)");
        } else if(op == "RSA Encrypt (Hybrid AES-GCM)") {
            setRowVisible(fileRow1, true);
            fileLabel1->setText("Plaintext file:");
            setRowVisible(fileRow2, true);
            fileLabel2->setText("RSA public key (.der):");
            setRowVisible(outRow, true);
            outLabel->setText("Cipher output file:");
        } else if(op == "RSA Decrypt (Hybrid AES-GCM)") {
            setRowVisible(fileRow1, true);
            fileLabel1->setText("Cipher input file:");
            setRowVisible(fileRow2, true);
            fileLabel2->setText("RSA private key (.der):");
            setRowVisible(outRow, true);
            outLabel->setText("Plaintext output file:");
        } else if(op == "DSA Signature Generation") {
            setRowVisible(fileRow1, true);
            fileLabel1->setText("Message file:");
            setRowVisible(fileRow2, true);
            fileLabel2->setText("DSA private key (.der):");
            setRowVisible(outRow, true);
            outLabel->setText("Signature output file:");
        } else if(op == "DSA Signature Verification") {
            setRowVisible(fileRow1, true);
            fileLabel1->setText("Message file:");
            setRowVisible(fileRow2, true);
            fileLabel2->setText("DSA public key (.der):");
            setRowVisible(fileRow3, true);
            fileLabel3->setText("Signature file:");
        }
    }

    void setRowVisible(QHBoxLayout* row, bool vis) {
        for (int i = 0; i < row->count(); ++i) {
            QWidget* w = row->itemAt(i)->widget();
            if(w) w->setVisible(vis);
        }
    }

    void setBusy(bool busy) {
        progress->setVisible(busy);
        processBtn->setEnabled(!busy);
    }

    void append(const QString& s) {
        status->appendPlainText(s);
    }
    void appendErr(const QString& s) {
        status->appendPlainText("❌ " + s);
    }

    // --- Operations ---

    void doRSAKeyGen() {
        // OutEdit should point to a folder
        QString folder = outEdit->text().trimmed();
        if(folder.isEmpty()) {
            folder = QFileDialog::getExistingDirectory(this, "Choose folder for keys");
            if(folder.isEmpty()) { appendErr("No output folder selected."); return; }
            outEdit->setText(folder);
        }
        QDir dir(folder);
        if(!dir.exists()) {
            appendErr("Folder does not exist: " + folder);
            return;
        }

        setBusy(true);
        QApplication::processEvents();
        try {
            AutoSeededRandomPool rng;
            InvertibleRSAFunction params;
            params.Initialize(rng, (unsigned int)cfg.rsa_bits);
            RSA::PrivateKey privateKey(params);
            RSA::PublicKey publicKey(params);

            QString privPath = dir.filePath("rsa_private.der");
            QString pubPath  = dir.filePath("rsa_public.der");

            QString err;
            if(!saveKeyDER(privateKey, privPath, &err)) { setBusy(false); appendErr(err); return; }
            if(!saveKeyDER(publicKey,  pubPath,  &err)) { setBusy(false); appendErr(err); return; }

            append("✅ RSA key-pair generated:");
            append("  • Private: " + privPath);
            append("  • Public : " + pubPath);
            lastOutputPath = privPath;
        } catch (const Exception& e) {
            appendErr("RSA keygen error: " + QString::fromUtf8(e.what()));
        }
        setBusy(false);
    }

    void doRSAEncryptHybrid() {
        const QString inPath  = fileEdit1->text().trimmed();
        const QString pubPath = fileEdit2->text().trimmed();
        QString outPath = outEdit->text().trimmed();
        if(inPath.isEmpty() || pubPath.isEmpty()) { appendErr("Select plaintext file and RSA public key."); return; }
        if(outPath.isEmpty()) {
            outPath = QFileDialog::getSaveFileName(this, "Save ciphertext file", QDir::homePath()+"/cipher.bin");
            if(outPath.isEmpty()) { appendErr("No output selected."); return; }
            outEdit->setText(outPath);
        }

        QByteArray plain = readAllFile(inPath);
        if(plain.isEmpty() && QFileInfo(inPath).size() > 0) { appendErr("Failed to read input."); return; }

        RSA::PublicKey pub;
        {
            QString err;
            if(!loadKeyDER(pub, pubPath, &err)) { appendErr(err); return; }
        }

        setBusy(true);
        QApplication::processEvents();
        try {
            AutoSeededRandomPool rng;

            // Generate AES key & IV
            const size_t keyLen = (size_t)cfg.aes_key_bits / 8;
            const size_t ivLen  = (size_t)cfg.aes_iv_len;
            SecByteBlock aesKey(keyLen), iv(ivLen);
            rng.GenerateBlock(aesKey, aesKey.size());
            rng.GenerateBlock(iv, iv.size());

            // Encrypt AES key with RSA OAEP (SHA-256)
            std::string encKey;
            {
                RSAES<OAEP<SHA256>>::Encryptor enc(pub);
                StringSource ss(aesKey, aesKey.size(), true,
                    new PK_EncryptorFilter(rng, enc, new StringSink(encKey))
                );
            }

            // AES-GCM encrypt whole file (cipher + tag concatenated)
            std::string cipherAndTag;
            {
                GCM<AES>::Encryption gcm;
                gcm.SetKeyWithIV(aesKey, aesKey.size(), iv, iv.size());
                StringSource ss((const byte*)plain.data(), plain.size(), true,
                    new AuthenticatedEncryptionFilter(
                        gcm,
                        new StringSink(cipherAndTag), false /*putAAD*/, 16 /*tag size*/
                    )
                );
            }

            // Write header + parts
            HybridHeader hdr{};
            std::memset(&hdr, 0, sizeof(hdr));
            std::memcpy(hdr.magic, MAGIC, 8);
            hdr.version   = VERSION;
            hdr.encKeyLen = (uint32_t)encKey.size();
            hdr.ivLen     = (uint32_t)iv.size();
            hdr.cipherLen = (uint64_t)cipherAndTag.size();

            std::ofstream ofs(outPath.toStdString(), std::ios::binary);
            if(!ofs) { setBusy(false); appendErr("Failed to open output file for writing."); return; }
            ofs.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));
            ofs.write(reinterpret_cast<const char*>(encKey.data()), encKey.size());
            ofs.write(reinterpret_cast<const char*>(iv.data()), iv.size());
            ofs.write(cipherAndTag.data(), cipherAndTag.size());
            ofs.close();

            append("✅ RSA Encrypt (hybrid) complete.");
            append("  • Output: " + outPath);
            lastOutputPath = outPath;
        } catch (const Exception& e) {
            appendErr("RSA encrypt error: " + QString::fromUtf8(e.what()));
        }
        setBusy(false);
    }

    void doRSADecryptHybrid() {
        const QString inPath  = fileEdit1->text().trimmed();
        const QString privPath = fileEdit2->text().trimmed();
        QString outPath = outEdit->text().trimmed();
        if(inPath.isEmpty() || privPath.isEmpty()) { appendErr("Select ciphertext file and RSA private key."); return; }
        if(outPath.isEmpty()) {
            outPath = QFileDialog::getSaveFileName(this, "Save plaintext file", QDir::homePath()+"/plain.out");
            if(outPath.isEmpty()) { appendErr("No output selected."); return; }
            outEdit->setText(outPath);
        }

        // Read entire container
        QFile f(inPath);
        if(!f.open(QIODevice::ReadOnly)) { appendErr("Failed to open input: " + f.errorString()); return; }
        QByteArray all = f.readAll();
        f.close();
        if(all.size() < (int)sizeof(HybridHeader)) { appendErr("Input too small/not a hybrid file."); return; }

        HybridHeader hdr{};
        std::memcpy(&hdr, all.data(), sizeof(hdr));
        if(std::memcmp(hdr.magic, MAGIC, 8) != 0 || hdr.version != VERSION) {
            appendErr("Invalid header/magic/version.");
            return;
        }

        size_t offset = sizeof(hdr);
        const size_t need = (size_t)hdr.encKeyLen + (size_t)hdr.ivLen + (size_t)hdr.cipherLen;
        if(all.size() < (int)(offset + need)) { appendErr("Corrupt container (lengths mismatch)."); return; }

        QByteArray encKey = all.mid((int)offset, (int)hdr.encKeyLen);
        offset += hdr.encKeyLen;
        QByteArray iv = all.mid((int)offset, (int)hdr.ivLen);
        offset += hdr.ivLen;
        QByteArray cipherAndTag = all.mid((int)offset, (int)hdr.cipherLen);
        offset += hdr.cipherLen;

        RSA::PrivateKey priv;
        {
            QString err;
            if(!loadKeyDER(priv, privPath, &err)) { appendErr(err); return; }
        }

        setBusy(true);
        QApplication::processEvents();
        try {
            AutoSeededRandomPool rng;

            // Decrypt AES key with RSA OAEP (SHA-256)
            SecByteBlock aesKey((size_t)cfg.aes_key_bits/8);
            {
                RSAES<OAEP<SHA256>>::Decryptor dec(priv);
                // Determine recovered length
                DecodingResult result;
                std::string recovered;
                recovered.resize(dec.FixedMaxPlaintextLength());
                result = dec.Decrypt(rng, (const byte*)encKey.data(), encKey.size(), (byte*)recovered.data());
                if(!result.isValidCoding) {
                    setBusy(false);
                    appendErr("RSA OAEP decryption failed (invalid coding).");
                    return;
                }
                recovered.resize(result.messageLength);
                if(recovered.size() != aesKey.size()) {
                    setBusy(false);
                    appendErr("Unexpected AES key size in container.");
                    return;
                }
                std::memcpy(aesKey.data(), recovered.data(), aesKey.size());
            }

            // Decrypt AES-GCM (cipher + tag at end)
            std::string recoveredPlain;
            {
                GCM<AES>::Decryption gcm;
                gcm.SetKeyWithIV(aesKey, aesKey.size(), (const byte*)iv.data(), iv.size());
                AuthenticatedDecryptionFilter df(
                    gcm, new StringSink(recoveredPlain),
                    AuthenticatedDecryptionFilter::DEFAULT_FLAGS /*MAC_AT_END is default*/,
                    16 /*tag size*/
                );
                StringSource ss((const byte*)cipherAndTag.data(), cipherAndTag.size(), true, new Redirector(df));
                if(!df.GetLastResult()) {
                    setBusy(false);
                    appendErr("AES-GCM authentication failed (bad tag).");
                    return;
                }
            }

            if(!writeAllFile(outPath, QByteArray(recoveredPlain.data(), (int)recoveredPlain.size()))) {
                setBusy(false);
                appendErr("Failed to write plaintext output.");
                return;
            }

            append("✅ RSA Decrypt (hybrid) complete.");
            append("  • Output: " + outPath);
            if((size_t)recoveredPlain.size() <= cfg.max_preview) {
                append("---- Plaintext Preview (HEX) ----");
                append(toHex(QByteArray(recoveredPlain.data(), (int)recoveredPlain.size())));
            } else {
                append("Plaintext is large; saved to file.");
            }
            lastOutputPath = outPath;
        } catch (const Exception& e) {
            appendErr("RSA decrypt error: " + QString::fromUtf8(e.what()));
        }
        setBusy(false);
    }

    void doDSASign() {
        const QString msgPath  = fileEdit1->text().trimmed();
        const QString privPath = fileEdit2->text().trimmed();
        QString outPath = outEdit->text().trimmed();
        if(msgPath.isEmpty() || privPath.isEmpty()) { appendErr("Select message file and DSA private key."); return; }
        if(outPath.isEmpty()) {
            outPath = QFileDialog::getSaveFileName(this, "Save signature file", QDir::homePath()+"/message.sig");
            if(outPath.isEmpty()) { appendErr("No output selected."); return; }
            outEdit->setText(outPath);
        }

        QByteArray msg = readAllFile(msgPath);
        if(msg.isEmpty() && QFileInfo(msgPath).size() > 0) { appendErr("Failed to read message."); return; }

        DSA::PrivateKey priv;
        {
            QString err;
            if(!loadKeyDER(priv, privPath, &err)) { appendErr(err); return; }
        }

        setBusy(true);
        QApplication::processEvents();
        try {
            AutoSeededRandomPool rng;
            DSA::Signer signer(priv); // Crypto++'s DSA uses SHA-1 internally by default
            std::string signature;
            StringSource ss((const byte*)msg.data(), msg.size(), true,
                new SignerFilter(rng, signer, new StringSink(signature))
            );
            if(!writeAllFile(outPath, QByteArray(signature.data(), (int)signature.size()))) {
                setBusy(false);
                appendErr("Failed to write signature.");
                return;
            }
            append("✅ DSA signature generated.");
            append("  • Signature file: " + outPath);
            if(signature.size() <= (int)cfg.max_preview) {
                append("---- Signature (HEX) ----");
                append(toHex(QByteArray(signature.data(), (int)signature.size())));
            }
            lastOutputPath = outPath;
        } catch (const Exception& e) {
            appendErr("DSA sign error: " + QString::fromUtf8(e.what()));
        }
        setBusy(false);
    }

    void doDSAVerify() {
        const QString msgPath  = fileEdit1->text().trimmed();
        const QString pubPath  = fileEdit2->text().trimmed();
        const QString sigPath  = fileEdit3->text().trimmed();
        if(msgPath.isEmpty() || pubPath.isEmpty() || sigPath.isEmpty()) {
            appendErr("Select message file, DSA public key, and signature file.");
            return;
        }

        QByteArray msg = readAllFile(msgPath);
        if(msg.isEmpty() && QFileInfo(msgPath).size() > 0) { appendErr("Failed to read message."); return; }
        QByteArray sig = readAllFile(sigPath);
        if(sig.isEmpty() && QFileInfo(sigPath).size() > 0) { appendErr("Failed to read signature."); return; }

        DSA::PublicKey pub;
        {
            QString err;
            if(!loadKeyDER(pub, pubPath, &err)) { appendErr(err); return; }
        }

        setBusy(true);
        QApplication::processEvents();
        try {
            DSA::Verifier verifier(pub);
            bool ok = verifier.VerifyMessage(
                (const byte*)msg.data(), msg.size(),
                (const byte*)sig.data(), sig.size()
            );
            if(ok) {
                append("✅ DSA verification: VALID");
            } else {
                append("❌ DSA verification: INVALID");
            }
        } catch (const Exception& e) {
            appendErr("DSA verify error: " + QString::fromUtf8(e.what()));
        }
        setBusy(false);
    }
};



int main(int argc, char** argv) {
    QApplication app(argc, argv);
    MainWindow w;
    w.show();
    return app.exec();
}

// #include "moc_main.cpp"  // Not actually needed because no Q_OBJECT subclasses with signals/slots defined outside, but harmless.
#include "main.moc"
