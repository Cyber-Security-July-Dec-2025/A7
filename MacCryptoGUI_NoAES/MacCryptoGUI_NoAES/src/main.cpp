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
#include <QDir>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDesktopServices>
#include <QUrl>
#include <QMessageBox>

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

#include <cryptopp/dsa.h>

using namespace CryptoPP;

struct Config {
    int rsa_bits = 2048;
    int dsa_L    = 2048;
    int dsa_N    = 224;
    size_t max_preview = 16 * 1024;
};

static QString toHex(const QByteArray& data, bool uppercase=false) {
    std::string out;
    StringSource((const byte*)data.data(), data.size(), true,
        new HexEncoder(new StringSink(out), uppercase, 0));
    return QString::fromStdString(out);
}

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
        ByteQueue q;
        key.Save(q);
        std::string buf;
        buf.resize(q.CurrentSize());
        q.Get((byte*)buf.data(), buf.size());
        return writeAllFile(path, QByteArray(buf.data(), (int)buf.size()), err);
    } catch (const Exception& e) {
        if(err) *err = "Crypto++ saveKeyDER error: " + QString::fromUtf8(e.what());
        return false;
    }
}

template <class TKey>
static bool loadKeyDER(TKey& key, const QString& path, QString* err=nullptr) {
    try {
        QByteArray der = readAllFile(path, err);
        if(der.isEmpty() && QFileInfo(path).size() > 0) return false;
        ByteQueue q;
        q.Put((const byte*)der.data(), der.size());
        q.MessageEnd();
        key.Load(q);
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

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow(QWidget* parent=nullptr) : QMainWindow(parent) {
        setWindowTitle("MacCryptoGUI — RSA & DSA (No AES)");
        resize(880, 660);
        loadConfigIfPresent();

        auto* central = new QWidget(this);
        auto* root = new QVBoxLayout(central);

        auto* opRow = new QHBoxLayout();
        opBox = new QComboBox();
        opBox->addItem("RSA Key-Pair Generation");
        opBox->addItem("RSA Encrypt (Direct OAEP, small data only)");
        opBox->addItem("RSA Decrypt (Direct OAEP, small data only)");
        opBox->addItem("DSA Key-Pair Generation");
        opBox->addItem("DSA Signature Generation");
        opBox->addItem("DSA Signature Verification");
        connect(opBox, &QComboBox::currentIndexChanged, this, &MainWindow::updateVisibleFields);
        opRow->addWidget(new QLabel("Operation:"));
        opRow->addWidget(opBox, 1);
        root->addLayout(opRow);

        fileRow1 = new QHBoxLayout();
        fileLabel1 = new QLabel("Input file:");
        fileEdit1 = new QLineEdit();
        auto* browse1 = new QPushButton("Upload...");
        connect(browse1, &QPushButton::clicked, this, [this]{
            QString p = QFileDialog::getOpenFileName(this, "Choose file");
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
            QString p = QFileDialog::getOpenFileName(this, "Choose key file (.der)");
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

        outRow = new QHBoxLayout();
        outLabel = new QLabel("Output file:");
        outEdit = new QLineEdit();
        auto* browseOut = new QPushButton("Save As...");
        connect(browseOut, &QPushButton::clicked, this, [this]{
            QString p = QFileDialog::getSaveFileName(this, "Choose output path");
            if(!p.isEmpty()) outEdit->setText(p);
        });
        outRow->addWidget(outLabel);
        outRow->addWidget(outEdit, 1);
        outRow->addWidget(browseOut);
        root->addLayout(outRow);

        auto* btnRow = new QHBoxLayout();
        processBtn = new QPushButton("Process");
        connect(processBtn, &QPushButton::clicked, this, &MainWindow::process);
        openOutBtn = new QPushButton("Open Output");
        connect(openOutBtn, &QPushButton::clicked, this, &MainWindow::openOutputFolder);
        btnRow->addWidget(processBtn);
        btnRow->addWidget(openOutBtn);
        root->addLayout(btnRow);

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
        } else if(op == "RSA Encrypt (Direct OAEP, small data only)") {
            doRSADirectEncrypt();
        } else if(op == "RSA Decrypt (Direct OAEP, small data only)") {
            doRSADirectDecrypt();
        } else if(op == "DSA Key-Pair Generation") {
            doDSAKeyGen();
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
    QComboBox* opBox = nullptr;
    QHBoxLayout *fileRow1=nullptr, *fileRow2=nullptr, *fileRow3=nullptr, *outRow=nullptr;
    QLabel *fileLabel1=nullptr, *fileLabel2=nullptr, *fileLabel3=nullptr, *outLabel=nullptr;
    QLineEdit *fileEdit1=nullptr, *fileEdit2=nullptr, *fileEdit3=nullptr, *outEdit=nullptr;
    QPushButton *processBtn=nullptr, *openOutBtn=nullptr;
    QProgressBar* progress=nullptr;
    QPlainTextEdit* status=nullptr;

    Config cfg;
    QString lastOutputPath;

    void append(const QString& s) { status->appendPlainText(s); }
    void appendErr(const QString& s) { status->appendPlainText("❌ " + s); }

    void setBusy(bool busy) {
        progress->setVisible(busy);
        processBtn->setEnabled(!busy);
    }

    void setRowVisible(QHBoxLayout* row, bool vis) {
        for(int i=0;i<row->count();++i){
            QWidget* w = row->itemAt(i)->widget();
            if(w) w->setVisible(vis);
        }
    }

    void loadConfigIfPresent() {
        QFile f("config.json");
        if(!f.open(QIODevice::ReadOnly)) return;
        auto doc = QJsonDocument::fromJson(f.readAll());
        if(!doc.isObject()) return;
        auto o = doc.object();
        if(o.contains("rsa")) {
            auto r = o["rsa"].toObject();
            if(r.contains("bits")) cfg.rsa_bits = r["bits"].toInt(cfg.rsa_bits);
        }
        if(o.contains("dsa")) {
            auto d = o["dsa"].toObject();
            if(d.contains("L")) cfg.dsa_L = d["L"].toInt(cfg.dsa_L);
            if(d.contains("N")) cfg.dsa_N = d["N"].toInt(cfg.dsa_N);
        }
        if(o.contains("io")) {
            auto i = o["io"].toObject();
            if(i.contains("max_preview_bytes")) cfg.max_preview = (size_t)i["max_preview_bytes"].toInt((int)cfg.max_preview);
        }
    }

    void updateVisibleFields() {
        const QString op = opBox->currentText();
        setRowVisible(fileRow1, false);
        setRowVisible(fileRow2, false);
        setRowVisible(fileRow3, false);
        setRowVisible(outRow,  false);

        if(op == "RSA Key-Pair Generation") {
            setRowVisible(outRow, true);
            outLabel->setText("Save keys into folder:");
            outEdit->setPlaceholderText("Choose a folder (RSA keys will be written there)");
        } else if(op == "RSA Encrypt (Direct OAEP, small data only)") {
            setRowVisible(fileRow1, true); fileLabel1->setText("Plaintext file:");
            setRowVisible(fileRow2, true); fileLabel2->setText("RSA public key (.der):");
            setRowVisible(outRow, true);   outLabel->setText("Cipher output file:");
        } else if(op == "RSA Decrypt (Direct OAEP, small data only)") {
            setRowVisible(fileRow1, true); fileLabel1->setText("Cipher input file:");
            setRowVisible(fileRow2, true); fileLabel2->setText("RSA private key (.der):");
            setRowVisible(outRow, true);   outLabel->setText("Plaintext output file:");
        } else if(op == "DSA Key-Pair Generation") {
            setRowVisible(outRow, true);
            outLabel->setText("Save keys into folder:");
            outEdit->setPlaceholderText("Choose a folder (DSA keys will be written there)");
        } else if(op == "DSA Signature Generation") {
            setRowVisible(fileRow1, true); fileLabel1->setText("Message file:");
            setRowVisible(fileRow2, true); fileLabel2->setText("DSA private key (.der):");
            setRowVisible(outRow, true);   outLabel->setText("Signature output file:");
        } else if(op == "DSA Signature Verification") {
            setRowVisible(fileRow1, true); fileLabel1->setText("Message file:");
            setRowVisible(fileRow2, true); fileLabel2->setText("DSA public key (.der):");
            setRowVisible(fileRow3, true); fileLabel3->setText("Signature file:");
        }
    }

    // ----- Crypto ops -----

    void doRSAKeyGen() {
        QString folder = outEdit->text().trimmed();
        if(folder.isEmpty()) {
            folder = QFileDialog::getExistingDirectory(this, "Choose folder for RSA keys");
            if(folder.isEmpty()) { appendErr("No output folder selected."); return; }
            outEdit->setText(folder);
        }
        QDir dir(folder);
        if(!dir.exists()) { appendErr("Folder does not exist: " + folder); return; }

        setBusy(true); QApplication::processEvents();
        try {
            AutoSeededRandomPool rng;
            InvertibleRSAFunction params;
            params.Initialize(rng, (unsigned int)cfg.rsa_bits);
            RSA::PrivateKey priv(params);
            RSA::PublicKey  pub(params);

            QString privPath = dir.filePath("rsa_private.der");
            QString pubPath  = dir.filePath("rsa_public.der");
            QString err;
            if(!saveKeyDER(priv, privPath, &err)) { setBusy(false); appendErr(err); return; }
            if(!saveKeyDER(pub,  pubPath,  &err)) { setBusy(false); appendErr(err); return; }

            append("✅ RSA key-pair generated:");
            append("  • Private: " + privPath);
            append("  • Public : " + pubPath);
            lastOutputPath = privPath;
        } catch(const Exception& e) {
            appendErr("RSA keygen error: " + QString::fromUtf8(e.what()));
        }
        setBusy(false);
    }

    void doRSADirectEncrypt() {
        const QString inPath  = fileEdit1->text().trimmed();
        const QString pubPath = fileEdit2->text().trimmed();
        QString outPath = outEdit->text().trimmed();

        if(inPath.isEmpty() || pubPath.isEmpty()) { appendErr("Select plaintext file and RSA public key."); return; }
        if(outPath.isEmpty()) {
            outPath = QFileDialog::getSaveFileName(this, "Save RSA-OAEP ciphertext", QDir::homePath()+"/cipher.rsa");
            if(outPath.isEmpty()) { appendErr("No output selected."); return; }
            outEdit->setText(outPath);
        }

        QByteArray plain = readAllFile(inPath);
        if(plain.isEmpty() && QFileInfo(inPath).size() > 0) { appendErr("Failed to read input."); return; }

        RSA::PublicKey pub;
        {
            QString err; if(!loadKeyDER(pub, pubPath, &err)) { appendErr(err); return; }
        }

        setBusy(true); QApplication::processEvents();
        try {
            AutoSeededRandomPool rng;
            RSAES<OAEP<SHA256>>::Encryptor enc(pub);

            size_t maxPlain = enc.FixedMaxPlaintextLength(); // k - 2*hLen - 2
            if((size_t)plain.size() > maxPlain) {
                setBusy(false);
                appendErr(QString("Plaintext too large for direct RSA-OAEP. Max for this key is %1 bytes.").arg(maxPlain));
                return;
            }

            std::string cipher;
            StringSource ss((const byte*)plain.data(), plain.size(), true,
                new PK_EncryptorFilter(rng, enc, new StringSink(cipher))
            );

            if(!writeAllFile(outPath, QByteArray(cipher.data(), (int)cipher.size()))) {
                setBusy(false); appendErr("Failed to write ciphertext."); return;
            }

            append("✅ RSA Encrypt (direct OAEP) complete.");
            append("  • Output: " + outPath);
            if(cipher.size() <= (int)cfg.max_preview) {
                append("---- Cipher (HEX) ----");
                append(toHex(QByteArray(cipher.data(), (int)cipher.size())));
            }
            lastOutputPath = outPath;
        } catch(const Exception& e) {
            appendErr("RSA direct encrypt error: " + QString::fromUtf8(e.what()));
        }
        setBusy(false);
    }

    void doRSADirectDecrypt() {
        const QString inPath   = fileEdit1->text().trimmed();
        const QString privPath = fileEdit2->text().trimmed();
        QString outPath = outEdit->text().trimmed();

        if(inPath.isEmpty() || privPath.isEmpty()) { appendErr("Select ciphertext file and RSA private key."); return; }
        if(outPath.isEmpty()) {
            outPath = QFileDialog::getSaveFileName(this, "Save plaintext", QDir::homePath()+"/plain.out");
            if(outPath.isEmpty()) { appendErr("No output selected."); return; }
            outEdit->setText(outPath);
        }

        QByteArray cipher = readAllFile(inPath);
        if(cipher.isEmpty() && QFileInfo(inPath).size() > 0) { appendErr("Failed to read input."); return; }

        RSA::PrivateKey priv;
        {
            QString err; if(!loadKeyDER(priv, privPath, &err)) { appendErr(err); return; }
        }

        setBusy(true); QApplication::processEvents();
        try {
            AutoSeededRandomPool rng;
            RSAES<OAEP<SHA256>>::Decryptor dec(priv);

            const size_t need = dec.FixedCiphertextLength(); // modulus byte length (k)
            if((size_t)cipher.size() != need) {
                setBusy(false);
                appendErr(QString("Unexpected ciphertext length: got %1, expected %2 bytes for this key.")
                          .arg(cipher.size()).arg(need));
                return;
            }

            std::string recovered;
            recovered.resize(dec.FixedMaxPlaintextLength());
            DecodingResult res = dec.Decrypt(
                rng,
                (const byte*)cipher.data(), cipher.size(),
                (byte*)recovered.data()
            );
            if(!res.isValidCoding) {
                setBusy(false); appendErr("RSA OAEP decryption failed (invalid coding)."); return;
            }
            recovered.resize(res.messageLength);

            if(!writeAllFile(outPath, QByteArray(recovered.data(), (int)recovered.size()))) {
                setBusy(false); appendErr("Failed to write plaintext output."); return;
            }

            append("✅ RSA Decrypt (direct OAEP) complete.");
            append("  • Output: " + outPath);
            if(recovered.size() <= (int)cfg.max_preview) {
                append("---- Plaintext (HEX) ----");
                append(toHex(QByteArray(recovered.data(), (int)recovered.size())));
            }
            lastOutputPath = outPath;
        } catch(const Exception& e) {
            appendErr("RSA direct decrypt error: " + QString::fromUtf8(e.what()));
        }
        setBusy(false);
    }

    void doDSAKeyGen() {
        QString folder = outEdit->text().trimmed();
        if(folder.isEmpty()) {
            folder = QFileDialog::getExistingDirectory(this, "Choose folder for DSA keys");
            if(folder.isEmpty()) { appendErr("No output folder selected."); return; }
            outEdit->setText(folder);
        }
        QDir dir(folder);
        if(!dir.exists()) { appendErr("Folder does not exist: " + folder); return; }

        setBusy(true); QApplication::processEvents();
        try {
            AutoSeededRandomPool rng;
            DSA::PrivateKey priv;
            priv.GenerateRandomWithKeySize(rng, (unsigned int)cfg.dsa_L);
            if(!priv.Validate(rng, 3)) { setBusy(false); appendErr("DSA private key validation failed."); return; }

            DSA::PublicKey pub;
            pub.AssignFrom(priv);
            if(!pub.Validate(rng, 3)) { setBusy(false); appendErr("DSA public key validation failed."); return; }

            QString privPath = dir.filePath("dsa_private.der");
            QString pubPath  = dir.filePath("dsa_public.der");
            QString err;
            if(!saveKeyDER(priv, privPath, &err)) { setBusy(false); appendErr(err); return; }
            if(!saveKeyDER(pub,  pubPath,  &err)) { setBusy(false); appendErr(err); return; }

            append("✅ DSA key-pair generated:");
            append("  • Private: " + privPath);
            append("  • Public : " + pubPath);
            lastOutputPath = privPath;
        } catch(const Exception& e) {
            appendErr("DSA keygen error: " + QString::fromUtf8(e.what()));
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
            QString err; if(!loadKeyDER(priv, privPath, &err)) { appendErr(err); return; }
        }

        setBusy(true); QApplication::processEvents();
        try {
            AutoSeededRandomPool rng;
            DSA::Signer signer(priv); // SHA-1 internally by default in Crypto++
            std::string sig;
            StringSource ss((const byte*)msg.data(), msg.size(), true,
                new SignerFilter(rng, signer, new StringSink(sig))
            );
            if(!writeAllFile(outPath, QByteArray(sig.data(), (int)sig.size()))) {
                setBusy(false); appendErr("Failed to write signature."); return;
            }
            append("✅ DSA signature generated.");
            append("  • Signature file: " + outPath);
            if(sig.size() <= (int)cfg.max_preview) {
                append("---- Signature (HEX) ----");
                append(toHex(QByteArray(sig.data(), (int)sig.size())));
            }
            lastOutputPath = outPath;
        } catch(const Exception& e) {
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
            QString err; if(!loadKeyDER(pub, pubPath, &err)) { appendErr(err); return; }
        }

        setBusy(true); QApplication::processEvents();
        try {
            DSA::Verifier verifier(pub);
            bool ok = verifier.VerifyMessage(
                (const byte*)msg.data(), msg.size(),
                (const byte*)sig.data(), sig.size()
            );
            if(ok) append("✅ DSA verification: VALID");
            else   append("❌ DSA verification: INVALID");
        } catch(const Exception& e) {
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
