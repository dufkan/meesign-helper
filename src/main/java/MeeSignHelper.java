/*
Copyright 2022 Jiří Gavenda and Antonín Dufka

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;

import java.io.*;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.math.BigInteger;
import java.nio.file.Paths;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.encoders.Hex;

public class MeeSignHelper {
    private static final String KEY_PATH = "keys";
    private final X509CertificateHolder serverCertificate;
    private final PEMKeyPair serverPrivateKey;

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            return;
        }

        Security.addProvider(new BouncyCastleProvider());
        java.util.logging.Logger.getLogger("org.apache.pdfbox").setLevel(java.util.logging.Level.OFF);
        final String certificatePath = Paths.get(KEY_PATH, "meesign-ca-cert.pem").toString();
        final String privateKeyPath = Paths.get(KEY_PATH, "meesign-ca-key.pem").toString();
        MeeSignHelper helper = new MeeSignHelper(certificatePath, privateKeyPath);

        switch (args[0]) {
            case "cert":
                helper.certHandler(args[1], args[2]);
                break;

            case "sign":
                helper.signHandler(args[1]);
                break;
        }
    }

    public MeeSignHelper(String certificatePath, String privateKeyPath) throws IOException {
        PEMParser pemParser = new PEMParser(new FileReader(certificatePath));
        serverCertificate = (X509CertificateHolder) pemParser.readObject();

        pemParser = new PEMParser(new FileReader(privateKeyPath));
        serverPrivateKey = (PEMKeyPair) pemParser.readObject();
    }

    public void certHandler(String subjectName, String publicKey) throws IOException, InvalidKeySpecException, OperatorCreationException, CertificateException {
        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(issueCertificate(subjectName, publicKey));
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter jpw = new JcaPEMWriter(sw)) {
            jpw.writeObject(cert);
        }
        System.out.print(sw.toString());
    }

    public void signHandler(String documentPath) throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        StringBuilder buffer = new StringBuilder();
        String line = "";
        while(!line.equals("-----END CERTIFICATE-----")) {
            line = reader.readLine();
            buffer.append(line).append("\n");
        }
        reader = new BufferedReader(new StringReader(buffer.toString()));

        X509Certificate certificate = Utils.parseCertificates(reader)[0];
        X509CertificateHolder certificateHolder = new X509CertificateHolder(certificate.getEncoded());
        signDocument(documentPath, certificateHolder, new ExternalSigner());
    }

    X509CertificateHolder issueCertificate(String subjectName, String publicKey) throws InvalidKeySpecException, IOException, OperatorCreationException {
        byte[] pk = Utils.hexStringToByteArray(publicKey);
        ECPublicKey puk = Utils.getPublicKeyFromBytes(pk);
        Random randNum = new Random();
        BigInteger serial = new BigInteger(64, randNum);
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365 * 24 * 60 * 60 * 1000L);

        ContentSigner sigGen = new JcaContentSignerBuilder("SHA256withECDSA").build(new JcaPEMKeyConverter().getPrivateKey(serverPrivateKey.getPrivateKeyInfo()));
        X500Name subject = new X500Name("CN=" + subjectName);
        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(serverCertificate.getIssuer(), serial, notBefore, notAfter, subject, puk);

        KeyUsage usage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation);
        certGen.addExtension(Extension.keyUsage, false, usage);

        return certGen.build(sigGen);
    }

    void signDocument(String documentPath, X509CertificateHolder certHolder, ContentSigner signer) throws IOException, OperatorCreationException, CMSException, GeneralSecurityException {
        File input = new File(documentPath);

        PDDocument document = PDDocument.load(input);
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        int accessPermissions = Utils.getMDPPermission(document);
        if (accessPermissions == 1) {
            throw new IllegalStateException("No changes to the document are permitted due to DocMDP transform parameters dictionary");
        }
        PDSignature signature = new PDSignature();
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        signature.setName(certHolder.getSubject().toString());
        signature.setSignDate(Calendar.getInstance());
        signature.setLocation("MeeSign");
        signature.setReason("MeeSign");

        document.setDocumentId(0L);
        document.addSignature(signature);
        ExternalSigningSupport externalSigning = document.saveIncrementalForExternalSigning(output);

        byte[] cmsSignature = sign(externalSigning.getContent(), certHolder, signer);
        externalSigning.setSignature(cmsSignature);
        document.saveIncremental(output);
        System.out.print(Hex.toHexString(output.toByteArray()));
    }

    byte[] sign(InputStream is, X509CertificateHolder signerCertificate, ContentSigner signer) throws IOException, OperatorCreationException, CMSException, GeneralSecurityException {
        byte[] data = IOUtils.toByteArray(is);
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        CMSTypedData msg = new CMSProcessableByteArray(data);
        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().build()
        ).build(signer, signerCertificate));

        X509CertificateHolder[] certs = new X509CertificateHolder[]{signerCertificate, serverCertificate};
        JcaCertStore certStore = new JcaCertStore(Arrays.asList(certs));
        gen.addCertificates(certStore);

        CMSSignedData signedData = gen.generate(msg);

        return signedData.getEncoded();
    }
}
