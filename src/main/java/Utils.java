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
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;

import java.io.*;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;


public class Utils {

    /**
     * Transforms byte array containing ECDSA P-256 public key to ECPublicKey object
     * @param pubKey 65 byte array with x,y ECDSA p-256 public key starting with 0x04 byte
     * @return ECPublicKey public key
     * @throws InvalidKeySpecException invalid input key
     */
    public static ECPublicKey getPublicKeyFromBytes(byte[] pubKey) throws InvalidKeySpecException {

        byte[] head = Base64.getDecoder().decode("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE".getBytes());
        byte[] pk = new byte[pubKey.length + head.length - 1];
        System.arraycopy(head, 0, pk, 0, head.length);
        System.arraycopy(pubKey, 1, pk, head.length, pubKey.length - 1);
        KeyFactory eckf;
        try {
            eckf = KeyFactory.getInstance("EC");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("EC key factory not present in runtime");
        }
        X509EncodedKeySpec ecpks = new X509EncodedKeySpec(pk);
        return (ECPublicKey) eckf.generatePublic(ecpks);
    }

    /**
     * Transforms raw ECDSA signature to DER format
     * @param signature raw (r,s) ECDSA signature
     * @return DER formatted ECDSA signature
     */
    public static byte[] formatSignature(byte[] signature) {
        int rFirstBit = (byteToUnsignedInt(signature[0])) > 0x7f ? 1 : 0; // value of first bit of r
        int sFirstBit = (byteToUnsignedInt(signature[32])) > 0x7f ? 1 : 0; // value of first bit of s
        byte[] result = new byte[64 + 4 + rFirstBit + sFirstBit + 2];
        result[0] = ((byte) 0x30);
        result[1] = ((byte) (64 + 4 + rFirstBit + sFirstBit)); // remaining data size
        result[2] = ((byte) 0x02);
        result[3] = ((byte) (32 + rFirstBit)); // length of r
        int pointer = 4;
        if (rFirstBit == 1) {
            result[pointer] = ((byte) 0x00);
            pointer++;
        }
        for (int i = 0; i < 32; i++) {
            result[pointer] = (signature[i]);
            pointer++;
        }
        result[pointer] = ((byte) 0x02);
        pointer++;
        result[pointer] = ((byte) (32 + sFirstBit)); // length of s
        pointer++;
        if (sFirstBit == 1) {
            result[pointer] = ((byte) 0x00);
            pointer++;
        }
        for (int i = 32; i < 64; i++) {
            result[pointer] = (signature[i]);
            pointer++;
        }
        return result;
    }

    public static int byteToUnsignedInt(byte b) {
        return b & 0xff;
    }


    /**
     * THIS METHOD IS FROM org.apache.pdfbox.examples.signature.SigUtils
     *
     * Get the access permissions granted for this document in the DocMDP transform parameters
     * dictionary. Details are described in the table "Entries in the DocMDP transform parameters
     * dictionary" in the PDF specification.
     *
     * @param doc document.
     * @return the permission value. 0 means no DocMDP transform parameters dictionary exists. Other
     * return values are 1, 2 or 3. 2 is also returned if the DocMDP transform parameters dictionary
     * is found but did not contain a /P entry, or if the value is outside the valid range.
     */
    public static int getMDPPermission(PDDocument doc)
    {
        COSDictionary permsDict = doc.getDocumentCatalog().getCOSObject()
                .getCOSDictionary(COSName.PERMS);
        if (permsDict != null) {
            COSDictionary signatureDict = permsDict.getCOSDictionary(COSName.DOCMDP);
            if (signatureDict != null) {
                COSArray refArray = signatureDict.getCOSArray(COSName.getPDFName("Reference"));
                if (refArray != null) {
                    for (int i = 0; i < refArray.size(); ++i) {
                        COSBase base = refArray.getObject(i);
                        if (base instanceof COSDictionary) {
                            COSDictionary sigRefDict = (COSDictionary) base;
                            if (COSName.DOCMDP.equals(sigRefDict.getDictionaryObject(COSName.getPDFName("TransformMethod")))) {
                                base = sigRefDict.getDictionaryObject(COSName.getPDFName("TransformParams"));
                                if (base instanceof COSDictionary) {
                                    COSDictionary transformDict = (COSDictionary) base;
                                    int accessPermissions = transformDict.getInt(COSName.P, 2);
                                    if (accessPermissions < 1 || accessPermissions > 3) {
                                        accessPermissions = 2;
                                    }
                                    return accessPermissions;
                                }
                            }
                        }
                    }
                }
            }
        }
        return 0;
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public static X509Certificate[] parseCertificates(Reader reader) throws Exception {
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter()
                .setProvider(new BouncyCastleProvider());

        List<X509Certificate> dst = new ArrayList<X509Certificate>();

        try (PEMParser parser = new PEMParser(reader)) {
            X509CertificateHolder holder;

            while ((holder = (X509CertificateHolder) parser.readObject()) != null) {
                X509Certificate certificate = converter.getCertificate(holder);
                if (certificate == null) {
                    continue;
                }

                dst.add(certificate);
            }
        }

        return dst.toArray(new X509Certificate[0]);
    }
}
