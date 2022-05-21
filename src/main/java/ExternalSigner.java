/*
Copyright 2021 Jiří Gavenda and Antonín Dufka

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
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.operator.ContentSigner;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class ExternalSigner implements ContentSigner {
    AlgorithmIdentifier algorithmIdentifier;
    ByteArrayOutputStream os;

    public ExternalSigner() {
        this.algorithmIdentifier = new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256);
        this.os = new ByteArrayOutputStream();
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }

    @Override
    public OutputStream getOutputStream() {
        return os;
    }

    @Override
    public byte[] getSignature() {
        byte[] data = os.toByteArray();
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        assert digest != null;
        data = digest.digest(data);
        for(byte b : data) {
            System.out.printf("%02x", b);
        }
        System.out.println();

        byte[] signature = new byte[0];
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        try {
            String line = reader.readLine();
            signature = Utils.hexStringToByteArray(line);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return Utils.formatSignature(signature);
    }
}
