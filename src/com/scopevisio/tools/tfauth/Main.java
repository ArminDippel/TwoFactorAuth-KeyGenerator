/**
 *                     GNU GENERAL PUBLIC LICENSE
 *                      Version 3, 29 June 2007
 *
 * Copyright (C) 2007 Free Software Foundation, Inc. <http://fsf.org/>
 * Everyone is permitted to copy and distribute verbatim copies
 * of this license document, but changing it is not allowed.
 *
 */
package com.scopevisio.tools.tfauth;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Insets;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.crypto.Cipher;
import javax.swing.ImageIcon;
import javax.swing.JFrame;
import javax.swing.JTextArea;
import javax.xml.bind.DatatypeConverter;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.KeyPair;

public class Main {

	private static final String TITLE = "Schlüsselpaar-Generator.";
	private static JTextArea logger = new JTextArea(TITLE);

	public static void main(String args[]) throws Exception {
		JFrame window = new JFrame();
		try {
			// basic window setup
			window.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
			window.setSize(500, 450);
			window.setTitle(TITLE);
			window.setLocationRelativeTo(null);
			URL resource = Main.class.getResource("scope_64.png");
			ImageIcon img = new ImageIcon(resource);
			window.setIconImage(img.getImage());

			// configure logging frame
			logger.setEditable(false);
			logger.setMargin(new Insets(10, 10, 10, 10));
			logger.setLineWrap(true);
			logger.setBackground(Color.WHITE);
			logger.setForeground(Color.BLACK);
			window.add(logger, BorderLayout.CENTER);
			window.setVisible(true);

			String[] keyPairs = createAndTestKeyPair();
			log("\n\nSchlüsselpaar erfolgreich erzeugt.\n");
			log("\nIhr öffentlicher Schlüssel:\n  " + keyPairs[0] + "\n");
			log("\nIhr privater Schlüssel:\n  " + keyPairs[1] + "\n");

		} catch (Exception e) {
			log("\n\nSchlüsselpaar-Erzeugung mit Fehlern fehlgeschlagen (" + e.getLocalizedMessage() + ")");
		}
		log("\nSie können das Fenster jetzt schließen.");
	}

	private static void log(String message) {
		String currentText = logger.getText();
		currentText = currentText + message;
		logger.setText(currentText);
	}

	private static String[] createAndTestKeyPair() throws Exception {
		log("\nVorbereiten der Schlüsselerzeugung... ");
		DateFormat dateFormat = new SimpleDateFormat("yyyyMMdd_HHmmss");
		Date date = new Date();
		String dateTimeString = dateFormat.format(date);
		String filenameBase = "scopevisio_rsa_" + dateTimeString;
		Path publicKeyFile = Paths.get(filenameBase + ".pub");
		Path privateKeyFile = Paths.get(filenameBase);
		Files.deleteIfExists(publicKeyFile);
		Files.deleteIfExists(privateKeyFile);

		log("Ok.\nErzeugen des Schlüsselkommentars... ");
		String userName = System.getProperty("user.name");
		String hostName = InetAddress.getLocalHost().getHostName();
		String keyComment = userName + "@" + hostName;

		log("Ok.\nErzeugen des Schlüsselpaars... ");
		JSch jsch = new JSch();
		KeyPair keyPairGen = KeyPair.genKeyPair(jsch, KeyPair.RSA, 4096);

		log("Ok.\nSchreiben der Schlüsseldateien... ");
		keyPairGen.writePublicKey(publicKeyFile.toFile().getAbsolutePath(), keyComment);
		keyPairGen.writePrivateKey(privateKeyFile.toFile().getAbsolutePath());
		String[] keyPairPaths = new String[] { publicKeyFile.toFile().getAbsolutePath(),
				privateKeyFile.toFile().getAbsolutePath() };
		keyPairGen.dispose();

		log("Ok.\nLesen des Schlüsselpaars aus den erzeugten Dateien... ");
		String publicKeyBody = new String(Files.readAllBytes(publicKeyFile));
		String privateKeyBody = new String(Files.readAllBytes(privateKeyFile));
		PublicKey publicKey = readPublicKey(publicKeyBody);
		PrivateKey privateKey = readPrivateKey(privateKeyBody);

		log("Ok.\nErzeugen einer zufälligen Nachricht... ");
		SecureRandom random = new SecureRandom();
		String randomMessage = new BigInteger(130, random).toString(32);

		log("Ok.\nVerschlüsseln der Nachricht... ");
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] encrypted = cipher.doFinal(randomMessage.getBytes());

		log("Ok.\nEntschlüsseln der Nachricht... ");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		String decrypted = new String(cipher.doFinal(encrypted));

		log("Ok.\nPrüfen der Schlüsselfunktionalität... ");
		if (!randomMessage.equals(decrypted)) {
			log("Fehlgeschlagen!");
			throw new RuntimeException(
					"Failure during test of key pair. Original and decrypted message not identical.");
		} else {
			log("Erfolgreich.");
		}
		return keyPairPaths;
	}

	public static PrivateKey readPrivateKey(String body) throws GeneralSecurityException, IOException {
		byte[] bytes = DatatypeConverter.parseBase64Binary(body.replaceAll("[-]+[^-]+[-]+", ""));
		DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes));
		checkArgument(in.read() == 48, "no id_rsa SEQUENCE");
		checkArgument(in.read() == 130, "no Version marker");
		in.skipBytes(5);
		BigInteger n = readAsnInteger(in);
		readAsnInteger(in);
		BigInteger e = readAsnInteger(in);
		RSAPrivateKeySpec spec = new RSAPrivateKeySpec(n, e);
		return KeyFactory.getInstance("RSA").generatePrivate(spec);
	}

	public static PublicKey readPublicKey(String body) throws GeneralSecurityException, IOException {
		byte[] bytes = DatatypeConverter.parseBase64Binary(body.split(" ")[1]);
		DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes));
		byte[] sshRsa = new byte[in.readInt()];
		in.readFully(sshRsa);
		checkArgument(new String(sshRsa).equals("ssh-rsa"), "no RFC-4716 ssh-rsa");
		byte[] exp = new byte[in.readInt()];
		in.readFully(exp);
		byte[] mod = new byte[in.readInt()];
		in.readFully(mod);
		BigInteger e = new BigInteger(exp);
		BigInteger n = new BigInteger(mod);
		RSAPublicKeySpec spec = new RSAPublicKeySpec(n, e);
		return KeyFactory.getInstance("RSA").generatePublic(spec);
	}

	private static BigInteger readAsnInteger(DataInputStream in) throws IOException {
		checkArgument(in.read() == 2, "no INTEGER marker");
		int length = in.read();
		if (length >= 0x80) {
			byte[] extended = new byte[4];
			int bytesToRead = length & 0x7f;
			in.readFully(extended, 4 - bytesToRead, bytesToRead);
			length = new BigInteger(extended).intValue();
		}
		byte[] data = new byte[length];
		in.readFully(data);
		return new BigInteger(data);
	}

	private static void checkArgument(boolean expression, Object errorMessage) {
		if (!expression)
			throw new IllegalArgumentException(String.valueOf(errorMessage));
	}
}
